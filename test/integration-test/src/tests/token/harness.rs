use std::{
    fs::OpenOptions,
    io::Write as _,
    os::{
        fd::{AsFd as _, AsRawFd as _, OwnedFd},
        unix::fs::OpenOptionsExt as _,
    },
};

use anyhow::{Context as _, Result, bail, ensure};
use aya::{
    token::{
        BpfFilesystem, BpfFilesystemContext, BpfFilesystemMount, BpfToken, FilesystemPermissions,
    },
    util::KernelVersion,
};
use nix::{
    mount::{MsFlags, mount},
    sched::{CloneFlags, unshare},
    sys::socket::{AddressFamily, SockFlag, SockType, socketpair},
};

mod capabilities;
pub(super) mod diagnostic;
pub(super) mod fd;
pub(super) use self::capabilities::{
    CapabilityProfile, MissingCapabilities, parse_effective_capabilities,
};
use self::{
    capabilities::require_effective_capabilities,
    diagnostic::{catch_child, exit_child, read_child_diagnostic},
    fd::{receive_fd, send_fd},
};

pub(super) fn require_kernel_6_9() -> Result<()> {
    let version = KernelVersion::current().context("query kernel version")?;
    ensure!(
        version >= KernelVersion::new(6, 9, 0),
        "BPF token qualification requires Linux >= 6.9; running {version:?}"
    );
    Ok(())
}

fn write_mapping(path: &str, value: &str) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(value.as_bytes())
}

fn enter_user_and_mount_namespaces(required_capabilities: CapabilityProfile) -> Result<()> {
    // SAFETY: getuid/getgid only query process credentials.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    unshare(CloneFlags::CLONE_NEWUSER).context("create user namespace")?;
    match write_mapping("/proc/self/setgroups", "deny") {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
        Err(error) => return Err(error.into()),
    }
    write_mapping("/proc/self/uid_map", &format!("0 {uid} 1")).context("write uid map")?;
    write_mapping("/proc/self/gid_map", &format!("0 {gid} 1")).context("write gid map")?;

    // SAFETY: setting IDs to the mapped namespace root affects only this child process.
    if unsafe { libc::setgid(0) } != 0 {
        return Err(std::io::Error::last_os_error()).context("set namespace gid");
    }
    // SAFETY: setting IDs to the mapped namespace root affects only this child process.
    if unsafe { libc::setuid(0) } != 0 {
        return Err(std::io::Error::last_os_error()).context("set namespace uid");
    }
    require_effective_capabilities(required_capabilities)?;

    unshare(CloneFlags::CLONE_NEWNS).context("create mount namespace")?;
    mount::<str, str, str, str>(None, "/", None, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None)
        .context("make child mount namespace private")
}

pub(super) struct ChildGuard<C>
where
    C: FnMut(libc::pid_t),
{
    pid: Option<libc::pid_t>,
    cleanup: C,
}

impl<C> ChildGuard<C>
where
    C: FnMut(libc::pid_t),
{
    pub(super) fn new(pid: libc::pid_t, cleanup: C) -> Self {
        Self {
            pid: Some(pid),
            cleanup,
        }
    }

    fn mark_reaped(&mut self) {
        self.pid = None;
    }
}

impl<C> Drop for ChildGuard<C>
where
    C: FnMut(libc::pid_t),
{
    fn drop(&mut self) {
        if let Some(pid) = self.pid.take() {
            (self.cleanup)(pid);
        }
    }
}

fn wait_for_child<C>(child: &mut ChildGuard<C>) -> Result<()>
where
    C: FnMut(libc::pid_t),
{
    let pid = child.pid.context("token child was already reaped")?;
    let mut status = 0;
    loop {
        // SAFETY: pid identifies our child and status points to writable process memory.
        let result = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        if result == pid {
            return finish_reaped_child(child, status);
        }
        if result < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if result < 0 {
            return Err(std::io::Error::last_os_error()).context("wait for token child");
        }
    }
}

pub(super) fn finish_reaped_child<C>(child: &mut ChildGuard<C>, status: libc::c_int) -> Result<()>
where
    C: FnMut(libc::pid_t),
{
    child.mark_reaped();
    ensure!(libc::WIFEXITED(status), "token child did not exit normally");
    match libc::WEXITSTATUS(status) {
        0 => Ok(()),
        3 => bail!("token child missing required effective capabilities after uid/gid mapping"),
        status => bail!("token child failed with status {status}"),
    }
}

fn kill_child(pid: libc::pid_t) {
    // SAFETY: best-effort cleanup targets only the child PID returned by fork.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, std::ptr::null_mut(), 0);
    }
}

fn run_child<F>(
    socket: &OwnedFd,
    required_capabilities: CapabilityProfile,
    child_test: F,
) -> Result<()>
where
    F: FnOnce(&BpfFilesystem, &BpfToken) -> Result<()>,
{
    enter_user_and_mount_namespaces(required_capabilities)?;
    let context = BpfFilesystemContext::create().context("create child-owned bpffs context")?;
    send_fd(socket, context.as_fd())?;
    drop(context);

    let mount = BpfFilesystemMount::from_owned_fd(receive_fd(socket)?)
        .context("adopt delegated bpffs mount")?;
    let bpffs = mount.open().context("open delegated bpffs mount")?;
    let token = BpfToken::create_from_bpffs(&bpffs)
        .context("create token in owning child user namespace")?;
    send_fd(socket, token.as_fd())?;
    child_test(&bpffs, &token)
}

pub(super) fn run_in_token_userns<F>(
    permissions: FilesystemPermissions,
    required_capabilities: CapabilityProfile,
    child_test: F,
) where
    F: FnOnce(&BpfFilesystem, &BpfToken) -> Result<()>,
{
    require_kernel_6_9().expect("qualified BPF token kernel");
    let (parent_socket, child_socket) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .expect("create Unix socketpair");

    // SAFETY: the child performs isolated test setup and exits with _exit; the qualified
    // campaign runs this test binary with one test thread, matching the kernel selftest model.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
    if pid == 0 {
        drop(parent_socket);
        let outcome = catch_child(Some(child_socket.as_fd()), || {
            std::panic::set_hook(Box::new(|_| {}));
            run_child(&child_socket, required_capabilities, child_test)
        });
        exit_child(outcome);
    }

    drop(child_socket);
    let mut child = ChildGuard::new(pid, kill_child);
    let context = BpfFilesystemContext::from_owned_fd(
        receive_fd(&parent_socket).expect("receive child-owned bpffs context"),
    )
    .expect("adopt child-owned bpffs context");
    let mount = context
        .materialize(permissions)
        .expect("delegate and materialize child-owned bpffs");
    send_fd(&parent_socket, mount.as_fd()).expect("send delegated bpffs mount to child");
    drop(mount);

    let token = BpfToken::from_owned_fd(
        receive_fd(&parent_socket).expect("receive child-created BPF token"),
    )
    .expect("adopt child-created BPF token");
    assert!(token.as_fd().as_raw_fd() >= 0);
    match wait_for_child(&mut child) {
        Ok(()) => {}
        Err(error) if child.pid.is_none() => {
            let diagnostic = read_child_diagnostic(&parent_socket).unwrap_or_else(|read_error| {
                format!("<failed to read child diagnostic: {read_error}>")
            });
            match diagnostic.as_str() {
                "" => panic!("child-userns token path failed: {error}"),
                _ => panic!(
                    "child-userns token path failed: {error}; child diagnostic: {diagnostic}"
                ),
            }
        }
        Err(error) => panic!("child-userns token path failed before reap: {error}"),
    }
}
