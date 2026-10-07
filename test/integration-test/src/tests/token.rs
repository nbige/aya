use std::{
    ffi::CStr,
    io::{self, IoSlice, IoSliceMut},
    os::{
        fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd},
        unix::process::CommandExt as _,
    },
    process::Command,
};

use anyhow::{Context as _, Result, ensure};
use aya::{
    EbpfLoader,
    maps::{MapData, MapError, MapType},
    programs::{ProgramType, Xdp},
    token::{
        BpfFilesystemContext, BpfFilesystemMount, BpfToken, FilesystemPermissions,
        FilesystemPermissionsBuilder,
    },
    util::KernelVersion,
};
use aya_obj::{attach::BpfAttachType, cmd::BpfCommand};
use nix::{
    cmsg_space,
    sys::socket::{
        AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, recv,
        recvmsg, sendmsg, socketpair,
    },
};

#[test_log::test]
fn token_create_nonexistent_path() {
    assert!(BpfToken::create("/nonexistent/bpffs/path").is_err());
}

#[test_log::test]
fn token_create_non_bpffs() {
    assert!(BpfToken::create("/tmp").is_err());
}

fn token_supported(test: &str) -> bool {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(6, 9, 0) {
        eprintln!("skipping {test} test on kernel {kernel_version:?}");
        return false;
    }
    true
}

#[test_log::test]
fn token_create_in_initial_userns_returns_eopnotsupp() -> Result<()> {
    if !token_supported("token_create_in_initial_userns_returns_eopnotsupp") {
        return Ok(());
    }
    let mount = BpfFilesystemContext::create()?.materialize(
        FilesystemPermissionsBuilder::default()
            .allow_cmd(BpfCommand::MapCreate)
            .build(),
    )?;
    let bpffs = mount.open()?;
    let Err(error) = BpfToken::create_from_bpffs(&bpffs) else {
        panic!("init_user_ns token creation unexpectedly succeeded");
    };
    assert_eq!(error.raw_os_error(), Some(libc::EOPNOTSUPP));
    Ok(())
}

#[test_log::test]
fn token_map_create_in_owning_userns() -> Result<()> {
    run_in_token_userns(
        "token_map_create_in_owning_userns",
        FilesystemPermissionsBuilder::default()
            .allow_cmd(BpfCommand::MapCreate)
            .allow_map_type(MapType::LruHash)
            .build(),
        |token| {
            let map = || aya_obj::Map::new_from_params(MapType::LruHash as u32, 4, 4, 1, 0);
            let error = MapData::create(map(), "aya_token_map", None).unwrap_err();
            let MapError::CreateError { io_error, .. } = error else {
                panic!("expected map creation error, got {error:?}");
            };
            assert_eq!(io_error.raw_os_error(), Some(libc::EPERM));
            let _map = MapData::create_with_token(map(), "aya_token_map", None, token.as_fd())?;
            Ok(())
        },
    )
}

#[test_log::test]
fn token_loader_btf_and_xdp_in_owning_userns() -> Result<()> {
    run_in_token_userns(
        "token_loader_btf_and_xdp_in_owning_userns",
        FilesystemPermissionsBuilder::default()
            .allow_cmd(BpfCommand::BtfLoad)
            .allow_cmd(BpfCommand::ProgLoad)
            .allow_prog_type(ProgramType::Xdp)
            .allow_attach_type(BpfAttachType::Xdp)
            .build(),
        |token| {
            let mut bpf = EbpfLoader::new().token(token)?.load(crate::PASS)?;
            let program: &mut Xdp = bpf
                .program_mut("pass")
                .context("missing pass program")?
                .try_into()?;
            program.load()?;
            assert!(
                program.info()?.btf_id().is_some(),
                "object BTF did not load"
            );
            Ok(())
        },
    )
}

fn send_fd(socket: &OwnedFd, fd: BorrowedFd<'_>) -> Result<()> {
    let fds = [fd.as_raw_fd()];
    let sent = sendmsg::<()>(
        socket.as_raw_fd(),
        &[IoSlice::new(&[0])],
        &[ControlMessage::ScmRights(&fds)],
        MsgFlags::empty(),
        None,
    )?;
    ensure!(sent == 1, "short descriptor send");
    Ok(())
}

fn receive_fd(socket: &OwnedFd) -> Result<OwnedFd> {
    let mut payload = [0];
    let mut iov = [IoSliceMut::new(&mut payload)];
    let mut control = cmsg_space!([RawFd; 1]);
    let message = recvmsg::<()>(
        socket.as_raw_fd(),
        &mut iov,
        Some(&mut control),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )?;
    ensure!(message.bytes == 1, "descriptor peer closed early");
    for control in message.cmsgs()? {
        if let ControlMessageOwned::ScmRights(fds) = control {
            let mut fds = fds.into_iter().map(|fd| {
                // SAFETY: SCM_RIGHTS installs new descriptors owned by this process.
                unsafe { OwnedFd::from_raw_fd(fd) }
            });
            let fd = fds.next().context("missing descriptor")?;
            ensure!(fds.next().is_none(), "expected one descriptor");
            return Ok(fd);
        }
    }
    anyhow::bail!("missing SCM_RIGHTS message")
}

fn report_setup_stage(socket: RawFd, stage: &'static [u8]) {
    // SAFETY: the socket is live and the static stage bytes remain readable during send.
    unsafe {
        libc::send(
            socket,
            stage.as_ptr().cast(),
            stage.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        );
    }
}

fn write_namespace_file(
    path: &CStr,
    data: &[u8],
    setup_socket: RawFd,
    stages: [&'static [u8]; 2],
) -> io::Result<()> {
    // SAFETY: `path` is NUL-terminated and the flags need no mode argument.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        let error = io::Error::last_os_error();
        report_setup_stage(setup_socket, stages[0]);
        return Err(error);
    }
    // SAFETY: `fd` was opened above and is owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: `data` is readable for `data.len()` bytes.
    let written = unsafe { libc::write(fd.as_raw_fd(), data.as_ptr().cast(), data.len()) };
    match usize::try_from(written) {
        Ok(written) if written == data.len() => Ok(()),
        Ok(_) => Err(io::Error::from_raw_os_error(libc::EIO)),
        Err(_) => Err(io::Error::last_os_error()),
    }
    .inspect_err(|_| report_setup_stage(setup_socket, stages[1]))
}

fn run_in_token_userns(
    test: &str,
    permissions: FilesystemPermissions,
    child_test: impl FnOnce(&BpfToken) -> Result<()>,
) -> Result<()> {
    if !token_supported(test) {
        return Ok(());
    }
    const SOCKET_ENV: &str = "AYA_TOKEN_TEST_SOCKET";
    if let Some(fd) = std::env::var_os(SOCKET_ENV) {
        let fd: RawFd = fd.to_str().context("socket FD is not UTF-8")?.parse()?;
        // SAFETY: only the parent sets this variable, for the socket inherited across exec.
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        let context = BpfFilesystemContext::create()?;
        send_fd(&socket, context.as_fd())?;
        let mount = BpfFilesystemMount::from_owned_fd(receive_fd(&socket)?)?;
        let bpffs = mount.open()?;
        return child_test(&BpfToken::create_from_bpffs(&bpffs)?);
    }

    let (parent_socket, child_socket) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    )?;
    let child_fd = child_socket.as_raw_fd();
    let (setup_parent, setup_child) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None,
        SockFlag::SOCK_CLOEXEC,
    )?;
    let setup_fd = setup_child.as_raw_fd();
    // SAFETY: getuid/getgid take no arguments and have no memory-safety preconditions.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let uid_map = format!("0 {uid} 1");
    let gid_map = format!("0 {gid} 1");
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            &format!("tests::token::{test}"),
            "--nocapture",
            "--test-threads=1",
        ])
        .env(SOCKET_ENV, child_fd.to_string());
    // SAFETY: the post-fork hook makes only async-signal-safe calls with buffers allocated before
    // the fork, and it neither locks, allocates, formats, nor unwinds.
    unsafe {
        command.pre_exec(move || {
            if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0 {
                let error = io::Error::last_os_error();
                report_setup_stage(setup_fd, b"unshare(CLONE_NEWUSER | CLONE_NEWNS)");
                return Err(error);
            }
            write_namespace_file(
                c"/proc/self/setgroups",
                b"deny",
                setup_fd,
                [b"open /proc/self/setgroups", b"write /proc/self/setgroups"],
            )?;
            write_namespace_file(
                c"/proc/self/uid_map",
                uid_map.as_bytes(),
                setup_fd,
                [b"open /proc/self/uid_map", b"write /proc/self/uid_map"],
            )?;
            write_namespace_file(
                c"/proc/self/gid_map",
                gid_map.as_bytes(),
                setup_fd,
                [b"open /proc/self/gid_map", b"write /proc/self/gid_map"],
            )?;
            if libc::fcntl(child_fd, libc::F_SETFD, 0) != 0 {
                let error = io::Error::last_os_error();
                report_setup_stage(setup_fd, b"fcntl child socket F_SETFD");
                return Err(error);
            }
            report_setup_stage(setup_fd, b"exec after successful pre_exec");
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|error| {
        let mut stage = [0; 128];
        let stage = match recv(setup_parent.as_raw_fd(), &mut stage, MsgFlags::MSG_DONTWAIT) {
            Ok(len) => std::str::from_utf8(&stage[..len]).unwrap_or("invalid setup stage report"),
            Err(_) => "before pre_exec or setup stage report unavailable",
        };
        anyhow::Error::new(error).context(format!("spawn token userns test: {stage}"))
    })?;
    drop(setup_parent);
    drop(setup_child);
    drop(child_socket);
    let result = (|| {
        let context = BpfFilesystemContext::from_owned_fd(receive_fd(&parent_socket)?)?;
        let mount = context.materialize(permissions)?;
        send_fd(&parent_socket, mount.as_fd())
    })();
    drop(parent_socket);
    if result.is_err() {
        drop(child.kill());
    }
    let status = child.wait()?;
    result?;
    ensure!(status.success(), "token userns test failed: {status}");
    Ok(())
}
