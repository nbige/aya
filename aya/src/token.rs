//! BPF token support for unprivileged BPF operations.
//!
//! BPF tokens (Linux 6.9+) allow unprivileged userspace programs to perform BPF
//! operations by obtaining a token from a specially-configured BPF filesystem.
//!
//! # Overview
//!
//! Linux requires the BPF filesystem and token to be owned by a non-initial user
//! namespace, while only a process privileged in the initial user namespace can set
//! delegation options. The setup therefore crosses a Unix descriptor handoff:
//!
//! 1. The future token owner enters its user and mount namespaces and creates a
//!    [`BpfFilesystemContext`].
//! 2. It passes that context to an initial-user-namespace process, which calls
//!    [`BpfFilesystemContext::materialize`].
//! 3. The privileged process returns the resulting [`BpfFilesystemMount`].
//! 4. The owner opens the mount and creates a [`BpfToken`] with local `CAP_BPF`.
//! 5. The token is passed to [`EbpfLoader::token`](crate::EbpfLoader::token).

use std::{
    ffi::{CStr, CString},
    io,
    os::{
        fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd},
        unix::ffi::OsStrExt as _,
    },
    path::Path,
};

use aya_obj::{
    attach::BpfAttachType,
    cmd::BpfCommand,
    generated::{bpf_attach_type, bpf_cmd, bpf_map_type, bpf_prog_type},
    maps::BpfMapType,
    programs::BpfProgType,
};

use crate::sys::bpf_token_create;

#[cfg(test)]
#[path = "token_tests.rs"]
mod tests;

/// A BPF token obtained from a BPF filesystem.
///
/// BPF tokens delegate a subset of BPF capabilities to unprivileged processes.
/// The token is created from a BPF filesystem (bpffs) that has been mounted with
/// appropriate `delegate_*` mount options.
///
/// # Minimum kernel version
///
/// BPF tokens require Linux 6.9 or later.
///
/// # Example
///
/// ```no_run
/// use aya::{Ebpf, EbpfLoader};
/// use aya::token::BpfToken;
///
/// let token = BpfToken::create("/sys/fs/bpf")?;
/// let bpf = EbpfLoader::new()
///     .token(&token)?
///     .load_file("program.o")?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct BpfToken {
    fd: crate::MockableFd,
}

impl BpfToken {
    /// Creates a BPF token from the given BPF filesystem path.
    ///
    /// The path must point to a delegated bpffs owned by the caller's non-initial
    /// user namespace, and the caller must have `CAP_BPF` in that namespace.
    /// Linux deliberately returns `EOPNOTSUPP` for token creation in `init_user_ns`.
    pub fn create<P: AsRef<Path>>(bpffs_path: P) -> Result<Self, io::Error> {
        let path = bpffs_path.as_ref();
        let path_c = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        // Open the bpffs directory.
        // SAFETY: `path_c` is NUL-terminated and the flags require no variadic mode argument.
        let dir_fd = unsafe {
            libc::open(
                path_c.as_ptr(),
                libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_RDONLY,
            )
        };
        let dir_fd = owned_fd_from_libc(dir_fd)?;

        Self::create_from_bpffs(&BpfFilesystem {
            fd: crate::MockableFd::from_fd(dir_fd),
        })
    }

    /// Creates a BPF token from an opened delegated BPF filesystem.
    ///
    /// The filesystem must be owned by the caller's current non-initial user
    /// namespace, and the caller must have `CAP_BPF` in that namespace.
    pub fn create_from_bpffs(bpffs: &BpfFilesystem) -> Result<Self, io::Error> {
        let token_fd = bpf_token_create(bpffs.as_fd())?;
        Ok(Self { fd: token_fd })
    }

    /// Adopts an inherited BPF token file descriptor.
    ///
    /// The descriptor is consumed without duplication and marked close-on-exec.
    /// Its BPF token type is checked by the kernel on the first token-enabled
    /// operation because Linux does not provide a token-info command.
    ///
    /// # Errors
    ///
    /// Returns an error if the descriptor is not live or close-on-exec cannot be set.
    pub fn from_owned_fd(fd: OwnedFd) -> Result<Self, io::Error> {
        ensure_cloexec(fd.as_raw_fd())?;
        Ok(Self {
            fd: crate::MockableFd::from_fd(fd),
        })
    }

    /// Returns a borrowed file descriptor for this token.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

fn ensure_cloexec(fd: RawFd) -> Result<(), io::Error> {
    // SAFETY: F_GETFD reads flags for `fd` without dereferencing userspace memory.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::FD_CLOEXEC != 0 {
        return Ok(());
    }

    // SAFETY: F_SETFD updates descriptor flags and `flags` came from F_GETFD above.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A new BPF filesystem context owned by the user namespace that created it.
///
/// Create this context in the future token owner's user namespace, then pass its
/// descriptor to a process privileged in `init_user_ns` for materialization.
pub struct BpfFilesystemContext {
    fd: OwnedFd,
}

impl BpfFilesystemContext {
    /// Creates a BPF filesystem context owned by the current user namespace.
    pub fn create() -> Result<Self, io::Error> {
        // SAFETY: the filesystem name is NUL-terminated and fsopen takes no variadic arguments.
        let fd = unsafe { libc::syscall(libc::SYS_fsopen, c"bpf".as_ptr(), FSOPEN_CLOEXEC) };
        Ok(Self {
            fd: owned_fd_from_syscall(fd)?,
        })
    }

    /// Adopts a BPF filesystem context received through a descriptor handoff.
    pub fn from_owned_fd(fd: OwnedFd) -> Result<Self, io::Error> {
        ensure_cloexec(fd.as_raw_fd())?;
        Ok(Self { fd })
    }

    /// Returns the BPF filesystem context descriptor.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Applies delegation and materializes a detached BPF filesystem mount.
    ///
    /// This stage must run in a process with `CAP_SYS_ADMIN` in `init_user_ns`.
    /// All four delegation masks are written exactly, including zero masks.
    pub fn materialize(
        self,
        permissions: FilesystemPermissions,
    ) -> Result<BpfFilesystemMount, io::Error> {
        self.set_mask(c"delegate_cmds", permissions.delegate_cmds)?;
        self.set_mask(c"delegate_maps", permissions.delegate_maps)?;
        self.set_mask(c"delegate_progs", permissions.delegate_progs)?;
        self.set_mask(c"delegate_attachs", permissions.delegate_attaches)?;
        if let Some(uid) = permissions.uid {
            self.set_string(c"uid", &uid.to_string())?;
        }
        if let Some(gid) = permissions.gid {
            self.set_string(c"gid", &gid.to_string())?;
        }

        // SAFETY: the context descriptor is live and CMD_CREATE takes null key/value pointers.
        let result = unsafe {
            libc::syscall(
                libc::SYS_fsconfig,
                self.fd.as_raw_fd(),
                FSCONFIG_CMD_CREATE,
                std::ptr::null::<libc::c_char>(),
                std::ptr::null::<libc::c_char>(),
                0,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: the configured context descriptor is live and fsmount takes scalar flags.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_fsmount,
                self.fd.as_raw_fd(),
                FSMOUNT_CLOEXEC,
                0u32,
            )
        };
        Ok(BpfFilesystemMount {
            fd: owned_fd_from_syscall(fd)?,
        })
    }

    fn set_mask(&self, key: &CStr, mask: u64) -> Result<(), io::Error> {
        self.set_string(key, &format!("0x{mask:x}"))
    }

    fn set_string(&self, key: &CStr, value: &str) -> Result<(), io::Error> {
        let value = CString::new(value)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        // SAFETY: the descriptor is live and both C strings are NUL-terminated for fsconfig.
        let result = unsafe {
            libc::syscall(
                libc::SYS_fsconfig,
                self.fd.as_raw_fd(),
                FSCONFIG_SET_STRING,
                key.as_ptr(),
                value.as_ptr(),
                0,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// A detached delegated BPF filesystem mount suitable for descriptor handoff.
pub struct BpfFilesystemMount {
    fd: OwnedFd,
}

impl BpfFilesystemMount {
    /// Adopts a detached BPF filesystem mount received through a descriptor handoff.
    pub fn from_owned_fd(fd: OwnedFd) -> Result<Self, io::Error> {
        ensure_cloexec(fd.as_raw_fd())?;
        Ok(Self { fd })
    }

    /// Returns the detached mount descriptor.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Opens the root of this BPF filesystem for token creation.
    pub fn open(&self) -> Result<BpfFilesystem, io::Error> {
        // SAFETY: the mount descriptor is live, the path is NUL-terminated, and no mode is needed.
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                c".".as_ptr(),
                libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_RDONLY,
            )
        };
        let fd = owned_fd_from_libc(fd)?;
        Ok(BpfFilesystem {
            fd: crate::MockableFd::from_fd(fd),
        })
    }
}

/// An opened BPF filesystem root usable for BPF token creation.
pub struct BpfFilesystem {
    fd: crate::MockableFd,
}

impl BpfFilesystem {
    /// Adopts an opened BPF filesystem root descriptor.
    pub fn from_owned_fd(fd: OwnedFd) -> Result<Self, io::Error> {
        ensure_cloexec(fd.as_raw_fd())?;
        Ok(Self {
            fd: crate::MockableFd::from_fd(fd),
        })
    }

    /// Returns the opened BPF filesystem descriptor.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

fn owned_fd_from_syscall(fd: libc::c_long) -> Result<OwnedFd, io::Error> {
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful fd-producing syscall returned a descriptor owned by this scope.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

fn owned_fd_from_libc(fd: libc::c_int) -> Result<OwnedFd, io::Error> {
    owned_fd_from_syscall(libc::c_long::from(fd))
}

/// Permissions for a BPF filesystem that control what operations are delegated
/// to unprivileged processes via BPF tokens.
///
/// Use [`FilesystemPermissionsBuilder`] to construct an instance.
#[derive(Debug, Default)]
pub struct FilesystemPermissions {
    delegate_cmds: u64,
    delegate_maps: u64,
    delegate_progs: u64,
    delegate_attaches: u64,
    uid: Option<u32>,
    gid: Option<u32>,
}

/// Builder for [`FilesystemPermissions`].
///
/// # Example
///
/// ```no_run
/// use aya::token::FilesystemPermissionsBuilder;
/// use aya_obj::cmd::BpfCommand;
/// use aya_obj::programs::BpfProgType;
/// use aya_obj::maps::BpfMapType;
///
/// let perms = FilesystemPermissionsBuilder::default()
///     .allow_cmd(BpfCommand::MapCreate)
///     .allow_cmd(BpfCommand::ProgLoad)
///     .allow_prog_type(BpfProgType::SocketFilter)
///     .allow_map_type(BpfMapType::Array)
///     .uid(1000)
///     .build();
///
/// # let _ = perms;
/// ```
#[derive(Debug, Default)]
pub struct FilesystemPermissionsBuilder {
    perms: FilesystemPermissions,
}

/// Converts a kernel enum discriminant into its delegation bitmask bit.
///
/// The kernel represents `delegate_{cmds,maps,progs,attaches}` as a single
/// `u64` bitmask indexed by the enum discriminant
/// (`include/uapi/linux/bpf.h`). A discriminant of 64 or higher cannot be
/// represented and would silently wrap under a plain `1 << n` shift,
/// corrupting the mask and delegating the wrong operation. Panic instead,
/// consistent with this builder's infallible, chainable `-> Self` API style.
fn checked_permission_bit(kind: &'static str, discriminant: u64) -> u64 {
    assert!(
        discriminant < 64,
        "BPF token delegation bit for {kind} (discriminant {discriminant}) does not fit in the \
         64-bit delegation mask; the kernel enum has grown beyond what this bitmask can represent"
    );
    1 << discriminant
}

impl FilesystemPermissionsBuilder {
    /// Allows the given BPF command to be used by token holders.
    #[must_use]
    pub fn allow_cmd(mut self, cmd: BpfCommand) -> Self {
        let cmd: bpf_cmd = cmd.into();
        self.perms.delegate_cmds |= checked_permission_bit("BpfCommand", cmd as u64);
        self
    }

    /// Allows the given map type to be created by token holders.
    #[must_use]
    pub fn allow_map_type(mut self, map_type: BpfMapType) -> Self {
        let map_type: bpf_map_type = map_type.into();
        self.perms.delegate_maps |= checked_permission_bit("BpfMapType", map_type as u64);
        self
    }

    /// Allows the given program type to be loaded by token holders.
    #[must_use]
    pub fn allow_prog_type(mut self, prog_type: BpfProgType) -> Self {
        let prog_type: bpf_prog_type = prog_type.into();
        self.perms.delegate_progs |= checked_permission_bit("BpfProgType", prog_type as u64);
        self
    }

    /// Allows the given attach type to be used by token holders.
    #[must_use]
    pub fn allow_attach_type(mut self, attach_type: BpfAttachType) -> Self {
        let attach_type: bpf_attach_type = attach_type.into();
        self.perms.delegate_attaches |= checked_permission_bit("BpfAttachType", attach_type as u64);
        self
    }

    /// Sets the owner UID of the mounted filesystem.
    #[must_use]
    pub const fn uid(mut self, uid: u32) -> Self {
        self.perms.uid = Some(uid);
        self
    }

    /// Sets the owner GID of the mounted filesystem.
    #[must_use]
    pub const fn gid(mut self, gid: u32) -> Self {
        self.perms.gid = Some(gid);
        self
    }

    /// Builds the [`FilesystemPermissions`].
    #[must_use]
    pub const fn build(self) -> FilesystemPermissions {
        self.perms
    }
}

const FSOPEN_CLOEXEC: u32 = 1;
const FSCONFIG_SET_STRING: u32 = 1;
const FSCONFIG_CMD_CREATE: u32 = 6;
const FSMOUNT_CLOEXEC: u32 = 1;
