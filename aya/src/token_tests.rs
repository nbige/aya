use std::{
    fs::File,
    io,
    os::fd::{AsRawFd as _, OwnedFd},
};

use assert_matches::assert_matches;
use aya_obj::generated::bpf_map_type;

use super::{
    BpfFilesystem, BpfFilesystemContext, BpfFilesystemMount, BpfToken,
    FilesystemPermissionsBuilder, checked_permission_bit, ensure_cloexec,
};
use crate::{
    features::Features,
    maps::{MapData, MapError},
    sys::{Syscall, override_syscall},
};

#[test]
fn checked_permission_bit_computes_shift_for_in_range_discriminants() {
    assert_eq!(checked_permission_bit("test", 0), 1);
    assert_eq!(checked_permission_bit("test", 5), 1 << 5);
    assert_eq!(checked_permission_bit("test", 63), 1 << 63);
}

#[test]
#[should_panic(expected = "does not fit in the 64-bit delegation mask")]
fn checked_permission_bit_panics_on_out_of_range_discriminant() {
    checked_permission_bit("test", 64);
}

// Every currently-defined kernel discriminant for the four delegation
// bitmask domains must fit in a `u64` bit position. The kernel's own
// `__MAX_BPF_*` sentinels are the authoritative upper bound: if this ever
// fails, one of the enums has grown past 64 variants and `allow_*` methods
// using discriminants near the top of the range will start panicking for
// legitimate callers, which must be handled (e.g. by widening the mask)
// before it ships.
#[test]
fn kernel_enum_discriminants_fit_in_delegation_bitmask() {
    use aya_obj::generated::{bpf_attach_type, bpf_cmd, bpf_map_type, bpf_prog_type};

    assert!(
        (bpf_cmd::__MAX_BPF_CMD as u64) <= 64,
        "bpf_cmd has grown past 64 variants"
    );
    assert!(
        (bpf_map_type::__MAX_BPF_MAP_TYPE as u64) <= 64,
        "bpf_map_type has grown past 64 variants"
    );
    assert!(
        (bpf_prog_type::__MAX_BPF_PROG_TYPE as u64) <= 64,
        "bpf_prog_type has grown past 64 variants"
    );
    assert!(
        (bpf_attach_type::__MAX_BPF_ATTACH_TYPE as u64) <= 64,
        "bpf_attach_type has grown past 64 variants"
    );
}

#[test]
fn allow_methods_build_expected_bits_for_known_variants() {
    use aya_obj::{
        attach::BpfAttachType, cmd::BpfCommand, maps::BpfMapType, programs::BpfProgType,
    };

    let perms = FilesystemPermissionsBuilder::default()
        .allow_cmd(BpfCommand::MapCreate)
        .allow_map_type(BpfMapType::Array)
        .allow_prog_type(BpfProgType::SocketFilter)
        .allow_attach_type(BpfAttachType::CgroupInetIngress)
        .build();

    assert_ne!(perms.delegate_cmds, 0);
    assert_ne!(perms.delegate_maps, 0);
    assert_ne!(perms.delegate_progs, 0);
    assert_ne!(perms.delegate_attaches, 0);
}

fn non_token_fd() -> OwnedFd {
    File::open("/dev/null").unwrap().into()
}

#[test]
#[cfg_attr(miri, ignore = "`open` and `fcntl` require OS file descriptors")]
fn from_owned_fd_preserves_ownership_and_sets_cloexec() {
    let fd = non_token_fd();
    let raw_fd = fd.as_raw_fd();
    // SAFETY: `raw_fd` is live and owned by `fd`; F_SETFD only changes descriptor flags.
    let result = unsafe { libc::fcntl(raw_fd, libc::F_SETFD, 0) };
    assert_eq!(result, 0);

    let token = BpfToken::from_owned_fd(fd).unwrap();

    assert_eq!(token.as_fd().as_raw_fd(), raw_fd);
    // SAFETY: the token owns `raw_fd`, so it remains live for this query.
    let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
    assert_ne!(flags & libc::FD_CLOEXEC, 0);
}

#[test]
#[cfg_attr(miri, ignore = "`open` and `fcntl` require OS file descriptors")]
fn filesystem_fd_stages_preserve_ownership_and_set_cloexec() {
    let context = BpfFilesystemContext::from_owned_fd(non_token_fd()).unwrap();
    assert!(context.as_fd().as_raw_fd() >= 0);

    let mount = BpfFilesystemMount::from_owned_fd(non_token_fd()).unwrap();
    assert!(mount.as_fd().as_raw_fd() >= 0);

    let filesystem = BpfFilesystem::from_owned_fd(non_token_fd()).unwrap();
    assert!(filesystem.as_fd().as_raw_fd() >= 0);
}

#[test]
#[cfg_attr(miri, ignore = "`fcntl` requires an OS file descriptor")]
fn ensure_cloexec_rejects_non_live_fd() {
    let error = ensure_cloexec(-1).unwrap_err();

    assert_eq!(error.raw_os_error(), Some(libc::EBADF));
}

#[test]
#[cfg_attr(miri, ignore = "`open` and `fcntl` require OS file descriptors")]
fn wrong_live_fd_fails_typed_at_first_token_operation() {
    let token = BpfToken::from_owned_fd(non_token_fd()).unwrap();
    override_syscall(|call| match call {
        Syscall::Ebpf {
            cmd: aya_obj::generated::bpf_cmd::BPF_MAP_CREATE,
            ..
        } => Err((-1, io::Error::from_raw_os_error(libc::EINVAL))),
        call => panic!("unexpected syscall: {call:?}"),
    });
    let map = aya_obj::Map::new_from_params(bpf_map_type::BPF_MAP_TYPE_ARRAY as u32, 4, 4, 1, 0);

    let result = MapData::create(
        map,
        "wrong_token",
        None,
        Some(token.as_fd()),
        Features::default(),
    );

    assert_matches!(
        result,
        Err(MapError::CreateError { io_error, .. })
            if io_error.raw_os_error() == Some(libc::EINVAL)
    );
}
