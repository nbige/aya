use std::{
    cell::Cell,
    fmt,
    io::{IoSlice, Result},
    os::{
        fd::{AsFd as _, AsRawFd as _, OwnedFd, RawFd},
        unix::net::UnixStream,
    },
    path::{Path, PathBuf},
};

use nix::{
    cmsg_space,
    sys::socket::{
        AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType, sendmsg, socketpair,
    },
};

use super::harness::{
    CapabilityProfile, ChildGuard, MissingCapabilities,
    diagnostic::{CHILD_DIAGNOSTIC_MAX, ChildOutcome, catch_child, read_child_diagnostic},
    fd::receive_fd_with_control,
    finish_reaped_child, parse_effective_capabilities,
};

#[derive(Debug)]
struct PanickingDiagnostic;

impl fmt::Display for PanickingDiagnostic {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        panic!("diagnostic formatting panic")
    }
}

impl std::error::Error for PanickingDiagnostic {}

fn descriptor_target(fd: std::os::fd::BorrowedFd<'_>) -> PathBuf {
    std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap()
}

fn target_descriptor_count(target: &Path) -> usize {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| std::fs::read_link(entry.path()).ok())
        .filter(|candidate| candidate == target)
        .count()
}

fn descriptor_sources(count: usize) -> Vec<(UnixStream, UnixStream, PathBuf)> {
    std::iter::repeat_with(|| {
        let (source, peer) = UnixStream::pair().unwrap();
        let target = descriptor_target(source.as_fd());
        (source, peer, target)
    })
    .take(count)
    .collect()
}

fn send_sources(socket: &OwnedFd, sources: &[(UnixStream, UnixStream, PathBuf)]) {
    let payload = [0u8];
    let iov = [IoSlice::new(&payload)];
    let raw_fds: Vec<_> = sources
        .iter()
        .map(|(source, _, _)| source.as_raw_fd())
        .collect();
    sendmsg::<()>(
        socket.as_raw_fd(),
        &iov,
        &[ControlMessage::ScmRights(&raw_fds)],
        MsgFlags::empty(),
        None,
    )
    .unwrap();
}

fn assert_only_source_descriptors_remain(sources: &[(UnixStream, UnixStream, PathBuf)]) {
    for (_, _, target) in sources {
        assert_eq!(
            target_descriptor_count(target),
            1,
            "leaked descriptor for {target:?}"
        );
    }
}

#[test]
fn reaped_child_error_does_not_run_cleanup() {
    let cleanup_calls = Cell::new(0);
    {
        let mut child = ChildGuard::new(4242, |_| cleanup_calls.set(cleanup_calls.get() + 1));
        let error = finish_reaped_child(&mut child, libc::SIGKILL).unwrap_err();
        assert!(error.to_string().contains("did not exit normally"));
    }
    assert_eq!(cleanup_calls.get(), 0);
}

#[test]
fn child_success_maps_to_zero_status() {
    let outcome = catch_child(None, || Ok(()));
    assert_eq!(outcome.exit_status(), 0);
}

#[test]
fn child_error_maps_to_one_status() {
    let outcome = catch_child(None, || Err(anyhow::anyhow!("classified error")));
    assert_eq!(outcome.exit_status(), 1);
}

#[test]
fn child_panic_maps_to_two_status() {
    let outcome = catch_child(None, || -> anyhow::Result<()> {
        panic!("bounded test panic")
    });
    assert!(matches!(outcome, ChildOutcome::Panic));
    assert_eq!(outcome.exit_status(), 2);
}

#[test]
fn diagnostic_formatting_panic_maps_to_two_status() {
    let (_parent, child) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .unwrap();

    let outcome = catch_child(Some(child.as_fd()), || {
        Err(anyhow::Error::new(PanickingDiagnostic))
    });

    assert!(matches!(outcome, ChildOutcome::Panic));
    assert_eq!(outcome.exit_status(), 2);
}

#[test]
fn missing_child_capabilities_map_to_distinct_status() {
    let outcome = catch_child(None, || {
        Err(MissingCapabilities::new(CapabilityProfile::XdpLoad, 0).into())
    });
    assert!(matches!(outcome, ChildOutcome::MissingCapabilities));
    assert_eq!(outcome.exit_status(), 3);
}

#[test]
fn missing_child_capability_status_is_clear() {
    let cleanup_calls = Cell::new(0);
    let mut child = ChildGuard::new(4242, |_| cleanup_calls.set(cleanup_calls.get() + 1));

    let error = finish_reaped_child(&mut child, 3 << 8).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("missing required effective capabilities")
    );
    assert_eq!(cleanup_calls.get(), 0);
}

#[test]
fn child_capability_profiles_match_bpf_operations() {
    assert_eq!(CapabilityProfile::Token.required_mask(), 1u64 << 39);
    assert_eq!(
        CapabilityProfile::TracePointLoad.required_mask(),
        (1u64 << 39) | (1u64 << 38)
    );
    assert_eq!(
        CapabilityProfile::XdpLoad.required_mask(),
        (1u64 << 39) | (1u64 << 12)
    );
}

#[test]
fn effective_capabilities_are_parsed_from_proc_status() {
    let status = "Name:\ttoken-test\nCapEff:\t000000c000001000\n";

    let effective = parse_effective_capabilities(status).unwrap();

    assert_eq!(effective, (1u64 << 39) | (1u64 << 38) | (1u64 << 12));
}

#[test]
fn child_error_diagnostic_is_delivered() {
    let (parent, child) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .unwrap();

    let outcome = catch_child(Some(child.as_fd()), || {
        Err(anyhow::anyhow!("exact pre-syscall Aya error"))
    });
    drop(child);
    let diagnostic = read_child_diagnostic(&parent).unwrap();

    assert!(matches!(outcome, ChildOutcome::Error));
    assert_eq!(diagnostic, "exact pre-syscall Aya error");
}

#[test]
fn child_error_diagnostic_is_bounded() {
    let (parent, child) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .unwrap();
    let error = "x".repeat(CHILD_DIAGNOSTIC_MAX * 2);

    let outcome = catch_child(Some(child.as_fd()), || Err(anyhow::Error::msg(error)));
    drop(child);
    let diagnostic = read_child_diagnostic(&parent).unwrap();

    assert!(matches!(outcome, ChildOutcome::Error));
    assert_eq!(diagnostic.len(), CHILD_DIAGNOSTIC_MAX);
    assert!(diagnostic.bytes().all(|byte| byte == b'x'));
}

#[test]
fn absent_child_diagnostic_returns_without_blocking() {
    let (parent, child) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .unwrap();
    drop(child);

    let diagnostic = read_child_diagnostic(&parent).unwrap();

    assert!(diagnostic.is_empty());
}

#[test]
fn truncated_scm_rights_closes_every_installed_descriptor() {
    let (sender, receiver) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .unwrap();
    let sources = descriptor_sources(4);
    send_sources(&sender, &sources);
    let mut control = cmsg_space!([RawFd; 1]);

    let error = receive_fd_with_control(&receiver, &mut control).unwrap_err();

    assert!(error.to_string().contains("truncated"), "{error}");
    assert_only_source_descriptors_remain(&sources);
}

#[test]
fn multiple_scm_rights_fds_are_all_closed_when_rejected() {
    let (sender, receiver) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .unwrap();
    let sources = descriptor_sources(2);
    send_sources(&sender, &sources);
    let mut control = cmsg_space!([RawFd; 2]);

    let error = receive_fd_with_control(&receiver, &mut control).unwrap_err();

    assert!(error.to_string().contains("descriptor count"));
    assert_only_source_descriptors_remain(&sources);
}
