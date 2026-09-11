use std::{
    io::{IoSlice, IoSliceMut},
    os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd},
};

use anyhow::{Context as _, Result, bail, ensure};
use nix::{
    cmsg_space,
    sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg},
};

pub(super) fn send_fd(socket: &OwnedFd, fd: std::os::fd::BorrowedFd<'_>) -> Result<()> {
    let payload = [0u8];
    let iov = [IoSlice::new(&payload)];
    let raw_fds = [fd.as_raw_fd()];
    let control = [ControlMessage::ScmRights(&raw_fds)];
    let sent = sendmsg::<()>(socket.as_raw_fd(), &iov, &control, MsgFlags::empty(), None)
        .context("send descriptor with SCM_RIGHTS")?;
    ensure!(sent == payload.len(), "short SCM_RIGHTS payload write");
    Ok(())
}

pub(super) fn receive_fd(socket: &OwnedFd) -> Result<OwnedFd> {
    let mut control = cmsg_space!([RawFd; 1]);
    receive_fd_with_control(socket, &mut control)
}

pub(in super::super) fn receive_fd_with_control(
    socket: &OwnedFd,
    control: &mut [u8],
) -> Result<OwnedFd> {
    let mut payload = [0u8];
    let expected_bytes = payload.len();
    let mut iov = [IoSliceMut::new(&mut payload)];
    let message = recvmsg::<()>(
        socket.as_raw_fd(),
        &mut iov,
        Some(control),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )
    .context("receive descriptor with SCM_RIGHTS")?;

    let bytes = message.bytes;
    let flags = message.flags;
    if flags.contains(MsgFlags::MSG_CTRUNC) {
        drop(adopt_truncated_rights(control));
        bail!("SCM_RIGHTS control message was truncated");
    }
    let mut received = Vec::new();
    let mut scm_rights_messages = 0;
    let mut unexpected_control = false;
    for control in message
        .cmsgs()
        .context("parse SCM_RIGHTS control message")?
    {
        match control {
            ControlMessageOwned::ScmRights(raw_fds) => {
                scm_rights_messages += 1;
                received.extend(raw_fds.into_iter().map(|raw_fd| {
                    // SAFETY: SCM_RIGHTS returned a new descriptor owned by this process.
                    unsafe { OwnedFd::from_raw_fd(raw_fd) }
                }));
            }
            _ => unexpected_control = true,
        }
    }

    ensure!(bytes == expected_bytes, "SCM_RIGHTS peer closed early");
    ensure!(
        !unexpected_control,
        "received unexpected Unix control message"
    );
    ensure!(
        scm_rights_messages == 1,
        "received unexpected SCM_RIGHTS message count"
    );
    ensure!(received.len() == 1, "received unexpected descriptor count");
    received
        .pop()
        .context("SCM_RIGHTS message contained no descriptor")
}

fn adopt_truncated_rights(control: &[u8]) -> Vec<OwnedFd> {
    // SAFETY: CMSG_LEN only computes the aligned header size for the constant zero payload.
    let header_len = unsafe { libc::CMSG_LEN(0) as usize };
    let alignment = size_of::<usize>();
    let mut offset = 0;
    let mut received = Vec::new();
    while control.len().saturating_sub(offset) >= size_of::<libc::cmsghdr>() {
        // SAFETY: the bounds check above covers one possibly unaligned cmsghdr value.
        let header = unsafe {
            std::ptr::read_unaligned(control.as_ptr().add(offset).cast::<libc::cmsghdr>())
        };
        if header.cmsg_len < header_len {
            break;
        }
        let Some(message_end) = offset.checked_add(header.cmsg_len) else {
            break;
        };
        let message_end = message_end.min(control.len());
        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
            let data_start = offset + header_len;
            let fd_count = message_end.saturating_sub(data_start) / size_of::<RawFd>();
            for index in 0..fd_count {
                let fd_offset = data_start + index * size_of::<RawFd>();
                // SAFETY: fd_offset is bounded by message_end and SCM_RIGHTS contains installed FDs.
                let raw_fd = unsafe {
                    std::ptr::read_unaligned(control.as_ptr().add(fd_offset).cast::<RawFd>())
                };
                // SAFETY: each SCM_RIGHTS entry is a new descriptor owned by this process.
                received.push(unsafe { OwnedFd::from_raw_fd(raw_fd) });
            }
        }
        let Some(next) = header
            .cmsg_len
            .checked_add(alignment - 1)
            .map(|len| len & !(alignment - 1))
            .and_then(|len| offset.checked_add(len))
        else {
            break;
        };
        if next <= offset {
            break;
        }
        offset = next;
    }
    received
}
