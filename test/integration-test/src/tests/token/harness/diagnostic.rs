use std::{
    fmt::{self, Write as _},
    io,
    os::fd::{AsRawFd as _, BorrowedFd, OwnedFd},
    panic::{AssertUnwindSafe, catch_unwind},
};

use anyhow::Result;

use super::capabilities::MissingCapabilities;

pub(crate) const CHILD_DIAGNOSTIC_MAX: usize = 1024;

struct DiagnosticBuffer {
    bytes: [u8; CHILD_DIAGNOSTIC_MAX],
    len: usize,
}

impl DiagnosticBuffer {
    const fn new() -> Self {
        Self {
            bytes: [0; CHILD_DIAGNOSTIC_MAX],
            len: 0,
        }
    }

    const fn as_bytes(&self) -> &[u8] {
        self.bytes.split_at(self.len).0
    }
}

impl fmt::Write for DiagnosticBuffer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let remaining = CHILD_DIAGNOSTIC_MAX - self.len;
        let count = remaining.min(s.len());
        self.bytes[self.len..self.len + count].copy_from_slice(&s.as_bytes()[..count]);
        self.len += count;
        Ok(())
    }
}

pub(super) fn write_child_diagnostic(fd: BorrowedFd<'_>, error: &anyhow::Error) {
    let mut buffer = DiagnosticBuffer::new();
    if write!(&mut buffer, "{error:#}").is_err() {
        return;
    }
    let bytes = buffer.as_bytes();
    if bytes.is_empty() {
        return;
    }
    // SAFETY: fd is the live child socket; bytes points to a readable buffer for bytes.len().
    unsafe {
        libc::send(
            fd.as_raw_fd(),
            bytes.as_ptr().cast(),
            bytes.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        );
    }
}

pub(crate) fn read_child_diagnostic(fd: &OwnedFd) -> io::Result<String> {
    let mut bytes = [0u8; CHILD_DIAGNOSTIC_MAX];
    let mut len = 0;
    while len < bytes.len() {
        // SAFETY: fd is the live parent socket and the remaining slice is writable.
        let result = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                bytes[len..].as_mut_ptr().cast(),
                bytes.len() - len,
                0,
            )
        };
        if result > 0 {
            len += result as usize;
            continue;
        }
        if result == 0 {
            break;
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
    Ok(String::from_utf8_lossy(&bytes[..len]).into_owned())
}

#[derive(Clone, Copy)]
pub(crate) enum ChildOutcome {
    Success,
    Error,
    Panic,
    MissingCapabilities,
}

impl ChildOutcome {
    pub(crate) const fn exit_status(self) -> libc::c_int {
        match self {
            Self::Success => 0,
            Self::Error => 1,
            Self::Panic => 2,
            Self::MissingCapabilities => 3,
        }
    }
}

pub(crate) fn catch_child<F>(diagnostic_fd: Option<BorrowedFd<'_>>, child: F) -> ChildOutcome
where
    F: FnOnce() -> Result<()>,
{
    match catch_unwind(AssertUnwindSafe(|| match child() {
        Ok(()) => ChildOutcome::Success,
        Err(error) => {
            let outcome = if error.downcast_ref::<MissingCapabilities>().is_some() {
                ChildOutcome::MissingCapabilities
            } else {
                ChildOutcome::Error
            };
            if let Some(fd) = diagnostic_fd {
                write_child_diagnostic(fd, &error);
            }
            outcome
        }
    })) {
        Ok(outcome) => outcome,
        Err(_) => ChildOutcome::Panic,
    }
}

pub(super) fn exit_child(outcome: ChildOutcome) -> ! {
    let exit_code = outcome.exit_status();
    // SAFETY: terminate the fork child without running inherited process-wide destructors.
    unsafe { libc::_exit(exit_code) }
}
