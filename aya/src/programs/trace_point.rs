//! Tracepoint programs.
use std::{
    fs, io,
    os::fd::{AsFd as _, OwnedFd},
    path::{Path, PathBuf},
};

use aya_obj::generated::{bpf_link_type, bpf_prog_type::BPF_PROG_TYPE_TRACEPOINT};
use thiserror::Error;

use crate::{
    programs::{
        ProgramData, ProgramError, ProgramType, define_link_wrapper, impl_try_from_fdlink,
        impl_try_into_fdlink, load_program_without_attach_type,
        perf_attach::{PerfLinkIdInner, PerfLinkInner, attach_perf_event, perf_attach},
        utils::find_tracefs_path,
    },
    sys::{SyscallError, perf_event_open_trace_point},
};

/// The type returned when attaching a [`TracePoint`] fails.
#[derive(Debug, Error)]
pub enum TracePointError {
    /// Error detaching from debugfs
    #[error("`{filename}`")]
    FileError {
        /// The file name
        filename: PathBuf,
        /// The [`io::Error`] returned from the file operation
        #[source]
        io_error: io::Error,
    },
}

/// A program that can be attached at a pre-defined kernel trace point.
///
/// The kernel provides a set of pre-defined trace points that eBPF programs can
/// be attached to. See `/sys/kernel/debug/tracing/events` for a list of which
/// events can be traced.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.7.
///
/// # Examples
///
/// ```no_run
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::programs::TracePoint;
///
/// let prog: &mut TracePoint = bpf.program_mut("trace_context_switch").unwrap().try_into()?;
/// prog.load()?;
/// prog.attach("sched", "sched_switch")?;
/// # Ok::<(), aya::EbpfError>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_TRACEPOINT")]
pub struct TracePoint {
    pub(crate) data: ProgramData<TracePointLink>,
}

impl TracePoint {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::TracePoint;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let Self { data } = self;
        load_program_without_attach_type(BPF_PROG_TYPE_TRACEPOINT, data)
    }

    /// Attaches to a given trace point.
    ///
    /// For a list of the available event categories and names, see
    /// `/sys/kernel/debug/tracing/events`.
    ///
    /// The returned value can be used to detach, see [`TracePoint::detach`].
    pub fn attach(&mut self, category: &str, name: &str) -> Result<TracePointLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let tracefs = find_tracefs_path()?;
        let id = read_sys_fs_trace_point_id(tracefs, category, name.as_ref())?;
        let perf_fd = perf_event_open_trace_point(id, None).map_err(|io_error| SyscallError {
            call: "perf_event_open_trace_point",
            io_error,
        })?;

        let link = perf_attach(
            prog_fd,
            perf_fd,
            None, /* cookie */
            &self.data.features,
        )?;
        self.data.links.insert(TracePointLink::new(link))
    }

    /// Attaches this program to a caller-supplied perf event descriptor.
    ///
    /// The descriptor is consumed and owned by the returned link. This path
    /// uses `PERF_EVENT_IOC_SET_BPF` and `PERF_EVENT_IOC_ENABLE` directly and
    /// does not open another perf event.
    ///
    /// # Errors
    ///
    /// Returns an error if the program is not loaded or either perf ioctl fails.
    #[cfg(target_os = "linux")]
    pub fn attach_to_perf_event(
        &mut self,
        perf_fd: OwnedFd,
    ) -> Result<TracePointLink, ProgramError> {
        let prog_fd = self.fd()?.as_fd();
        let link = attach_perf_event(prog_fd, crate::MockableFd::from_fd(perf_fd), None)?;
        Ok(TracePointLink::new(PerfLinkInner::PerfLink(link)))
    }
}

define_link_wrapper!(
    TracePointLink,
    TracePointLinkId,
    PerfLinkInner,
    PerfLinkIdInner,
    TracePoint,
);

impl_try_into_fdlink!(TracePointLink, PerfLinkInner);
impl_try_from_fdlink!(
    TracePointLink,
    PerfLinkInner,
    bpf_link_type::BPF_LINK_TYPE_PERF_EVENT
);

pub(crate) fn read_sys_fs_trace_point_id(
    tracefs: &Path,
    category: &str,
    name: &Path,
) -> Result<u64, TracePointError> {
    let filename = tracefs.join("events").join(category).join(name).join("id");

    let id = match fs::read_to_string(&filename) {
        Ok(id) => id,
        Err(io_error) => return Err(TracePointError::FileError { filename, io_error }),
    };
    let id = match id.trim().parse() {
        Ok(id) => id,
        Err(error) => {
            return Err(TracePointError::FileError {
                filename,
                io_error: io::Error::other(error),
            });
        }
    };

    Ok(id)
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    mod linux {
        use std::{cell::Cell, fs::File, io, os::fd::AsRawFd as _, path::Path};

        use assert_matches::assert_matches;
        use aya_obj::generated::bpf_prog_info;

        use super::super::TracePoint;
        use crate::{
            VerifierLogLevel,
            features::Features,
            programs::{ProgramData, ProgramError},
            sys::{PerfEventIoctlRequest, Syscall, override_syscall},
        };

        thread_local! {
            static IOCTL_COUNT: Cell<usize> = const { Cell::new(0) };
        }

        const fn empty_program_info() -> bpf_prog_info {
            // SAFETY: every field in the bindgen C struct accepts the all-zero representation.
            unsafe { std::mem::zeroed() }
        }

        fn loaded_tracepoint() -> TracePoint {
            let data = ProgramData::from_bpf_prog_info(
                None,
                crate::MockableFd::from(File::open("/dev/null").unwrap()),
                Path::new(""),
                empty_program_info(),
                VerifierLogLevel::default(),
                None,
                Features::default(),
            )
            .unwrap();
            TracePoint { data }
        }

        #[test]
        #[cfg_attr(miri, ignore = "`open` and `fcntl` require OS file descriptors")]
        fn inherited_perf_event_is_owned_and_attached_without_open() {
            IOCTL_COUNT.set(0);
            override_syscall(|call| match call {
                Syscall::PerfEventIoctl {
                    request: PerfEventIoctlRequest::SetBpf(_) | PerfEventIoctlRequest::Enable,
                    ..
                } => {
                    IOCTL_COUNT.set(IOCTL_COUNT.get() + 1);
                    Ok(0)
                }
                Syscall::PerfEventIoctl {
                    request: PerfEventIoctlRequest::Disable,
                    ..
                } => Ok(0),
                call => panic!("unexpected syscall: {call:?}"),
            });
            let perf_fd = File::open("/dev/null").unwrap();
            let raw_fd = perf_fd.as_raw_fd();
            let mut program = loaded_tracepoint();

            let link = program.attach_to_perf_event(perf_fd.into()).unwrap();

            assert_eq!(IOCTL_COUNT.get(), 2);
            // SAFETY: `link` owns the inherited descriptor until it is dropped below.
            assert_ne!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) }, -1);
            drop(link);
            // SAFETY: F_GETFD reports descriptor liveness without dereferencing memory.
            assert_eq!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        }

        #[test]
        #[cfg_attr(miri, ignore = "`open` and `fcntl` require OS file descriptors")]
        fn inherited_perf_event_attach_failure_closes_fd_without_open() {
            override_syscall(|call| match call {
                Syscall::PerfEventIoctl {
                    request: PerfEventIoctlRequest::SetBpf(_),
                    ..
                } => Err((-1, io::Error::from_raw_os_error(libc::EINVAL))),
                call => panic!("unexpected syscall: {call:?}"),
            });
            let perf_fd = File::open("/dev/null").unwrap();
            let raw_fd = perf_fd.as_raw_fd();
            let mut program = loaded_tracepoint();

            let error = program.attach_to_perf_event(perf_fd.into()).unwrap_err();

            assert_matches!(error, ProgramError::SyscallError(_));
            // SAFETY: F_GETFD reports descriptor liveness without dereferencing memory.
            assert_eq!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        }
    }
}
