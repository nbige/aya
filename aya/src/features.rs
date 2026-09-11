//! A snapshot of kernel feature support.
//!
//! Most callers use the process-ambient snapshot ([`Features::ambient`]), which is derived from
//! [`crate::kernel_features::FEATURES`] and therefore benefits from its per-feature caching.
//! Loading through a BPF token instead uses [`Features::detect_with_token`], which performs no
//! probes at all: `BPF_TOKEN_CREATE` requires Linux 6.9, and every feature this snapshot tracks
//! landed years before that, so the token's mere existence already proves the kernel supports
//! all of them.

use std::{io, os::fd::BorrowedFd, sync::LazyLock};

use aya_obj::btf::BtfFeature;

use crate::kernel_features::{FEATURES, Feature};

/// A `(major, minor, patch)` kernel version, ordered like [`crate::util::KernelVersion`].
type MinKernelVersion = (u16, u16, u16);

/// Returns whether `version` is at or before `max`.
const fn version_at_most(version: MinKernelVersion, max: MinKernelVersion) -> bool {
    let (major, minor, patch) = version;
    let (max_major, max_minor, max_patch) = max;
    if major != max_major {
        return major < max_major;
    }
    if minor != max_minor {
        return minor < max_minor;
    }
    patch <= max_patch
}

/// The kernel version `BPF_TOKEN_CREATE` itself requires (Linux 6.9). A BPF token cannot exist
/// on a kernel older than this, so its mere presence already proves every entry in
/// [`TOKEN_IMPLIED_FEATURE_VERSIONS`] and [`TOKEN_IMPLIED_BTF_FEATURE_VERSIONS`].
const MIN_TOKEN_KERNEL_VERSION: MinKernelVersion = (6, 9, 0);

/// Minimum kernel version for each non-BTF feature [`Features::detect_with_token`] tracks. Every
/// entry predates [`MIN_TOKEN_KERNEL_VERSION`], so none of them needs a live probe when a token
/// is in use: the token's own existence already proves the kernel is new enough.
///
/// - `bpf_name`: BPF map/program names, kernel 4.15
///   (<https://github.com/torvalds/linux/commit/ad5b177bd73f5107d97c36f56395c4281fb6f089>).
/// - `bpf_probe_read_kernel`: the `bpf_probe_read_kernel` helper, kernel 5.5.
/// - `bpf_global_data`: `.data`/`.rodata`/`.bss` global data maps, kernel 5.2.
/// - `bpf_perf_link`: `BPF_LINK_CREATE` for perf-event-backed kprobe/uprobe/tracepoint
///   attachment, kernel 5.15.
/// - `bpf_cookie`: the `bpf_get_attach_cookie` helper, kernel 5.15.
/// - `cpumap_prog_id` / `devmap_prog_id`: chained XDP program ids on `CPUMAP`/`DEVMAP` map
///   values, kernel 5.9.
const TOKEN_IMPLIED_FEATURE_VERSIONS: [(&str, MinKernelVersion); 7] = [
    ("bpf_name", (4, 15, 0)),
    ("bpf_probe_read_kernel", (5, 5, 0)),
    ("bpf_global_data", (5, 2, 0)),
    ("bpf_perf_link", (5, 15, 0)),
    ("bpf_cookie", (5, 15, 0)),
    ("cpumap_prog_id", (5, 9, 0)),
    ("devmap_prog_id", (5, 9, 0)),
];

/// Minimum kernel version for `BPF_BTF_LOAD` itself and each [`BtfFeature`]
/// [`Features::detect_with_token`] tracks. This is the kernel's acceptance of a *user-supplied*
/// BTF blob passed to `BPF_BTF_LOAD`/`BPF_PROG_LOAD`/`BPF_MAP_CREATE`, gated purely by kernel
/// version (`CONFIG_BPF_SYSCALL`), unlike the *kernel's own* embedded vmlinux BTF exposed at
/// `/sys/kernel/btf/vmlinux`, which depends on the build-time `CONFIG_DEBUG_INFO_BTF` option and
/// is read directly from that file elsewhere ([`crate::Btf::from_sys_fs`]) rather than probed
/// here. Every entry below predates [`MIN_TOKEN_KERNEL_VERSION`] too.
///
/// - `btf`: `BPF_BTF_LOAD`, kernel 4.18.
/// - `Func`/`Float`: kernel 5.1.
/// - `FuncGlobal`/`DataSec`/`DataSecZero`: kernel 5.2.
/// - `DeclTag`: kernel 5.16.
/// - `TypeTag`: kernel 5.17.
/// - `Enum64`: kernel 6.0
///   (<https://lwn.net/Articles/893267/>).
const TOKEN_IMPLIED_BTF_FEATURE_VERSIONS: [(&str, MinKernelVersion); 9] = [
    ("btf", (4, 18, 0)),
    ("Func", (5, 1, 0)),
    ("Float", (5, 1, 0)),
    ("FuncGlobal", (5, 2, 0)),
    ("DataSec", (5, 2, 0)),
    ("DataSecZero", (5, 2, 0)),
    ("DeclTag", (5, 16, 0)),
    ("TypeTag", (5, 17, 0)),
    ("Enum64", (6, 0, 0)),
];

const _: () = {
    let mut i = 0;
    while i < TOKEN_IMPLIED_FEATURE_VERSIONS.len() {
        let (_name, version) = TOKEN_IMPLIED_FEATURE_VERSIONS[i];
        assert!(
            version_at_most(version, MIN_TOKEN_KERNEL_VERSION),
            "a feature claimed to be implied by BPF token support must predate Linux 6.9"
        );
        i += 1;
    }
    let mut i = 0;
    while i < TOKEN_IMPLIED_BTF_FEATURE_VERSIONS.len() {
        let (_name, version) = TOKEN_IMPLIED_BTF_FEATURE_VERSIONS[i];
        assert!(
            version_at_most(version, MIN_TOKEN_KERNEL_VERSION),
            "a BTF feature claimed to be implied by BPF token support must predate Linux 6.9"
        );
        i += 1;
    }
};

/// BTF capabilities of a [`Features`] snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BtfCapabilities {
    func: bool,
    func_global: bool,
    datasec: bool,
    datasec_zero: bool,
    float: bool,
    decl_tag: bool,
    type_tag: bool,
    enum64: bool,
}

impl BtfCapabilities {
    /// Returns whether the given BTF feature is supported.
    pub const fn is_supported(&self, feature: BtfFeature) -> bool {
        let Self {
            func,
            func_global,
            datasec,
            datasec_zero,
            float,
            decl_tag,
            type_tag,
            enum64,
        } = self;
        match feature {
            BtfFeature::Func => *func,
            BtfFeature::FuncGlobal => *func_global,
            BtfFeature::DataSec => *datasec,
            BtfFeature::DataSecZero => *datasec_zero,
            BtfFeature::Float => *float,
            BtfFeature::DeclTag => *decl_tag,
            BtfFeature::TypeTag => *type_tag,
            BtfFeature::Enum64 => *enum64,
        }
    }
}

/// Kernel BPF and BTF feature support, either the process-ambient set or one probed through a
/// specific BPF token.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Features {
    bpf_name: bool,
    bpf_probe_read_kernel: bool,
    bpf_perf_link: bool,
    bpf_global_data: bool,
    bpf_cookie: bool,
    cpumap_prog_id: bool,
    devmap_prog_id: bool,
    btf: Option<BtfCapabilities>,
}

impl Features {
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "this interface is terrible"
    )]
    #[expect(clippy::too_many_arguments, reason = "this interface is terrible")]
    #[doc(hidden)]
    pub const fn new(
        bpf_name: bool,
        bpf_probe_read_kernel: bool,
        bpf_perf_link: bool,
        bpf_global_data: bool,
        bpf_cookie: bool,
        cpumap_prog_id: bool,
        devmap_prog_id: bool,
        btf: Option<BtfCapabilities>,
    ) -> Self {
        Self {
            bpf_name,
            bpf_probe_read_kernel,
            bpf_perf_link,
            bpf_global_data,
            bpf_cookie,
            cpumap_prog_id,
            devmap_prog_id,
            btf,
        }
    }

    /// Snapshots the process-ambient feature set.
    ///
    /// This reads through to [`crate::kernel_features::FEATURES`], so each underlying feature is
    /// still probed at most once per process.
    fn ambient() -> Self {
        Self {
            bpf_name: FEATURES.is_supported(Feature::BpfName),
            bpf_probe_read_kernel: FEATURES.is_supported(Feature::BpfProbeReadKernel),
            bpf_perf_link: FEATURES.is_supported(Feature::BpfPerfLink),
            bpf_global_data: FEATURES.is_supported(Feature::BpfGlobalData),
            bpf_cookie: FEATURES.is_supported(Feature::BpfCookie),
            cpumap_prog_id: FEATURES.is_supported(Feature::CpuMapProgId),
            devmap_prog_id: FEATURES.is_supported(Feature::DevMapProgId),
            btf: FEATURES.btf().map(|caps| BtfCapabilities {
                func: caps.is_supported(BtfFeature::Func),
                func_global: caps.is_supported(BtfFeature::FuncGlobal),
                datasec: caps.is_supported(BtfFeature::DataSec),
                datasec_zero: caps.is_supported(BtfFeature::DataSecZero),
                float: caps.is_supported(BtfFeature::Float),
                decl_tag: caps.is_supported(BtfFeature::DeclTag),
                type_tag: caps.is_supported(BtfFeature::TypeTag),
                enum64: caps.is_supported(BtfFeature::Enum64),
            }),
        }
    }

    /// Returns the process-ambient feature set, computed once and cached for the process.
    pub(crate) fn ambient_cached() -> Self {
        static AMBIENT: LazyLock<Features> = LazyLock::new(Features::ambient);
        AMBIENT.clone()
    }

    /// Detects BPF and BTF features implied by the given BPF token's privilege delegation.
    ///
    /// This performs no probe syscalls. `BPF_TOKEN_CREATE` itself requires Linux 6.9
    /// (see [`MIN_TOKEN_KERNEL_VERSION`]), and every feature and BTF capability this snapshot
    /// tracks landed years earlier (see [`TOKEN_IMPLIED_FEATURE_VERSIONS`] and
    /// [`TOKEN_IMPLIED_BTF_FEATURE_VERSIONS`]), so a token's mere existence already proves the
    /// kernel supports all of them: there is nothing left to determine by probing.
    ///
    /// Probing anyway would be actively wrong under token-scoped privilege delegation, not just
    /// redundant: each probe loads a program or creates a map of some fixed, hardcoded type
    /// (for example `probe_bpf_global_data`'s program probe always uses
    /// `BPF_PROG_TYPE_SOCKET_FILTER`) chosen without regard to what the caller's token actually
    /// delegates. A token that delegates only the program and map types a real load needs can
    /// reject a probe's unrelated type with a permission error unrelated to whether the kernel
    /// supports the feature under test, previously either misread as "unsupported" (silently
    /// dropping global-data maps and breaking relocations) or, if propagated faithfully, failing
    /// a load the token and kernel both fully support.
    ///
    /// This intentionally excludes reading the kernel's own embedded vmlinux BTF from
    /// `/sys/kernel/btf/vmlinux` (used elsewhere for [`crate::programs::ProgramInfo`]-driven
    /// CO-RE against kernel types): that depends on the build-time `CONFIG_DEBUG_INFO_BTF`
    /// option rather than kernel version, is not part of this snapshot, is read directly from
    /// that file rather than probed through the token, and is unaffected by this change.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "kept for API stability across call sites"
    )]
    pub(crate) const fn detect_with_token(_token_fd: BorrowedFd<'_>) -> io::Result<Self> {
        Ok(Self {
            bpf_name: true,
            bpf_probe_read_kernel: true,
            bpf_perf_link: true,
            bpf_global_data: true,
            bpf_cookie: true,
            cpumap_prog_id: true,
            devmap_prog_id: true,
            btf: Some(BtfCapabilities {
                func: true,
                func_global: true,
                datasec: true,
                datasec_zero: true,
                float: true,
                decl_tag: true,
                type_tag: true,
                enum64: true,
            }),
        })
    }

    /// Returns whether BPF program names and map names are supported.
    pub const fn bpf_name(&self) -> bool {
        self.bpf_name
    }

    /// Returns whether the `bpf_probe_read_kernel` helper is supported.
    pub const fn bpf_probe_read_kernel(&self) -> bool {
        self.bpf_probe_read_kernel
    }

    /// Returns whether `bpf_links` are supported for Kprobes/Uprobes/Tracepoints.
    pub const fn bpf_perf_link(&self) -> bool {
        self.bpf_perf_link
    }

    /// Returns whether BPF program global data is supported.
    pub const fn bpf_global_data(&self) -> bool {
        self.bpf_global_data
    }

    /// Returns whether BPF program cookie is supported.
    pub const fn bpf_cookie(&self) -> bool {
        self.bpf_cookie
    }

    /// Returns whether XDP CPU Maps support chained program IDs.
    pub const fn cpumap_prog_id(&self) -> bool {
        self.cpumap_prog_id
    }

    /// Returns whether XDP Device Maps support chained program IDs.
    pub const fn devmap_prog_id(&self) -> bool {
        self.devmap_prog_id
    }

    /// If BTF is supported, returns which BTF features are supported.
    pub const fn btf(&self) -> Option<&BtfCapabilities> {
        self.btf.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, os::fd::BorrowedFd};

    use super::Features;
    use crate::sys::override_syscall;

    const TOKEN_FD: std::os::fd::RawFd = 42;

    thread_local! {
        static SYSCALL_COUNT: Cell<usize> = const { Cell::new(0) };
    }

    /// `detect_with_token` must not issue any probe syscall: `BPF_TOKEN_CREATE` requires Linux
    /// 6.9, every feature this snapshot tracks landed years before that, and probing anyway can
    /// spuriously fail (or spuriously succeed) against a token that does not delegate a given
    /// probe's own hardcoded program or map type, unrelated to whether the feature under test is
    /// actually supported. Every flag must still come back `true`.
    #[test]
    fn detect_with_token_probes_nothing_and_reports_full_support() {
        SYSCALL_COUNT.set(0);
        override_syscall(|call| {
            SYSCALL_COUNT.set(SYSCALL_COUNT.get() + 1);
            panic!("unexpected syscall during token-implied feature detection: {call:?}");
        });

        // SAFETY: TOKEN_FD is used only as an opaque integer; no syscall touches it.
        let token_fd = unsafe { BorrowedFd::borrow_raw(TOKEN_FD) };
        let features = Features::detect_with_token(token_fd).unwrap();

        assert_eq!(SYSCALL_COUNT.get(), 0);

        assert!(features.bpf_name());
        assert!(features.bpf_probe_read_kernel());
        assert!(features.bpf_perf_link());
        assert!(features.bpf_global_data());
        assert!(features.bpf_cookie());
        assert!(features.cpumap_prog_id());
        assert!(features.devmap_prog_id());

        let btf = features.btf().expect("BTF support must be implied");
        assert!(btf.is_supported(aya_obj::btf::BtfFeature::Func));
        assert!(btf.is_supported(aya_obj::btf::BtfFeature::FuncGlobal));
        assert!(btf.is_supported(aya_obj::btf::BtfFeature::DataSec));
        assert!(btf.is_supported(aya_obj::btf::BtfFeature::DataSecZero));
        assert!(btf.is_supported(aya_obj::btf::BtfFeature::Float));
        assert!(btf.is_supported(aya_obj::btf::BtfFeature::DeclTag));
        assert!(btf.is_supported(aya_obj::btf::BtfFeature::TypeTag));
        assert!(btf.is_supported(aya_obj::btf::BtfFeature::Enum64));
    }

    #[test]
    fn version_at_most_orders_major_minor_patch() {
        use super::version_at_most;

        assert!(version_at_most((5, 15, 0), (6, 9, 0)));
        assert!(version_at_most((6, 9, 0), (6, 9, 0)));
        assert!(!version_at_most((6, 9, 1), (6, 9, 0)));
        assert!(!version_at_most((6, 10, 0), (6, 9, 0)));
        assert!(!version_at_most((7, 0, 0), (6, 9, 0)));
    }
}
