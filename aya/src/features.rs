//! Kernel feature support.
//!
//! Internally, Aya reads the process-ambient feature set through a process-wide probe cache.
//! Nothing is probed until a feature is queried, and each feature is probed at most once per
//! process.
//! [`crate::features()`] instead returns a fixed snapshot: it probes every feature once, so a
//! clone taken before a privilege drop or a fork keeps its values.
//! Loading through a BPF token uses the features implied by token support, and performs no
//! probes at all: `BPF_TOKEN_CREATE` requires Linux 6.9, and every feature tracked here landed
//! years before that, so the token's mere existence already proves the kernel supports all of
//! them.

use std::sync::LazyLock;

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

/// Minimum kernel version for each non-BTF feature [`Features::implied_by_token`] tracks. Every
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
/// [`Features::implied_by_token`] tracks. This is the kernel's acceptance of a *user-supplied*
/// BTF blob passed to `BPF_BTF_LOAD`/`BPF_PROG_LOAD`/`BPF_MAP_CREATE`, gated purely by kernel
/// version (`CONFIG_BPF_SYSCALL`), unlike the *kernel's own* embedded vmlinux BTF exposed at
/// `/sys/kernel/btf/vmlinux`, which depends on the build-time `CONFIG_DEBUG_INFO_BTF` option and
/// is read directly from that file elsewhere ([`crate::Btf::from_sys_fs`]) rather than probed
/// here. Every entry below predates [`MIN_TOKEN_KERNEL_VERSION`] too.
///
/// - `btf`: `BPF_BTF_LOAD`, kernel 4.18.
/// - `Func`: kernel 4.20.
/// - `DataSec`/`DataSecZero`: kernel 5.2.
/// - `FuncGlobal`: kernel 5.6.
/// - `Float`: kernel 5.13.
/// - `DeclTag`: kernel 5.16.
/// - `TypeTag`: kernel 5.17.
/// - `Enum64`: kernel 6.0
///   (<https://lwn.net/Articles/893267/>).
const TOKEN_IMPLIED_BTF_FEATURE_VERSIONS: [(&str, MinKernelVersion); 9] = [
    ("btf", (4, 18, 0)),
    ("Func", (4, 20, 0)),
    ("Float", (5, 13, 0)),
    ("FuncGlobal", (5, 6, 0)),
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

/// BTF capabilities of a [`Features`] set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BtfCapabilities {
    repr: BtfRepr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum BtfRepr {
    /// Reads through to the process-wide probes, which run lazily.
    Ambient,
    Fixed(FixedBtfCapabilities),
}

impl Default for BtfRepr {
    fn default() -> Self {
        Self::Fixed(FixedBtfCapabilities::default())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct FixedBtfCapabilities {
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
    const AMBIENT: Self = Self {
        repr: BtfRepr::Ambient,
    };

    #[expect(clippy::fn_params_excessive_bools, reason = "mirrors Features::new")]
    #[expect(clippy::too_many_arguments, reason = "mirrors Features::new")]
    #[doc(hidden)]
    pub const fn new(
        func: bool,
        func_global: bool,
        datasec: bool,
        datasec_zero: bool,
        float: bool,
        decl_tag: bool,
        type_tag: bool,
        enum64: bool,
    ) -> Self {
        Self {
            repr: BtfRepr::Fixed(FixedBtfCapabilities {
                func,
                func_global,
                datasec,
                datasec_zero,
                float,
                decl_tag,
                type_tag,
                enum64,
            }),
        }
    }

    /// Returns whether the given BTF feature is supported.
    pub fn is_supported(&self, feature: BtfFeature) -> bool {
        let fixed = match &self.repr {
            BtfRepr::Ambient => {
                return FEATURES
                    .btf()
                    .is_some_and(|capabilities| capabilities.is_supported(feature));
            }
            BtfRepr::Fixed(fixed) => fixed,
        };
        let FixedBtfCapabilities {
            func,
            func_global,
            datasec,
            datasec_zero,
            float,
            decl_tag,
            type_tag,
            enum64,
        } = fixed;
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

/// Kernel BPF and BTF feature support.
///
/// A value is either the lazy process-ambient set used internally by Aya, a fixed snapshot
/// returned by [`crate::features()`], the set implied by a BPF token, or a set built by the
/// caller.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Features {
    repr: FeaturesRepr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum FeaturesRepr {
    /// Reads through to the process-wide probes, which run lazily.
    Ambient,
    Fixed(FixedFeatures),
}

impl Default for FeaturesRepr {
    fn default() -> Self {
        Self::Fixed(FixedFeatures::default())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct FixedFeatures {
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
            repr: FeaturesRepr::Fixed(FixedFeatures {
                bpf_name,
                bpf_probe_read_kernel,
                bpf_perf_link,
                bpf_global_data,
                bpf_cookie,
                cpumap_prog_id,
                devmap_prog_id,
                btf,
            }),
        }
    }

    /// Returns the process-ambient feature set.
    ///
    /// This is a handle onto [`crate::kernel_features::FEATURES`]: constructing it probes
    /// nothing, and each feature is probed at most once per process, when it is first queried.
    pub(crate) const fn ambient() -> Self {
        Self {
            repr: FeaturesRepr::Ambient,
        }
    }

    /// Returns a fixed snapshot of the process-ambient feature set.
    ///
    /// This queries every feature, and every BTF capability when BTF is supported, through the
    /// process-wide probe cache. The result reads no probe afterwards, so it keeps its values
    /// when it is cloned and used after a privilege drop or a fork.
    pub(crate) fn detect() -> Self {
        let btf = FEATURES.btf().map(|_| {
            let supported = |feature| BtfCapabilities::AMBIENT.is_supported(feature);
            BtfCapabilities::new(
                supported(BtfFeature::Func),
                supported(BtfFeature::FuncGlobal),
                supported(BtfFeature::DataSec),
                supported(BtfFeature::DataSecZero),
                supported(BtfFeature::Float),
                supported(BtfFeature::DeclTag),
                supported(BtfFeature::TypeTag),
                supported(BtfFeature::Enum64),
            )
        });
        Self::new(
            FEATURES.is_supported(Feature::BpfName),
            FEATURES.is_supported(Feature::BpfProbeReadKernel),
            FEATURES.is_supported(Feature::BpfPerfLink),
            FEATURES.is_supported(Feature::BpfGlobalData),
            FEATURES.is_supported(Feature::BpfCookie),
            FEATURES.is_supported(Feature::CpuMapProgId),
            FEATURES.is_supported(Feature::DevMapProgId),
            btf,
        )
    }

    /// Returns the features implied by BPF token support.
    ///
    /// This performs no probe syscalls. `BPF_TOKEN_CREATE` itself requires Linux 6.9
    /// (see [`MIN_TOKEN_KERNEL_VERSION`]), and every feature and BTF capability tracked here
    /// landed years earlier (see [`TOKEN_IMPLIED_FEATURE_VERSIONS`] and
    /// [`TOKEN_IMPLIED_BTF_FEATURE_VERSIONS`]), so a token's mere existence already proves the
    /// kernel supports all of them: there is nothing left to determine by probing.
    ///
    /// Probing anyway would be actively wrong under token-scoped privilege delegation, not just
    /// redundant: each probe loads a program or creates a map of some fixed, hardcoded type
    /// (for example `probe_bpf_global_data`'s program probe always uses
    /// `BPF_PROG_TYPE_SOCKET_FILTER`) chosen without regard to what the caller's token actually
    /// delegates. A token that delegates only the program and map types a real load needs can
    /// reject a probe's unrelated type with a permission error unrelated to whether the kernel
    /// supports the feature under test, which would either be misread as "unsupported"
    /// (silently dropping global-data maps and breaking relocations) or, if propagated
    /// faithfully, fail a load the token and kernel both fully support.
    ///
    /// This intentionally excludes reading the kernel's own embedded vmlinux BTF from
    /// `/sys/kernel/btf/vmlinux` (used elsewhere for [`crate::programs::ProgramInfo`]-driven
    /// CO-RE against kernel types): that depends on the build-time `CONFIG_DEBUG_INFO_BTF`
    /// option rather than kernel version and is read directly from that file.
    pub(crate) const fn implied_by_token() -> Self {
        Self {
            repr: FeaturesRepr::Fixed(FixedFeatures {
                bpf_name: true,
                bpf_probe_read_kernel: true,
                bpf_perf_link: true,
                bpf_global_data: true,
                bpf_cookie: true,
                cpumap_prog_id: true,
                devmap_prog_id: true,
                btf: Some(BtfCapabilities {
                    repr: BtfRepr::Fixed(FixedBtfCapabilities {
                        func: true,
                        func_global: true,
                        datasec: true,
                        datasec_zero: true,
                        float: true,
                        decl_tag: true,
                        type_tag: true,
                        enum64: true,
                    }),
                }),
            }),
        }
    }

    fn get(&self, feature: Feature, fixed: fn(&FixedFeatures) -> bool) -> bool {
        match &self.repr {
            FeaturesRepr::Ambient => FEATURES.is_supported(feature),
            FeaturesRepr::Fixed(features) => fixed(features),
        }
    }

    /// Returns whether BPF program names and map names are supported.
    pub fn bpf_name(&self) -> bool {
        self.get(Feature::BpfName, |f| f.bpf_name)
    }

    /// Returns whether the `bpf_probe_read_kernel` helper is supported.
    pub fn bpf_probe_read_kernel(&self) -> bool {
        self.get(Feature::BpfProbeReadKernel, |f| f.bpf_probe_read_kernel)
    }

    /// Returns whether `bpf_links` are supported for Kprobes/Uprobes/Tracepoints.
    pub fn bpf_perf_link(&self) -> bool {
        self.get(Feature::BpfPerfLink, |f| f.bpf_perf_link)
    }

    /// Returns whether BPF program global data is supported.
    pub fn bpf_global_data(&self) -> bool {
        self.get(Feature::BpfGlobalData, |f| f.bpf_global_data)
    }

    /// Returns whether BPF program cookie is supported.
    pub fn bpf_cookie(&self) -> bool {
        self.get(Feature::BpfCookie, |f| f.bpf_cookie)
    }

    /// Returns whether XDP CPU Maps support chained program IDs.
    pub fn cpumap_prog_id(&self) -> bool {
        self.get(Feature::CpuMapProgId, |f| f.cpumap_prog_id)
    }

    /// Returns whether XDP Device Maps support chained program IDs.
    pub fn devmap_prog_id(&self) -> bool {
        self.get(Feature::DevMapProgId, |f| f.devmap_prog_id)
    }

    /// If BTF is supported, returns which BTF features are supported.
    pub fn btf(&self) -> Option<&BtfCapabilities> {
        match &self.repr {
            FeaturesRepr::Ambient => FEATURES
                .btf()
                .is_some()
                .then_some(&BtfCapabilities::AMBIENT),
            FeaturesRepr::Fixed(features) => features.btf.as_ref(),
        }
    }
}

/// The fixed snapshot returned by [`crate::features()`]. Every feature is probed on first use.
pub(crate) static DETECTED: LazyLock<Features> = LazyLock::new(Features::detect);

#[cfg(test)]
mod tests {
    use aya_obj::btf::BtfFeature;

    use super::{BtfCapabilities, Features};
    use crate::sys::override_syscall;

    /// `implied_by_token` must not issue any probe syscall: `BPF_TOKEN_CREATE` requires Linux
    /// 6.9, every feature tracked here landed years before that, and probing anyway can
    /// spuriously fail (or spuriously succeed) against a token that does not delegate a given
    /// probe's own hardcoded program or map type, unrelated to whether the feature under test is
    /// actually supported. Every flag must still come back `true`.
    #[test]
    fn implied_by_token_probes_nothing_and_reports_full_support() {
        override_syscall(|call| {
            panic!("unexpected syscall during token-implied feature detection: {call:?}");
        });

        let features = Features::implied_by_token();

        assert!(features.bpf_name());
        assert!(features.bpf_probe_read_kernel());
        assert!(features.bpf_perf_link());
        assert!(features.bpf_global_data());
        assert!(features.bpf_cookie());
        assert!(features.cpumap_prog_id());
        assert!(features.devmap_prog_id());

        let btf = features.btf().expect("BTF support must be implied");
        for feature in [
            BtfFeature::Func,
            BtfFeature::FuncGlobal,
            BtfFeature::DataSec,
            BtfFeature::DataSecZero,
            BtfFeature::Float,
            BtfFeature::DeclTag,
            BtfFeature::TypeTag,
            BtfFeature::Enum64,
        ] {
            assert!(btf.is_supported(feature), "{feature:?}");
        }
    }

    /// Obtaining the ambient feature set must not probe: only the features a caller actually
    /// queries may cost a syscall.
    #[test]
    fn ambient_probes_nothing_until_queried() {
        override_syscall(|call| {
            panic!("unexpected syscall while constructing ambient features: {call:?}");
        });

        let features = Features::ambient();
        assert_eq!(features, Features::ambient());
        assert_ne!(features, Features::default());
        assert_ne!(features, Features::implied_by_token());
        assert_eq!(BtfCapabilities::default(), BtfCapabilities::default());
    }

    /// A snapshot must be fixed: once it exists, no accessor may issue a probe syscall, so a
    /// snapshot taken before a privilege drop keeps the values it had.
    #[test]
    fn snapshot_is_fixed() {
        let features = Features::new(
            true,
            false,
            true,
            false,
            true,
            false,
            true,
            Some(BtfCapabilities::new(
                true, false, true, false, true, false, true, false,
            )),
        );
        override_syscall(|call| panic!("unexpected syscall after snapshot: {call:?}"));

        assert!(features.bpf_name());
        assert!(!features.bpf_probe_read_kernel());
        assert!(features.bpf_perf_link());
        assert!(!features.bpf_global_data());
        assert!(features.bpf_cookie());
        assert!(!features.cpumap_prog_id());
        assert!(features.devmap_prog_id());
        let btf = features.btf().unwrap();
        assert!(btf.is_supported(BtfFeature::Func));
        assert!(!btf.is_supported(BtfFeature::FuncGlobal));
        assert!(btf.is_supported(BtfFeature::DataSec));
        assert!(!btf.is_supported(BtfFeature::Enum64));
    }

    #[test]
    fn default_reports_no_support() {
        let features = Features::default();
        assert!(!features.bpf_name());
        assert!(!features.bpf_cookie());
        assert!(!features.cpumap_prog_id());
        assert!(features.btf().is_none());
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
