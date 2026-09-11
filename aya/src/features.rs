//! A snapshot of kernel feature support.
//!
//! Most callers use the process-ambient snapshot ([`Features::ambient`]), which is derived from
//! [`crate::kernel_features::FEATURES`] and therefore benefits from its per-feature caching.
//! Loading through a BPF token instead probes with that token's privilege delegation
//! ([`Features::detect_with_token`]); because a token's capabilities are fixed for its lifetime,
//! the snapshot is computed once per load and reused for every map and program it creates.

use std::{os::fd::BorrowedFd, sync::LazyLock};

use aya_obj::btf::BtfFeature;

use crate::{
    kernel_features::{FEATURES, Feature},
    programs::ProgramType,
    sys::{
        BpfHelper, is_bpf_global_data_supported_inner, is_bpf_name_supported_inner,
        is_btf_feature_supported_inner, is_btf_supported_inner, is_cpumap_prog_id_supported_inner,
        is_devmap_prog_id_supported_inner, is_helper_supported_inner, is_perf_link_supported_inner,
    },
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

    /// Probes BPF and BTF features using the given BPF token for privilege delegation.
    ///
    /// Unlike the ambient set, this always performs a fresh probe: the token's capabilities are
    /// not known ahead of time and are not shared with the process-ambient cache. Callers that
    /// load multiple items with the same token should probe once and reuse the result.
    pub(crate) fn detect_with_token(token_fd: BorrowedFd<'_>) -> Self {
        let token_fd = Some(token_fd);
        let btf = is_btf_supported_inner(token_fd)
            .unwrap_or(false)
            .then(|| BtfCapabilities {
                func: is_btf_feature_supported_inner(BtfFeature::Func, token_fd),
                func_global: is_btf_feature_supported_inner(BtfFeature::FuncGlobal, token_fd),
                datasec: is_btf_feature_supported_inner(BtfFeature::DataSec, token_fd),
                datasec_zero: is_btf_feature_supported_inner(BtfFeature::DataSecZero, token_fd),
                float: is_btf_feature_supported_inner(BtfFeature::Float, token_fd),
                decl_tag: is_btf_feature_supported_inner(BtfFeature::DeclTag, token_fd),
                type_tag: is_btf_feature_supported_inner(BtfFeature::TypeTag, token_fd),
                enum64: is_btf_feature_supported_inner(BtfFeature::Enum64, token_fd),
            });
        Self {
            bpf_name: is_bpf_name_supported_inner(token_fd).unwrap_or(false),
            bpf_probe_read_kernel: matches!(
                is_helper_supported_inner(
                    ProgramType::TracePoint,
                    BpfHelper::BPF_FUNC_probe_read_kernel,
                    token_fd,
                ),
                Ok(true)
            ),
            bpf_perf_link: is_perf_link_supported_inner(token_fd).unwrap_or(false),
            bpf_global_data: is_bpf_global_data_supported_inner(token_fd).unwrap_or(false),
            bpf_cookie: matches!(
                is_helper_supported_inner(
                    ProgramType::KProbe,
                    BpfHelper::BPF_FUNC_get_attach_cookie,
                    token_fd,
                ),
                Ok(true)
            ),
            cpumap_prog_id: is_cpumap_prog_id_supported_inner(token_fd).unwrap_or(false),
            devmap_prog_id: is_devmap_prog_id_supported_inner(token_fd).unwrap_or(false),
            btf,
        }
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
