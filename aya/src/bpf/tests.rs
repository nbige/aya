use std::{collections::HashMap, fs::File, path::Path, sync::Arc};

use assert_matches::assert_matches;
use aya_obj::generated::bpf_prog_info;

use super::{Ebpf, EbpfError, EbpfLoader, TokenLoadingState, VerifierLogLevel};
use crate::{
    features::Features,
    programs::{Program, ProgramData, ProgramError, TracePoint},
    sys::override_syscall,
    token::BpfToken,
};

fn adopted_non_token_fd() -> BpfToken {
    BpfToken::from_owned_fd(File::open("/dev/null").unwrap().into()).unwrap()
}

const fn empty_program_info() -> bpf_prog_info {
    // SAFETY: every field in the bindgen C struct accepts the all-zero representation.
    unsafe { std::mem::zeroed() }
}

#[test]
#[cfg_attr(miri, ignore = "`open` and `fcntl` require OS file descriptors")]
fn caller_features_avoid_token_feature_probe_syscalls() {
    let token = adopted_non_token_fd();
    let supplied = Features::new(true, false, false, false, false, false, false, None);
    let mut loader = EbpfLoader::new();
    loader.token_with_features(&token, supplied).unwrap();
    override_syscall(|call| panic!("unexpected feature-probe syscall: {call:?}"));

    let (features, token_fd) = loader.selected_features();

    assert!(features.bpf_name());
    assert!(token_fd.is_some());
}

#[test]
#[cfg_attr(miri, ignore = "`open` and `fcntl` require OS file descriptors")]
fn conflicting_token_feature_selection_is_typed() {
    let token = adopted_non_token_fd();
    let mut loader = EbpfLoader::new();
    loader.token(&token).unwrap();

    let error = loader
        .token_with_features(&token, Features::default())
        .unwrap_err();

    assert_matches!(error, EbpfError::TokenFeatureSelectionConflict);
}

fn token_program(loaded: bool) -> Program {
    let token_fd = Arc::new(crate::MockableFd::from(File::open("/dev/null").unwrap()));
    let mut data = ProgramData::from_bpf_prog_info(
        None,
        crate::MockableFd::from(File::open("/dev/null").unwrap()),
        Path::new(""),
        empty_program_info(),
        VerifierLogLevel::default(),
        Some(token_fd),
        Features::default(),
    )
    .unwrap();
    if !loaded {
        data.fd = None;
    }
    Program::TracePoint(TracePoint { data })
}

fn token_ebpf(programs: impl IntoIterator<Item = (&'static str, Program)>) -> Ebpf {
    Ebpf {
        maps: HashMap::new(),
        programs: programs
            .into_iter()
            .map(|(name, program)| (name.to_owned(), program))
            .collect(),
        token_loading: TokenLoadingState::Active,
    }
}

#[test]
#[cfg_attr(miri, ignore = "`open` requires OS file descriptors")]
fn finalization_rejects_unloaded_selected_program_transactionally() {
    let mut bpf = token_ebpf([("selected", token_program(false))]);

    let error = bpf.finalize_token_loading(["selected"]).unwrap_err();

    assert_matches!(
        error,
        EbpfError::SelectedProgramNotLoaded { name } if name == "selected"
    );
    assert_matches!(bpf.token_loading, TokenLoadingState::Active);
    let Program::TracePoint(program) = bpf.program("selected").unwrap() else {
        panic!("expected tracepoint")
    };
    assert!(program.data.token_fd.is_some());
}

#[test]
#[cfg_attr(miri, ignore = "`open` requires OS file descriptors")]
fn finalization_clears_every_program_token_and_keeps_loaded_program_valid() {
    let mut bpf = token_ebpf([
        ("selected", token_program(true)),
        ("unselected", token_program(false)),
    ]);

    bpf.finalize_token_loading(["selected"]).unwrap();

    assert_matches!(bpf.token_loading, TokenLoadingState::Finalized);
    assert_matches!(bpf.program("selected").unwrap().fd(), Ok(_));
    for (_, program) in bpf.programs() {
        let Program::TracePoint(program) = program else {
            panic!("expected tracepoint")
        };
        assert!(program.data.token_fd.is_none());
        assert!(program.data.token_loading_finalized);
    }
}

#[test]
#[cfg_attr(miri, ignore = "`open` requires OS file descriptors")]
fn finalized_unselected_program_fails_before_bpf_syscall() {
    let mut bpf = token_ebpf([
        ("selected", token_program(true)),
        ("unselected", token_program(false)),
    ]);
    bpf.finalize_token_loading(["selected"]).unwrap();
    override_syscall(|call| panic!("unexpected post-finalization syscall: {call:?}"));
    let program: &mut TracePoint = bpf.program_mut("unselected").unwrap().try_into().unwrap();

    let error = program.load().unwrap_err();

    assert_matches!(error, ProgramError::TokenLoadingFinalized);
}
