mod artifact;
mod catalog;
mod harness;
#[cfg(test)]
mod harness_tests;

use std::{
    convert::TryInto as _,
    os::fd::{AsFd as _, AsRawFd as _},
};

use anyhow::{Context as _, Result};
use aya::{
    maps::MapData,
    programs::Xdp,
    token::{BpfFilesystemContext, BpfToken, FilesystemPermissionsBuilder},
};
use aya_obj::{cmd::BpfCommand, maps::BpfMapType};

use self::{
    artifact::validate_pass_artifact,
    catalog::{BTF_OBJECT, TOKEN_FEATURE_DETECTION, XDP_OBJECT, load_pass_with_parent_features},
    harness::{CapabilityProfile, require_kernel_6_9, run_in_token_userns},
};

#[test_log::test]
fn token_create_nonexistent_path() {
    let result = BpfToken::create("/nonexistent/bpffs/path");
    assert!(result.is_err(), "nonexistent bpffs path must fail");
}

#[test_log::test]
fn token_create_non_bpffs() {
    let result = BpfToken::create("/tmp");
    assert!(result.is_err(), "regular directory must not create a token");
}

#[test_log::test]
#[ignore = "requires Linux >= 6.9, initial-userns CAP_SYS_ADMIN, and BPF token support"]
fn token_create_in_initial_userns_returns_eopnotsupp() {
    require_kernel_6_9().expect("qualified BPF token kernel");
    let context = BpfFilesystemContext::create().expect("create init-userns bpffs context");
    let mount = context
        .materialize(
            FilesystemPermissionsBuilder::default()
                .allow_cmd(BpfCommand::MapCreate)
                .build(),
        )
        .expect("materialize init-userns bpffs");
    let bpffs = mount.open().expect("open init-userns bpffs");
    let Err(error) = BpfToken::create_from_bpffs(&bpffs) else {
        panic!("init_user_ns token creation unexpectedly succeeded");
    };
    assert_eq!(error.raw_os_error(), Some(libc::EOPNOTSUPP));
}

#[test_log::test]
#[ignore = "requires Linux >= 6.9, initial-userns CAP_SYS_ADMIN, user namespaces, and BPF token support"]
fn token_map_create_in_owning_userns() {
    let permissions = FilesystemPermissionsBuilder::default()
        .allow_cmd(BpfCommand::MapCreate)
        .allow_map_type(BpfMapType::Array)
        .build();
    run_in_token_userns(permissions, CapabilityProfile::Token, |_bpffs, token| {
        let map = MapData::create(
            aya_obj::Map::Legacy(aya_obj::maps::LegacyMap {
                def: aya_obj::maps::bpf_map_def {
                    map_type: aya_obj::generated::bpf_map_type::BPF_MAP_TYPE_ARRAY as u32,
                    key_size: 4,
                    value_size: 4,
                    max_entries: 1,
                    ..Default::default()
                },
                section_index: 0,
                section_kind: aya_obj::EbpfSectionKind::Maps,
                symbol_index: None,
                data: Vec::new(),
                inner_def: None,
            }),
            "aya_token_map",
            None,
            Some(token.as_fd()),
            Default::default(),
        )?;
        assert!(map.fd().as_fd().as_raw_fd() >= 0);
        Ok(())
    });
}

#[test_log::test]
#[ignore = "requires Linux >= 6.9, initial-userns CAP_SYS_ADMIN, user namespaces, AYA_BUILD_INTEGRATION_BPF=true with a fresh CARGO_TARGET_DIR, and BPF token support"]
fn token_btf_load_in_owning_userns() {
    validate_pass_artifact().expect("valid PASS integration BPF artifact");
    let features = (*aya::features()).clone();
    run_in_token_userns(
        BTF_OBJECT.permissions(),
        BTF_OBJECT.capabilities,
        move |_bpffs, token| {
            load_pass_with_parent_features(token, features)
                .context("load object BTF with delegated token")?;
            Ok(())
        },
    );
}

#[test_log::test]
#[ignore = "requires Linux >= 6.9, initial-userns CAP_SYS_ADMIN, user namespaces, AYA_BUILD_INTEGRATION_BPF=true with a fresh CARGO_TARGET_DIR, and BPF token support"]
fn token_prog_load_in_owning_userns() {
    validate_pass_artifact().expect("valid PASS integration BPF artifact");
    let features = (*aya::features()).clone();
    run_in_token_userns(
        XDP_OBJECT.permissions(),
        XDP_OBJECT.capabilities,
        move |_bpffs, token| {
            let mut bpf = load_pass_with_parent_features(token, features)?;
            let program: &mut Xdp = bpf
                .program_mut("pass")
                .context("missing pass program")?
                .try_into()?;
            program.load()?;
            Ok(())
        },
    );
}

#[test_log::test]
#[ignore = "requires Linux >= 6.9, initial-userns CAP_SYS_ADMIN, user namespaces, and BPF token support"]
fn token_feature_detection_in_owning_userns() {
    // The asserted bpf_name probe loads a TracePoint program. TracePoint leaves
    // expected_attach_type unset, so the kernel checks attach-mask bit zero.
    run_in_token_userns(
        TOKEN_FEATURE_DETECTION.permissions(),
        TOKEN_FEATURE_DETECTION.capabilities,
        |_bpffs, token| {
            let features = aya::sys::detect_features_with_token(token.as_fd());
            assert!(features.bpf_name());
            Ok(())
        },
    );
}

#[test_log::test]
#[ignore = "requires Linux >= 6.9, initial-userns CAP_SYS_ADMIN, user namespaces, and BPF token support"]
fn token_direct_create_in_owning_userns() {
    let permissions = FilesystemPermissionsBuilder::default()
        .allow_cmd(BpfCommand::MapCreate)
        .build();
    run_in_token_userns(permissions, CapabilityProfile::Token, |_bpffs, token| {
        assert!(token.as_fd().as_raw_fd() >= 0);
        Ok(())
    });
}

#[test_log::test]
#[ignore = "requires Linux >= 6.9, initial-userns CAP_SYS_ADMIN, user namespaces, and BPF token support"]
fn token_detached_bpffs_open_in_owning_userns() {
    let permissions = FilesystemPermissionsBuilder::default()
        .allow_cmd(BpfCommand::MapCreate)
        .build();
    run_in_token_userns(permissions, CapabilityProfile::Token, |bpffs, _token| {
        assert!(bpffs.as_fd().as_raw_fd() >= 0);
        Ok(())
    });
}

#[test_log::test]
#[ignore = "requires Linux >= 6.9, initial-userns CAP_SYS_ADMIN, user namespaces, AYA_BUILD_INTEGRATION_BPF=true with a fresh CARGO_TARGET_DIR, and BPF token support"]
fn token_multiple_from_same_bpffs_in_owning_userns() {
    validate_pass_artifact().expect("valid PASS integration BPF artifact");
    let features = (*aya::features()).clone();
    run_in_token_userns(
        BTF_OBJECT.permissions(),
        BTF_OBJECT.capabilities,
        move |bpffs, first| {
            let second = BpfToken::create_from_bpffs(bpffs)?;
            assert_ne!(first.as_fd().as_raw_fd(), second.as_fd().as_raw_fd());
            load_pass_with_parent_features(first, features.clone())?;
            load_pass_with_parent_features(&second, features)?;
            Ok(())
        },
    );
}

#[test_log::test]
#[ignore = "requires Linux >= 6.9, initial-userns CAP_SYS_ADMIN, user namespaces, AYA_BUILD_INTEGRATION_BPF=true with a fresh CARGO_TARGET_DIR, and BPF token support"]
fn token_full_delegation_in_owning_userns() {
    validate_pass_artifact().expect("valid PASS integration BPF artifact");
    let features = (*aya::features()).clone();
    run_in_token_userns(
        BTF_OBJECT.permissions(),
        BTF_OBJECT.capabilities,
        move |_bpffs, token| {
            load_pass_with_parent_features(token, features)?;
            Ok(())
        },
    );
}

#[test_log::test]
#[ignore = "requires Linux >= 6.9, initial-userns CAP_SYS_ADMIN, user namespaces, and BPF token support"]
fn token_bpffs_uid_gid_in_owning_userns() {
    let permissions = FilesystemPermissionsBuilder::default()
        .allow_cmd(BpfCommand::MapCreate)
        .uid(0)
        .gid(0)
        .build();
    run_in_token_userns(
        permissions,
        CapabilityProfile::Token,
        |_bpffs, token| -> Result<()> {
            assert!(token.as_fd().as_raw_fd() >= 0);
            Ok(())
        },
    );
}
