use anyhow::{Context as _, Result};
use aya::{
    Ebpf, EbpfLoader,
    features::Features,
    token::{BpfToken, FilesystemPermissions, FilesystemPermissionsBuilder},
};
use aya_obj::{attach::BpfAttachType, cmd::BpfCommand, programs::BpfProgType};

use super::harness::CapabilityProfile;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandPermission {
    BtfLoad,
    ProgLoad,
}

impl CommandPermission {
    fn allow(self, builder: FilesystemPermissionsBuilder) -> FilesystemPermissionsBuilder {
        builder.allow_cmd(match self {
            Self::BtfLoad => BpfCommand::BtfLoad,
            Self::ProgLoad => BpfCommand::ProgLoad,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProgramPermission {
    Xdp,
    Tracepoint,
}

impl ProgramPermission {
    fn allow(self, builder: FilesystemPermissionsBuilder) -> FilesystemPermissionsBuilder {
        builder.allow_prog_type(match self {
            Self::Xdp => BpfProgType::Xdp,
            Self::Tracepoint => BpfProgType::Tracepoint,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttachPermission {
    Xdp,
    BitZero,
}

impl AttachPermission {
    fn allow(self, builder: FilesystemPermissionsBuilder) -> FilesystemPermissionsBuilder {
        builder.allow_attach_type(match self {
            Self::Xdp => BpfAttachType::Xdp,
            Self::BitZero => BpfAttachType::CgroupInetIngress,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DelegationContract {
    commands: &'static [CommandPermission],
    program_types: &'static [ProgramPermission],
    attach_types: &'static [AttachPermission],
    pub(super) capabilities: CapabilityProfile,
}

impl DelegationContract {
    pub(super) fn permissions(self) -> FilesystemPermissions {
        let builder = self.commands.iter().copied().fold(
            FilesystemPermissionsBuilder::default(),
            |builder, command| command.allow(builder),
        );
        let builder = self
            .program_types
            .iter()
            .copied()
            .fold(builder, |builder, program_type| program_type.allow(builder));
        self.attach_types
            .iter()
            .copied()
            .fold(builder, |builder, attach_type| attach_type.allow(builder))
            .build()
    }
}

pub(super) const BTF_OBJECT: DelegationContract = DelegationContract {
    commands: &[CommandPermission::BtfLoad],
    program_types: &[],
    attach_types: &[],
    capabilities: CapabilityProfile::Token,
};

pub(super) const XDP_OBJECT: DelegationContract = DelegationContract {
    commands: &[CommandPermission::BtfLoad, CommandPermission::ProgLoad],
    program_types: &[ProgramPermission::Xdp],
    attach_types: &[AttachPermission::Xdp],
    capabilities: CapabilityProfile::XdpLoad,
};

pub(super) const TOKEN_FEATURE_DETECTION: DelegationContract = DelegationContract {
    commands: &[CommandPermission::ProgLoad],
    program_types: &[ProgramPermission::Tracepoint],
    attach_types: &[AttachPermission::BitZero],
    capabilities: CapabilityProfile::TracePointLoad,
};

pub(super) fn load_pass_with_parent_features(token: &BpfToken, features: Features) -> Result<Ebpf> {
    EbpfLoader::new()
        .token_with_features(token, features)?
        .load(crate::PASS)
        .context("load PASS with parent-detected features")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_object_loader_delegation_contracts_remain_exact() {
        assert_eq!(BTF_OBJECT.commands, &[CommandPermission::BtfLoad]);
        assert!(BTF_OBJECT.program_types.is_empty());
        assert!(BTF_OBJECT.attach_types.is_empty());
        assert_eq!(BTF_OBJECT.capabilities, CapabilityProfile::Token);
        assert_eq!(
            XDP_OBJECT.commands,
            &[CommandPermission::BtfLoad, CommandPermission::ProgLoad]
        );
        assert_eq!(XDP_OBJECT.program_types, &[ProgramPermission::Xdp]);
        assert_eq!(XDP_OBJECT.attach_types, &[AttachPermission::Xdp]);
        assert_eq!(XDP_OBJECT.capabilities, CapabilityProfile::XdpLoad);
    }

    #[test]
    fn token_feature_detection_contract_remains_isolated() {
        assert_eq!(
            TOKEN_FEATURE_DETECTION.commands,
            &[CommandPermission::ProgLoad]
        );
        assert_eq!(
            TOKEN_FEATURE_DETECTION.program_types,
            &[ProgramPermission::Tracepoint]
        );
        assert_eq!(
            TOKEN_FEATURE_DETECTION.attach_types,
            &[AttachPermission::BitZero]
        );
        assert_eq!(
            TOKEN_FEATURE_DETECTION.capabilities,
            CapabilityProfile::TracePointLoad
        );
    }
}
