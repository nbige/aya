use std::{fmt, fs};

use anyhow::{Context as _, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Capability {
    Bpf,
    Perfmon,
    NetAdmin,
}

impl Capability {
    const fn mask(self) -> u64 {
        match self {
            Self::Bpf => 1u64 << 39,
            Self::Perfmon => 1u64 << 38,
            Self::NetAdmin => 1u64 << 12,
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Bpf => "CAP_BPF",
            Self::Perfmon => "CAP_PERFMON",
            Self::NetAdmin => "CAP_NET_ADMIN",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapabilityProfile {
    Token,
    TracePointLoad,
    XdpLoad,
}

impl CapabilityProfile {
    const fn capabilities(self) -> &'static [Capability] {
        match self {
            Self::Token => &[Capability::Bpf],
            Self::TracePointLoad => &[Capability::Bpf, Capability::Perfmon],
            Self::XdpLoad => &[Capability::Bpf, Capability::NetAdmin],
        }
    }

    pub(crate) const fn required_mask(self) -> u64 {
        let capabilities = self.capabilities();
        let mut index = 0;
        let mut mask = 0;
        while index < capabilities.len() {
            mask |= capabilities[index].mask();
            index += 1;
        }
        mask
    }
}

#[derive(Debug)]
pub(crate) struct MissingCapabilities {
    profile: CapabilityProfile,
    effective: u64,
}

impl MissingCapabilities {
    pub(crate) const fn new(profile: CapabilityProfile, effective: u64) -> Self {
        Self { profile, effective }
    }
}

impl fmt::Display for MissingCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("child user namespace missing required effective capabilities: ")?;
        let mut separator = "";
        for capability in self.profile.capabilities() {
            if self.effective & capability.mask() == 0 {
                write!(f, "{separator}{capability}")?;
                separator = ", ";
            }
        }
        Ok(())
    }
}

impl std::error::Error for MissingCapabilities {}

pub(crate) fn parse_effective_capabilities(status: &str) -> Result<u64> {
    let hexadecimal = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .context("/proc/self/status is missing CapEff")?
        .trim();
    u64::from_str_radix(hexadecimal, 16).context("parse CapEff from /proc/self/status")
}

pub(super) fn require_effective_capabilities(profile: CapabilityProfile) -> Result<()> {
    let status = fs::read_to_string("/proc/self/status").context("read child process status")?;
    let effective = parse_effective_capabilities(&status)?;
    if effective & profile.required_mask() != profile.required_mask() {
        return Err(MissingCapabilities::new(profile, effective).into());
    }
    Ok(())
}
