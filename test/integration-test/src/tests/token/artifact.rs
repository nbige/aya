use anyhow::{Context as _, Result, ensure};
use aya_obj::Object;

const ELF64_HEADER_LEN: usize = 64;
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const BUILD_CONTRACT: &str = "integration BPF artifacts must be built with AYA_BUILD_INTEGRATION_BPF=true in a fresh CARGO_TARGET_DIR (or via the canonical `cargo xtask integration-test` path)";

pub(super) fn validate_pass_artifact() -> Result<()> {
    validate_object_artifact(crate::PASS)
}

fn validate_object_artifact(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() >= ELF64_HEADER_LEN,
        "{BUILD_CONTRACT}: PASS is {} bytes, shorter than an ELF64 header",
        bytes.len()
    );
    ensure!(
        bytes.starts_with(ELF_MAGIC),
        "{BUILD_CONTRACT}: PASS has invalid ELF magic"
    );
    ensure!(
        bytes.as_ptr().align_offset(8) == 0,
        "{BUILD_CONTRACT}: PASS must be 8-byte aligned"
    );
    Object::parse(bytes).with_context(|| {
        format!("{BUILD_CONTRACT}: parse embedded PASS integration BPF artifact")
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_object_artifact;

    #[repr(align(8))]
    struct Aligned<const N: usize>([u8; N]);

    fn minimal_elf() -> Aligned<64> {
        let mut bytes = [0u8; 64];
        bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        bytes[16..18].copy_from_slice(&[1, 0]);
        bytes[18..20].copy_from_slice(&[247, 0]);
        bytes[20..24].copy_from_slice(&[1, 0, 0, 0]);
        bytes[52..54].copy_from_slice(&[64, 0]);
        bytes[58..60].copy_from_slice(&[64, 0]);
        Aligned(bytes)
    }

    #[test]
    fn validator_accepts_minimal_aligned_elf() {
        validate_object_artifact(&minimal_elf().0).unwrap();
    }

    #[test]
    fn validator_rejects_empty_stub_with_build_guidance() {
        let error = validate_object_artifact(&[]).unwrap_err();
        assert!(error.to_string().contains("AYA_BUILD_INTEGRATION_BPF=true"));
    }

    #[test]
    fn validator_rejects_bad_elf_magic() {
        let bytes = Aligned([0u8; 64]);
        let error = validate_object_artifact(&bytes.0).unwrap_err();
        assert!(error.to_string().contains("ELF magic"));
    }

    #[test]
    fn validator_rejects_misaligned_elf() {
        let elf = minimal_elf();
        let mut bytes = Aligned([0u8; 65]);
        bytes.0[1..].copy_from_slice(&elf.0);
        let error = validate_object_artifact(&bytes.0[1..]).unwrap_err();
        assert!(error.to_string().contains("8-byte aligned"));
    }
}
