//! Proving-key encodings and loaders, for measuring what loading the Groth16
//! proving key costs and which checks that cost buys (see FEASIBILITY.md).
//!
//! The prover itself still uses `circuit_native::load_proving_key`
//! (compressed, fully validated by arkworks). This module adds:
//!
//! - writing the key compressed or uncompressed;
//! - loading it with arkworks (sequential decoding, then a parallel check) or
//!   with a parallel loader that decodes and checks each point vector across
//!   all cores, producing the same key;
//! - a choice of point checks: full (on the curve and in the prime-order
//!   subgroup, which is what arkworks' `Validate::Yes` does), on the curve
//!   only, or none;
//! - checking the key file's SHA-256 against a recorded value before parsing.
//!
//! What the checks cover: BN254's G1 has cofactor 1, so a G1 point on the
//! curve is in the subgroup; G2 points additionally need a subgroup check (a
//! scalar multiplication each). A compressed point is decoded by solving the
//! curve equation, so it is always on the curve, but not necessarily in G2's
//! subgroup. An uncompressed point is taken as written unless checked.

use anyhow::{anyhow, bail, Context, Result};
use ark_bn254::Bn254;
use ark_ec::AffineRepr;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Valid, Validate};
use rayon::prelude::*;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

/// How the key's curve points are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// x coordinate and a sign bit (32 bytes per G1 point, 64 per G2 point)
    Compressed,
    /// Both coordinates (64 bytes per G1 point, 128 per G2 point)
    Uncompressed,
}

impl Encoding {
    fn compress(self) -> Compress {
        match self {
            Encoding::Compressed => Compress::Yes,
            Encoding::Uncompressed => Compress::No,
        }
    }
}

/// Which checks are applied to each decoded point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointCheck {
    /// On the curve and in the prime-order subgroup (arkworks `Validate::Yes`)
    Full,
    /// On the curve only: skips G2's subgroup check
    OnCurve,
    /// No checks (arkworks `Validate::No`)
    None,
}

/// Which code decodes the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Loader {
    /// `ProvingKey::deserialize_with_mode`: points decoded one by one, then
    /// checked in parallel. Supports `PointCheck::Full` and `None` only.
    Arkworks,
    /// Each point vector read in one block, then decoded and checked in
    /// parallel with the same arkworks point codec.
    Parallel,
}

/// Write the proving key in the given encoding, flushed to disk.
pub fn write_proving_key(pk: &ProvingKey<Bn254>, path: &Path, encoding: Encoding) -> Result<()> {
    let file = std::fs::File::create(path).with_context(|| format!("failed to create {path:?}"))?;
    let mut writer = BufWriter::new(file);
    pk.serialize_with_mode(&mut writer, encoding.compress())
        .map_err(|e| anyhow!("failed to serialize proving key: {e}"))?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(())
}

/// Refuse a key file whose SHA-256 differs from `expected` (hex), before any
/// of it is parsed.
pub fn check_file_sha256(path: &Path, expected: &str) -> Result<()> {
    let actual = crate::circuit_native::file_sha256(path)?;
    if !actual.eq_ignore_ascii_case(expected) {
        bail!("proving key {path:?} has SHA-256 {actual}, expected {expected}");
    }
    Ok(())
}

/// Load a proving key written in `encoding`, applying `check` to every point.
pub fn load_proving_key_with(path: &Path, encoding: Encoding, check: PointCheck, loader: Loader) -> Result<ProvingKey<Bn254>> {
    let file = std::fs::File::open(path).with_context(|| format!("failed to open proving key {path:?}"))?;
    let file_len = file.metadata()?.len();
    let mut reader = BufReader::with_capacity(1 << 20, file);
    let pk = match loader {
        Loader::Arkworks => {
            let validate = match check {
                PointCheck::Full => Validate::Yes,
                PointCheck::None => Validate::No,
                PointCheck::OnCurve => bail!("the arkworks loader has no on-curve-only check"),
            };
            ProvingKey::deserialize_with_mode(&mut reader, encoding.compress(), validate)
                .map_err(|e| anyhow!("failed to deserialize proving key: {e}"))?
        }
        Loader::Parallel => load_parallel(&mut reader, file_len, encoding.compress(), check)?,
    };
    // Trailing bytes mean the file is not (only) a proving key.
    let mut rest = [0u8; 1];
    if reader.read(&mut rest)? != 0 {
        bail!("proving key {path:?} has trailing data");
    }
    Ok(pk)
}

/// Field order of the derived `CanonicalSerialize` for `ProvingKey` and
/// `VerifyingKey` (ark-groth16 0.5); each `Vec` is a u64 length followed by
/// its elements. Tests compare the result with arkworks' own loader.
fn load_parallel<R: Read>(reader: &mut R, file_len: u64, compress: Compress, check: PointCheck) -> Result<ProvingKey<Bn254>> {
    let vk = VerifyingKey {
        alpha_g1: read_point(reader, compress, check)?,
        beta_g2: read_point(reader, compress, check)?,
        gamma_g2: read_point(reader, compress, check)?,
        delta_g2: read_point(reader, compress, check)?,
        gamma_abc_g1: read_points(reader, file_len, compress, check)?,
    };
    Ok(ProvingKey {
        vk,
        beta_g1: read_point(reader, compress, check)?,
        delta_g1: read_point(reader, compress, check)?,
        a_query: read_points(reader, file_len, compress, check)?,
        b_g1_query: read_points(reader, file_len, compress, check)?,
        b_g2_query: read_points(reader, file_len, compress, check)?,
        h_query: read_points(reader, file_len, compress, check)?,
        l_query: read_points(reader, file_len, compress, check)?,
    })
}

/// A point type with an on-curve test (`Valid::check` is the full test).
trait CheckedPoint: AffineRepr + CanonicalDeserialize + Valid + Send + Sync {
    fn is_on_curve(&self) -> bool;
}

impl<P: ark_ec::short_weierstrass::SWCurveConfig> CheckedPoint for ark_ec::short_weierstrass::Affine<P> {
    fn is_on_curve(&self) -> bool {
        ark_ec::short_weierstrass::Affine::is_on_curve(self)
    }
}

fn check_point<P: CheckedPoint>(point: &P, check: PointCheck) -> Result<()> {
    let ok = match check {
        PointCheck::Full => point.check().is_ok(),
        PointCheck::OnCurve => point.is_on_curve(),
        PointCheck::None => true,
    };
    if !ok {
        bail!("proving key contains an invalid curve point");
    }
    Ok(())
}

fn read_point<P: CheckedPoint, R: Read>(reader: &mut R, compress: Compress, check: PointCheck) -> Result<P> {
    let point = P::deserialize_with_mode(reader, compress, Validate::No)
        .map_err(|e| anyhow!("failed to deserialize proving key point: {e}"))?;
    check_point(&point, check)?;
    Ok(point)
}

fn read_points<P: CheckedPoint, R: Read>(reader: &mut R, file_len: u64, compress: Compress, check: PointCheck) -> Result<Vec<P>> {
    let len = u64::deserialize_with_mode(&mut *reader, compress, Validate::No)
        .map_err(|e| anyhow!("failed to read a vector length: {e}"))?;
    let size = P::zero().serialized_size(compress);
    // Refuse a length the file cannot hold before allocating for it.
    let bytes = len.checked_mul(size as u64).filter(|&b| b <= file_len)
        .ok_or_else(|| anyhow!("proving key vector length {len} exceeds the file"))?;
    let mut buf = vec![0u8; bytes as usize];
    reader.read_exact(&mut buf).context("proving key is truncated")?;
    buf.par_chunks_exact(size)
        .map(|chunk| {
            let point = P::deserialize_with_mode(chunk, compress, Validate::No)
                .map_err(|e| anyhow!("failed to deserialize proving key point: {e}"))?;
            check_point(&point, check)?;
            Ok(point)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fq2, Fr, G1Affine, G2Affine};
    use ark_ff::UniformRand;
    use ark_groth16::Groth16;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable};
    use ark_snark::SNARK;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    /// x * y = z with z public, padded with `extra` copies to give the key
    /// vectors several entries each.
    struct Product {
        extra: usize,
    }

    impl ConstraintSynthesizer<Fr> for Product {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            for i in 0..=self.extra {
                let (x, y) = (Fr::from(3u64 + i as u64), Fr::from(5u64));
                let a = cs.new_witness_variable(|| Ok(x))?;
                let b = cs.new_witness_variable(|| Ok(y))?;
                let c = cs.new_input_variable(|| Ok(x * y))?;
                cs.enforce_constraint(LinearCombination::from(a), LinearCombination::from(b), LinearCombination::from(c))?;
                cs.enforce_constraint(LinearCombination::from(a) + b, LinearCombination::from(Variable::One), LinearCombination::from(a) + b)?;
            }
            Ok(())
        }
    }

    fn test_key() -> ProvingKey<Bn254> {
        let mut rng = StdRng::seed_from_u64(1);
        Groth16::<Bn254>::circuit_specific_setup(Product { extra: 3 }, &mut rng).unwrap().0
    }

    /// An on-curve G2 point outside the prime-order subgroup.
    fn g2_outside_subgroup() -> G2Affine {
        let mut rng = StdRng::seed_from_u64(2);
        loop {
            if let Some(p) = G2Affine::get_point_from_x_unchecked(Fq2::rand(&mut rng), true) {
                if !p.is_in_correct_subgroup_assuming_on_curve() {
                    return p;
                }
            }
        }
    }

    fn write(pk: &ProvingKey<Bn254>, encoding: Encoding) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        write_proving_key(pk, file.path(), encoding).unwrap();
        file
    }

    const ALL: [(Loader, PointCheck); 5] = [
        (Loader::Arkworks, PointCheck::Full),
        (Loader::Arkworks, PointCheck::None),
        (Loader::Parallel, PointCheck::Full),
        (Loader::Parallel, PointCheck::OnCurve),
        (Loader::Parallel, PointCheck::None),
    ];

    #[test]
    fn every_loader_reads_back_the_same_key() {
        let pk = test_key();
        assert!(pk.b_g2_query.len() > 4 && pk.l_query.len() > 4);
        for encoding in [Encoding::Compressed, Encoding::Uncompressed] {
            let file = write(&pk, encoding);
            for (loader, check) in ALL {
                let loaded = load_proving_key_with(file.path(), encoding, check, loader).unwrap();
                assert!(loaded == pk, "{encoding:?} {loader:?} {check:?}");
            }
        }
    }

    #[test]
    fn uncompressed_is_about_twice_the_size() {
        let pk = test_key();
        let compressed = std::fs::metadata(write(&pk, Encoding::Compressed).path()).unwrap().len();
        let uncompressed = std::fs::metadata(write(&pk, Encoding::Uncompressed).path()).unwrap().len();
        assert!(uncompressed > compressed * 19 / 10 && uncompressed < compressed * 2 + 64, "{compressed} {uncompressed}");
    }

    #[test]
    fn off_curve_point_is_rejected_unless_unchecked() {
        let mut pk = test_key();
        let p = pk.a_query[1];
        pk.a_query[1] = G1Affine::new_unchecked(p.x, p.y + ark_bn254::Fq::from(1u64));
        let file = write(&pk, Encoding::Uncompressed);
        for (loader, check) in ALL {
            let result = load_proving_key_with(file.path(), Encoding::Uncompressed, check, loader);
            assert_eq!(result.is_ok(), check == PointCheck::None, "{loader:?} {check:?}");
        }
    }

    #[test]
    fn g2_point_outside_the_subgroup_needs_the_full_check() {
        let mut pk = test_key();
        pk.b_g2_query[2] = g2_outside_subgroup();
        for encoding in [Encoding::Compressed, Encoding::Uncompressed] {
            let file = write(&pk, encoding);
            for (loader, check) in ALL {
                let result = load_proving_key_with(file.path(), encoding, check, loader);
                assert_eq!(result.is_ok(), check != PointCheck::Full, "{encoding:?} {loader:?} {check:?}");
            }
        }
    }

    #[test]
    fn oversized_length_and_truncation_and_trailing_data_are_rejected() {
        let pk = test_key();
        let file = write(&pk, Encoding::Uncompressed);
        let bytes = std::fs::read(file.path()).unwrap();

        // The vk's gamma_abc_g1 length follows alpha_g1 (64 bytes) and three G2 points (128 each).
        let mut huge = bytes.clone();
        huge[64 + 3 * 128..64 + 3 * 128 + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        let truncated = &bytes[..bytes.len() - 10];
        let mut trailing = bytes.clone();
        trailing.push(0);
        for (name, contents) in [("huge", huge.as_slice()), ("truncated", truncated), ("trailing", trailing.as_slice())] {
            let tampered = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(tampered.path(), contents).unwrap();
            assert!(load_proving_key_with(tampered.path(), Encoding::Uncompressed, PointCheck::None, Loader::Parallel).is_err(), "{name}");
        }
    }

    #[test]
    fn build_manifests_without_a_proving_key_hash_still_parse() {
        let old = r#"{"circuit":"c","r1cs_sha256":"aa","verifying_key_sha256":"bb"}"#;
        let manifest: crate::circuit_native::BuildManifest = serde_json::from_str(old).unwrap();
        assert_eq!(manifest.proving_key_sha256, None);
        assert_eq!(serde_json::to_string(&manifest).unwrap(), old);
    }

    #[test]
    fn hash_check_detects_any_change() {
        let pk = test_key();
        let file = write(&pk, Encoding::Uncompressed);
        let hash = crate::circuit_native::file_sha256(file.path()).unwrap();
        check_file_sha256(file.path(), &hash).unwrap();

        // A different but well-formed key passes every point check, not the hash.
        let other = write(&Groth16::<Bn254>::circuit_specific_setup(Product { extra: 3 }, &mut StdRng::seed_from_u64(9)).unwrap().0, Encoding::Uncompressed);
        load_proving_key_with(other.path(), Encoding::Uncompressed, PointCheck::Full, Loader::Parallel).unwrap();
        assert!(check_file_sha256(other.path(), &hash).is_err());
    }
}
