//! `c2pa-x509-zk-bench pk-load`: what loading the Groth16 proving key costs
//! in each encoding, loader, and level of checking (see
//! `c2pa_x509_zk_demo::proving_key`).
//!
//! From a compressed key written by setup, the `convert` step (one process)
//! loads it with full checks and writes it back compressed and uncompressed
//! into the work directory, timing each write and hash. Each configuration is
//! then loaded in its own process, `--reps` times: the first repetition after
//! evicting the key file from the page cache (`posix_fadvise(DONTNEED)`, with
//! the residency checked through `mincore`), the others warm.

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

use c2pa_x509_zk_demo::file_sha256;
use c2pa_x509_zk_demo::proving_key::{check_file_sha256, load_proving_key_with, write_proving_key, Encoding, Loader, PointCheck};

use super::{
    check_output_location, create_workspace, environment, finish_workspace, run_measured, timed, RESULT_PREFIX,
};

/// A way of storing and loading the proving key.
#[derive(Debug, Clone, Copy)]
pub struct PkConfig {
    pub name: &'static str,
    pub encoding: Encoding,
    pub loader: Loader,
    pub check: PointCheck,
    /// Check the file's SHA-256 against the value recorded at setup before parsing it
    pub sha256: bool,
}

/// What the prover does today.
pub const CURRENT: &str = "compressed-arkworks-full";

const fn cfg(name: &'static str, encoding: Encoding, loader: Loader, check: PointCheck, sha256: bool) -> PkConfig {
    PkConfig { name, encoding, loader, check, sha256 }
}

use Encoding::{Compressed, Uncompressed};
use Loader::{Arkworks, Parallel};
use PointCheck::{Full, None as Unchecked, OnCurve};

pub const CONFIGS: &[PkConfig] = &[
    cfg("compressed-arkworks-full", Compressed, Arkworks, Full, false),
    cfg("compressed-arkworks-none", Compressed, Arkworks, Unchecked, false),
    cfg("compressed-parallel-full", Compressed, Parallel, Full, false),
    cfg("compressed-parallel-none", Compressed, Parallel, Unchecked, false),
    cfg("uncompressed-arkworks-full", Uncompressed, Arkworks, Full, false),
    cfg("uncompressed-arkworks-none", Uncompressed, Arkworks, Unchecked, false),
    cfg("uncompressed-arkworks-none-sha256", Uncompressed, Arkworks, Unchecked, true),
    cfg("uncompressed-parallel-full", Uncompressed, Parallel, Full, false),
    cfg("uncompressed-parallel-full-sha256", Uncompressed, Parallel, Full, true),
    cfg("uncompressed-parallel-on-curve", Uncompressed, Parallel, OnCurve, false),
    cfg("uncompressed-parallel-on-curve-sha256", Uncompressed, Parallel, OnCurve, true),
    cfg("uncompressed-parallel-none", Uncompressed, Parallel, Unchecked, false),
    cfg("uncompressed-parallel-none-sha256", Uncompressed, Parallel, Unchecked, true),
];

pub fn config(name: &str) -> Result<PkConfig> {
    CONFIGS.iter().copied().find(|c| c.name == name).ok_or_else(|| {
        anyhow!("unknown proving-key configuration {name}; one of: {}", CONFIGS.iter().map(|c| c.name).collect::<Vec<_>>().join(", "))
    })
}

/// Load a key per `config`, timing the hash check and the load as separate steps.
pub fn load_timed(
    config: PkConfig,
    path: &Path,
    expected_sha256: Option<&str>,
    steps: &mut serde_json::Map<String, Value>,
) -> Result<ark_groth16::ProvingKey<ark_bn254::Bn254>> {
    if config.sha256 {
        let expected = expected_sha256.ok_or_else(|| anyhow!("{} needs a recorded proving-key SHA-256", config.name))?;
        timed(steps, "check_proving_key_sha256", || check_file_sha256(path, expected))?;
    }
    timed(steps, "load_proving_key", || load_proving_key_with(path, config.encoding, config.check, config.loader))
}

fn key_file(work_dir: &Path, encoding: Encoding) -> PathBuf {
    work_dir.join(match encoding {
        Compressed => "proving_key.compressed",
        Uncompressed => "proving_key.uncompressed",
    })
}

/// Drop the file's cached pages (they are clean: the key was synced when written).
fn evict(path: &Path) -> Result<()> {
    use std::os::fd::AsRawFd;
    let file = std::fs::File::open(path)?;
    // SAFETY: plain syscall on an open descriptor.
    let rc = unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
    if rc != 0 {
        bail!("posix_fadvise failed: {rc}");
    }
    Ok(())
}

/// Fraction of the file's pages in the page cache, via mincore.
fn resident_fraction(path: &Path) -> Result<f64> {
    use std::os::fd::AsRawFd;
    let file = std::fs::File::open(path)?;
    let len = file.metadata()?.len() as usize;
    if len == 0 {
        return Ok(0.0);
    }
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    // SAFETY: a read-only private mapping of a file we opened, unmapped below;
    // mincore only reports residency into `vec`, sized for the mapping.
    unsafe {
        let addr = libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ, libc::MAP_PRIVATE, file.as_raw_fd(), 0);
        if addr == libc::MAP_FAILED {
            bail!("mmap failed: {}", std::io::Error::last_os_error());
        }
        let mut vec = vec![0u8; len.div_ceil(page)];
        let rc = libc::mincore(addr, len, vec.as_mut_ptr());
        libc::munmap(addr, len);
        if rc != 0 {
            bail!("mincore failed: {}", std::io::Error::last_os_error());
        }
        Ok(vec.iter().filter(|&&b| b & 1 == 1).count() as f64 / vec.len() as f64)
    }
}

/// One step of the benchmark, in its own process. Prints a `BENCH-RESULT` line.
pub fn pk_phase(name: &str, work_dir: &Path, key: &Path, config_name: &str, cold: bool) -> Result<()> {
    let mut steps = serde_json::Map::new();
    let mut data = serde_json::Map::new();
    match name {
        "convert" => {
            let pk = timed(&mut steps, "load_input_parallel_full", || load_proving_key_with(key, Compressed, Full, Parallel))?;
            for (label, encoding) in [("compressed", Compressed), ("uncompressed", Uncompressed)] {
                let path = key_file(work_dir, encoding);
                timed(&mut steps, &format!("write_{label}"), || write_proving_key(&pk, &path, encoding))?;
                let hash = timed(&mut steps, &format!("sha256_{label}"), || file_sha256(&path))?;
                data.insert(format!("{label}_bytes"), json!(std::fs::metadata(&path)?.len()));
                data.insert(format!("{label}_sha256"), json!(hash));
            }
            // Canonical serialization: the compressed copy should be the input, byte for byte.
            data.insert("compressed_copy_matches_input".into(), json!(file_sha256(key)? == data["compressed_sha256"]));
            data.insert("points".into(), json!({
                "g1": 2 + pk.vk.gamma_abc_g1.len() + pk.a_query.len() + pk.b_g1_query.len() + pk.h_query.len() + pk.l_query.len() + 1,
                "g2": 3 + pk.b_g2_query.len(),
                "a_query": pk.a_query.len(),
                "b_g1_query": pk.b_g1_query.len(),
                "b_g2_query": pk.b_g2_query.len(),
                "h_query": pk.h_query.len(),
                "l_query": pk.l_query.len(),
                "b_g2_query_nonzero": pk.b_g2_query.iter().filter(|p| !p.infinity).count(),
            }));
        }
        "load" => {
            let config = config(config_name)?;
            let path = key_file(work_dir, config.encoding);
            if cold {
                evict(&path)?;
            }
            data.insert("resident_before_load".into(), json!(resident_fraction(&path)?));
            let hashes: Value = serde_json::from_slice(&std::fs::read(work_dir.join("convert.json"))?)?;
            let label = match config.encoding { Compressed => "compressed", Uncompressed => "uncompressed" };
            let expected = hashes["data"][format!("{label}_sha256")].as_str().map(str::to_string);
            let pk = load_timed(config, &path, expected.as_deref(), &mut steps)?;
            data.insert("a_query".into(), json!(pk.a_query.len()));
        }
        other => bail!("unknown pk-load phase {other}"),
    }
    println!("{RESULT_PREFIX}{}", json!({ "steps": steps, "data": data }));
    Ok(())
}

/// The whole benchmark: convert, then every configuration `reps` times.
pub fn pk_load(key: &Path, work_dir: Option<PathBuf>, reps: usize, only: &[String], keep: bool, out: Option<PathBuf>) -> Result<()> {
    let zk_root = std::env::current_dir()?;
    let exe = std::env::current_exe()?;
    let key = std::fs::canonicalize(key)?;
    let configs: Vec<PkConfig> = if only.is_empty() { CONFIGS.to_vec() } else { only.iter().map(|n| config(n)).collect::<Result<_>>()? };
    if reps == 0 {
        bail!("--reps must be at least 1");
    }

    let work_dir = create_workspace(work_dir.as_deref(), &zk_root.join("target/bench"))?;
    if let Err(e) = check_output_location(out.as_deref(), &work_dir) {
        std::fs::remove_dir(&work_dir)?;
        return Err(e);
    }
    eprintln!("Work directory: {}", work_dir.display());
    let environment = environment(&zk_root);
    let phase_cmd = |name: &str| {
        let mut cmd = Command::new(&exe);
        cmd.args(["pk-phase", name, "--work-dir"]).arg(&work_dir).arg("--key").arg(&key);
        cmd
    };

    eprintln!("Converting {}...", key.display());
    let convert = run_measured(&mut phase_cmd("convert"))?;
    let convert_result = convert.result.clone().ok_or_else(|| anyhow!("convert printed no result"))?;
    std::fs::write(work_dir.join("convert.json"), serde_json::to_vec(&convert_result)?)?;

    let mut loads = Vec::new();
    for config in &configs {
        for rep in 0..reps {
            let cold = rep == 0;
            eprintln!("Load: {} ({})...", config.name, if cold { "cold" } else { "warm" });
            let mut cmd = phase_cmd("load");
            cmd.args(["--config", config.name]);
            if cold {
                cmd.arg("--cold");
            }
            let m = run_measured(&mut cmd)?;
            let result = m.result.unwrap_or(json!({}));
            eprintln!("  {:.1} s, {:.0} MiB", m.wall_s, m.peak_rss_kib as f64 / 1024.0);
            loads.push(json!({
                "config": config.name,
                "encoding": format!("{:?}", config.encoding).to_lowercase(),
                "loader": format!("{:?}", config.loader).to_lowercase(),
                "point_check": format!("{:?}", config.check).to_lowercase(),
                "sha256_checked": config.sha256,
                "cache": if cold { "cold" } else { "warm" },
                "wall_s": m.wall_s,
                "peak_rss_mib": m.peak_rss_kib as f64 / 1024.0,
                "steps": result["steps"],
                "data": result["data"],
            }));
        }
    }

    let record = json!({
        "schema": "c2pa-x509-zk-pk-load/1",
        "circuit": "x509_issue_and_possession",
        "curve": "BN254",
        "input_key": key,
        "method": "Each load runs in its own process (wall time and peak RSS from wait4). The first repetition of each \
                   configuration follows posix_fadvise(DONTNEED) on the key file (residency before the load is \
                   recorded via mincore); later repetitions are warm. Under WSL2 the Windows host may still cache the \
                   virtual disk, so 'cold' means not in the Linux page cache. point_check: full = on the curve and in \
                   the prime-order subgroup (arkworks Validate::Yes), on-curve skips G2's subgroup check, none skips \
                   both (compressed points are on the curve by construction). sha256_checked: the file's SHA-256 is \
                   compared with the value recorded when it was written, before parsing.",
        "environment": environment,
        "convert": {
            "wall_s": convert.wall_s,
            "peak_rss_mib": convert.peak_rss_kib as f64 / 1024.0,
            "steps": convert_result["steps"],
            "data": convert_result["data"],
        },
        "loads": loads,
    });

    let text = serde_json::to_string_pretty(&record)?;
    if let Err(e) = check_output_location(out.as_deref(), &work_dir) {
        println!("{text}");
        return Err(e.context(format!("record printed instead; work directory kept at {}", work_dir.display())));
    }
    match &out {
        Some(path) => std::fs::write(path, text + "\n")?,
        None => println!("{text}"),
    }
    finish_workspace(&work_dir, keep)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_names_are_unique_and_resolve() {
        for c in CONFIGS {
            assert_eq!(config(c.name).unwrap().name, c.name);
            assert_eq!(CONFIGS.iter().filter(|d| d.name == c.name).count(), 1);
        }
        assert!(config(CURRENT).is_ok());
        assert!(config("nope").is_err());
        // The arkworks loader has no on-curve-only mode.
        assert!(CONFIGS.iter().all(|c| !(matches!(c.loader, Arkworks) && matches!(c.check, OnCurve))));
    }

    #[test]
    fn eviction_and_residency() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), vec![7u8; 1 << 20]).unwrap();
        file.as_file().sync_all().unwrap();
        let _ = std::fs::read(file.path()).unwrap();
        assert!(resident_fraction(file.path()).unwrap() > 0.9);
        evict(file.path()).unwrap();
        // Eviction is advisory; on Linux clean pages of a synced file are dropped.
        assert!(resident_fraction(file.path()).unwrap() < 0.1);
    }
}
