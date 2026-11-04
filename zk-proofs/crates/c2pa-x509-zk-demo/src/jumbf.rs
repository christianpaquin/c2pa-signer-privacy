//! Minimal JUMBF reading for the active manifest (roadmap E2b).
//!
//! Third-party anonymization needs the active manifest's exact bytes: the
//! claim (the payload the original signature covers) and the claim
//! signature's `COSE_Sign1`, with its position in the manifest store so it can
//! later be replaced in place at the same size. c2pa's `Reader` exposes
//! neither, so this walks the JUMBF boxes directly (ISO 19566-5; C2PA §11.5).

use anyhow::{anyhow, bail, Result};
use std::ops::Range;
use std::path::Path;

/// The parts of the active manifest that the original signature covers.
#[derive(Debug, Clone)]
pub struct ActiveManifest {
    /// The manifest's label (`urn:c2pa:...`).
    pub label: String,
    /// The claim box's label (`c2pa.claim.v2` or `c2pa.claim`).
    pub claim_label: String,
    /// The claim box's CBOR content: the detached payload of the signature.
    pub claim: Vec<u8>,
    /// The claim signature box's CBOR content: a tagged `COSE_Sign1`.
    pub cose_sign1: Vec<u8>,
    /// Where `cose_sign1` lies in the manifest store.
    pub cose_sign1_range: Range<usize>,
}

/// One box: type, content range within the buffer, and total range.
struct JBox {
    kind: [u8; 4],
    content: Range<usize>,
}

fn boxes(buf: &[u8], range: Range<usize>) -> Result<Vec<JBox>> {
    let mut out = Vec::new();
    let mut i = range.start;
    while i < range.end {
        if i + 8 > range.end {
            bail!("truncated JUMBF box header at {i}");
        }
        let lbox = u32::from_be_bytes(buf[i..i + 4].try_into()?) as usize;
        let kind: [u8; 4] = buf[i + 4..i + 8].try_into()?;
        let (header, len) = match lbox {
            0 => (8, range.end - i),
            1 => {
                if i + 16 > range.end {
                    bail!("truncated extended JUMBF box header at {i}");
                }
                (16, u64::from_be_bytes(buf[i + 8..i + 16].try_into()?) as usize)
            }
            n => (8, n),
        };
        if len < header || i + len > range.end {
            bail!("JUMBF box at {i} has invalid length {len}");
        }
        out.push(JBox { kind, content: i + header..i + len });
        i += len;
    }
    Ok(out)
}

/// A superbox's label and its child boxes (after the description box).
fn superbox(buf: &[u8], content: Range<usize>) -> Result<(String, Vec<JBox>)> {
    let mut children = boxes(buf, content)?.into_iter();
    let desc = children.next().filter(|b| &b.kind == b"jumd").ok_or_else(|| anyhow!("superbox without a description box"))?;
    let d = &buf[desc.content];
    if d.len() < 17 {
        bail!("short JUMBF description box");
    }
    let toggles = d[16];
    let label = if toggles & 0x02 != 0 {
        let rest = &d[17..];
        let end = rest.iter().position(|&b| b == 0).ok_or_else(|| anyhow!("unterminated JUMBF label"))?;
        String::from_utf8(rest[..end].to_vec())?
    } else {
        String::new()
    };
    Ok((label, children.collect()))
}

/// The single CBOR content box of a labelled superbox.
fn cbor_content(children: &[JBox]) -> Result<Range<usize>> {
    let mut cbor = children.iter().filter(|b| &b.kind == b"cbor");
    let found = cbor.next().ok_or_else(|| anyhow!("no CBOR content box"))?;
    if cbor.next().is_some() {
        bail!("more than one CBOR content box");
    }
    Ok(found.content.clone())
}

/// The active (last) manifest of a manifest store.
pub fn active_manifest(store: &[u8]) -> Result<ActiveManifest> {
    let top = boxes(store, 0..store.len())?;
    let root = top.first().filter(|b| &b.kind == b"jumb").ok_or_else(|| anyhow!("not a JUMBF manifest store"))?;
    let (store_label, manifests) = superbox(store, root.content.clone())?;
    if store_label != "c2pa" {
        bail!("manifest store label is {store_label:?}, not \"c2pa\"");
    }
    let last = manifests.iter().filter(|b| &b.kind == b"jumb").last().ok_or_else(|| anyhow!("manifest store has no manifests"))?;
    let (label, parts) = superbox(store, last.content.clone())?;

    let (mut claim, mut signature) = (None, None);
    for part in parts.iter().filter(|b| &b.kind == b"jumb") {
        let (part_label, children) = superbox(store, part.content.clone())?;
        if part_label == "c2pa.claim.v2" || part_label == "c2pa.claim" {
            if claim.replace((part_label, cbor_content(&children)?)).is_some() {
                bail!("more than one claim in the active manifest");
            }
        } else if part_label == "c2pa.signature" {
            if signature.replace(cbor_content(&children)?).is_some() {
                bail!("more than one claim signature in the active manifest");
            }
        }
    }
    let (claim_label, claim) = claim.ok_or_else(|| anyhow!("active manifest has no claim"))?;
    let cose_sign1_range = signature.ok_or_else(|| anyhow!("active manifest has no claim signature"))?;
    Ok(ActiveManifest {
        label,
        claim_label,
        claim: store[claim].to_vec(),
        cose_sign1: store[cose_sign1_range.clone()].to_vec(),
        cose_sign1_range,
    })
}

/// The manifest store embedded in an asset.
pub fn manifest_store(asset: &Path) -> Result<Vec<u8>> {
    c2pa::jumbf_io::load_jumbf_from_file(asset).map_err(|e| anyhow!("no C2PA manifest store in {}: {e}", asset.display()))
}
