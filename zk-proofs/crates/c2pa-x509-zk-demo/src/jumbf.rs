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

/// The boxes in `buf[range]`. Every length is checked against the bytes that
/// remain in the container before use, so malformed input is an error, never
/// an out-of-range slice or an overflow.
fn boxes(buf: &[u8], range: Range<usize>) -> Result<Vec<JBox>> {
    if range.start > range.end || range.end > buf.len() {
        bail!("JUMBF container range {range:?} is outside the buffer");
    }
    let mut out = Vec::new();
    let mut i = range.start;
    while i < range.end {
        let remaining = range.end - i;
        if remaining < 8 {
            bail!("truncated JUMBF box header at {i}");
        }
        let lbox = u32::from_be_bytes(buf[i..i + 4].try_into()?);
        let kind: [u8; 4] = buf[i + 4..i + 8].try_into()?;
        let (header, len) = match lbox {
            0 => (8, remaining),
            1 => {
                if remaining < 16 {
                    bail!("truncated extended JUMBF box header at {i}");
                }
                let xl = u64::from_be_bytes(buf[i + 8..i + 16].try_into()?);
                (16, usize::try_from(xl).map_err(|_| anyhow!("JUMBF box at {i} has length {xl}, too large"))?)
            }
            n => (8, usize::try_from(n)?),
        };
        if len < header || len > remaining {
            bail!("JUMBF box at {i} has invalid length {len} ({remaining} bytes remain in its container)");
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

/// The manifests of a manifest store, in store order (the active one last).
fn manifest_boxes(store: &[u8]) -> Result<Vec<JBox>> {
    let top = boxes(store, 0..store.len())?;
    let root = top.first().filter(|b| &b.kind == b"jumb").ok_or_else(|| anyhow!("not a JUMBF manifest store"))?;
    let (store_label, manifests) = superbox(store, root.content.clone())?;
    if store_label != "c2pa" {
        bail!("manifest store label is {store_label:?}, not \"c2pa\"");
    }
    Ok(manifests.into_iter().filter(|b| &b.kind == b"jumb").collect())
}

/// A manifest's label, claim, and claim signature.
fn parse_manifest(store: &[u8], manifest: &JBox) -> Result<ActiveManifest> {
    let (label, parts) = superbox(store, manifest.content.clone())?;
    let (mut claim, mut signature) = (None, None);
    for part in parts.iter().filter(|b| &b.kind == b"jumb") {
        let (part_label, children) = superbox(store, part.content.clone())?;
        if part_label == "c2pa.claim.v2" || part_label == "c2pa.claim" {
            if claim.replace((part_label, cbor_content(&children)?)).is_some() {
                bail!("more than one claim in manifest {label}");
            }
        } else if part_label == "c2pa.signature" {
            if signature.replace(cbor_content(&children)?).is_some() {
                bail!("more than one claim signature in manifest {label}");
            }
        }
    }
    let (claim_label, claim) = claim.ok_or_else(|| anyhow!("manifest {label} has no claim"))?;
    let cose_sign1_range = signature.ok_or_else(|| anyhow!("manifest {label} has no claim signature"))?;
    Ok(ActiveManifest {
        label,
        claim_label,
        claim: store[claim].to_vec(),
        cose_sign1: store[cose_sign1_range.clone()].to_vec(),
        cose_sign1_range,
    })
}

/// The active (last) manifest of a manifest store.
pub fn active_manifest(store: &[u8]) -> Result<ActiveManifest> {
    let manifests = manifest_boxes(store)?;
    let last = manifests.last().ok_or_else(|| anyhow!("manifest store has no manifests"))?;
    parse_manifest(store, last)
}

/// Every manifest of a manifest store, in store order (the active one last).
pub fn manifests(store: &[u8]) -> Result<Vec<ActiveManifest>> {
    manifest_boxes(store)?.iter().map(|m| parse_manifest(store, m)).collect()
}

/// The number of manifests in a manifest store.
pub fn manifest_count(store: &[u8]) -> Result<usize> {
    let top = boxes(store, 0..store.len())?;
    let root = top.first().filter(|b| &b.kind == b"jumb").ok_or_else(|| anyhow!("not a JUMBF manifest store"))?;
    let (_, manifests) = superbox(store, root.content.clone())?;
    Ok(manifests.iter().filter(|b| &b.kind == b"jumb").count())
}

/// An assertion of the active manifest: its label and its content box's type
/// and bytes (CBOR or JSON, typically).
#[derive(Debug, Clone)]
pub struct Assertion {
    pub label: String,
    pub content_type: [u8; 4],
    pub content: Vec<u8>,
}

/// The active manifest's assertions, in store order.
pub fn active_assertions(store: &[u8]) -> Result<Vec<Assertion>> {
    let top = boxes(store, 0..store.len())?;
    let root = top.first().filter(|b| &b.kind == b"jumb").ok_or_else(|| anyhow!("not a JUMBF manifest store"))?;
    let (_, manifests) = superbox(store, root.content.clone())?;
    let last = manifests.iter().filter(|b| &b.kind == b"jumb").last().ok_or_else(|| anyhow!("manifest store has no manifests"))?;
    let (_, parts) = superbox(store, last.content.clone())?;
    let mut out = Vec::new();
    for part in parts.iter().filter(|b| &b.kind == b"jumb") {
        let (part_label, children) = superbox(store, part.content.clone())?;
        if part_label != "c2pa.assertions" {
            continue;
        }
        for assertion in children.iter().filter(|b| &b.kind == b"jumb") {
            let (label, contents) = superbox(store, assertion.content.clone())?;
            let content = contents.first().ok_or_else(|| anyhow!("assertion {label} has no content"))?;
            out.push(Assertion { label, content_type: content.kind, content: store[content.content.clone()].to_vec() });
        }
    }
    Ok(out)
}

/// The manifest store embedded in an asset.
pub fn manifest_store(asset: &Path) -> Result<Vec<u8>> {
    c2pa::jumbf_io::load_jumbf_from_file(asset).map_err(|e| anyhow!("no C2PA manifest store in {}: {e}", asset.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jbox(kind: &[u8; 4], content: &[u8]) -> Vec<u8> {
        let mut out = ((content.len() + 8) as u32).to_be_bytes().to_vec();
        out.extend_from_slice(kind);
        out.extend_from_slice(content);
        out
    }

    /// A labelled superbox: a description box (UUID, toggles "requestable +
    /// label", the label) followed by `children`.
    fn superbox(label: &str, children: &[Vec<u8>]) -> Vec<u8> {
        let mut desc = vec![0u8; 16];
        desc.push(0x03);
        desc.extend_from_slice(label.as_bytes());
        desc.push(0);
        let mut content = jbox(b"jumd", &desc);
        children.iter().for_each(|c| content.extend_from_slice(c));
        jbox(b"jumb", &content)
    }

    fn manifest(label: &str, parts: &[(&str, &[u8])]) -> Vec<u8> {
        let parts: Vec<Vec<u8>> = parts.iter().map(|(l, cbor)| superbox(l, &[jbox(b"cbor", cbor)])).collect();
        superbox(label, &parts)
    }

    #[test]
    fn reads_the_last_manifest_and_locates_its_signature() {
        let first = manifest("urn:c2pa:first", &[("c2pa.claim.v2", b"OLD"), ("c2pa.signature", b"OLDSIG")]);
        let active = manifest("urn:c2pa:active", &[("c2pa.claim.v2", b"CLAIM"), ("c2pa.signature", b"SIGNATURE")]);
        let store = superbox("c2pa", &[first, active]);
        let m = active_manifest(&store).unwrap();
        assert_eq!((m.label.as_str(), m.claim_label.as_str()), ("urn:c2pa:active", "c2pa.claim.v2"));
        assert_eq!(m.claim, b"CLAIM");
        assert_eq!(&store[m.cose_sign1_range.clone()], b"SIGNATURE");
    }

    #[test]
    fn rejects_malformed_structure() {
        let no_claim = superbox("c2pa", &[manifest("urn:c2pa:x", &[("c2pa.signature", b"S")])]);
        let two_claims = superbox("c2pa", &[manifest("urn:c2pa:x", &[("c2pa.claim.v2", b"A"), ("c2pa.claim", b"B"), ("c2pa.signature", b"S")])]);
        let no_manifest = superbox("c2pa", &[]);
        let wrong_label = superbox("other", &[manifest("urn:c2pa:x", &[("c2pa.claim.v2", b"A"), ("c2pa.signature", b"S")])]);
        let no_description = jbox(b"jumb", &jbox(b"cbor", b"x"));
        for (name, store) in [("no claim", no_claim), ("two claims", two_claims), ("no manifest", no_manifest), ("label", wrong_label), ("no description", no_description)] {
            assert!(active_manifest(&store).is_err(), "{name} accepted");
        }
    }

    /// Lengths that overflow, undershoot the header, or overrun the container
    /// are errors, not panics.
    #[test]
    fn rejects_malformed_lengths_without_panicking() {
        // The review's probe: an outer box running to the end of the buffer,
        // holding a description box whose extended length wraps around.
        let mut wrapping = vec![0, 0, 0, 0];
        wrapping.extend_from_slice(b"jumb");
        wrapping.extend_from_slice(&[0, 0, 0, 1]);
        wrapping.extend_from_slice(b"jumd");
        wrapping.extend_from_slice(&(u64::MAX - 7).to_be_bytes());
        assert_eq!(wrapping.len(), 24);

        let mut extended_too_long = vec![0, 0, 0, 1];
        extended_too_long.extend_from_slice(b"jumb");
        extended_too_long.extend_from_slice(&64u64.to_be_bytes());

        let mut shorter_than_header = 4u32.to_be_bytes().to_vec();
        shorter_than_header.extend_from_slice(b"jumb");

        let mut past_parent = superbox("c2pa", &[]);
        past_parent[3] += 1; // the outer length now exceeds the buffer

        let mut child_past_parent = superbox("c2pa", &[jbox(b"cbor", b"abcdef")]);
        let n = child_past_parent.len();
        child_past_parent[n - 14 + 3] += 8; // the child's length runs past its parent

        let truncated_header = vec![0, 0, 0, 9, b'j'];
        let truncated_extended = [&[0u8, 0, 0, 1][..], b"jumb", &[0, 0]].concat();
        let extended_shorter_than_header = [&[0u8, 0, 0, 1][..], b"jumb", &8u64.to_be_bytes()].concat();

        for (name, store) in [
            ("wrapping extended length", wrapping),
            ("extended length past the buffer", extended_too_long),
            ("length shorter than the header", shorter_than_header),
            ("box past the buffer", past_parent),
            ("child past its parent", child_past_parent),
            ("truncated header", truncated_header),
            ("truncated extended header", truncated_extended),
            ("extended length shorter than the header", extended_shorter_than_header),
            ("empty", vec![]),
        ] {
            assert!(active_manifest(&store).is_err(), "{name} accepted");
        }
    }
}
