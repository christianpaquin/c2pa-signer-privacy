//! Metadata scrubbing (roadmap H6, CLAIM-PRIVACY.md, "Metadata outside the
//! claim"): overwrite the identifying metadata that lies in byte ranges the
//! hard binding excludes, in place, at the same size.
//!
//! Only excluded bytes change, so the claim, its assertions, and the hard
//! binding stay valid: the scrubber checks that every byte outside the
//! exclusions is unchanged. Metadata inside the bound ranges is signed and
//! cannot change; it is reported, not removed.
//!
//! JPEG only for now: each excluded range must be the manifest store (whole
//! APP11 JUMBF segments, marker and length included, as real assets exclude
//! it; or one such segment's payload), left alone; or exactly one segment's
//! payload (after its marker and length, which the binding covers) holding
//! EXIF, XMP, or extended XMP.
//! Any other excluded range is refused rather than guessed at. A scrubbed
//! payload keeps its marker and length, and becomes an inert identifier
//! (`c2pa-x509-zk-scrubbed`) followed by zeros, which EXIF and XMP readers
//! skip. Other formats are accepted only when their sole exclusion is the
//! manifest store (nothing to scrub).

use anyhow::{anyhow, bail, Result};

/// The identifier a scrubbed payload starts with.
pub const SCRUBBED: &[u8] = b"c2pa-x509-zk-scrubbed\0";

const EXIF: &[u8] = b"Exif\0\0";
const XMP: &[u8] = b"http://ns.adobe.com/xap/1.0/\0";
const XMP_EXTENDED: &[u8] = b"http://ns.adobe.com/xmp/extension/\0";
const JUMBF: &[u8] = b"JP";
/// The C2PA manifest store's JUMBF description type (C2PA 2.5, §11.1.4.2).
const C2PA_STORE_UUID: [u8; 16] = [0x63, 0x32, 0x70, 0x61, 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71];

/// What scrubbing removed, and the metadata it had to leave.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScrubReport {
    /// Removed: (kind, start, length) of each payload overwritten.
    pub removed: Vec<(&'static str, u64, u64)>,
    /// Left, because the hard binding covers it (signed): a description each.
    pub bound: Vec<String>,
}

impl ScrubReport {
    /// The bytes removed of a kind.
    pub fn bytes(&self, kind: &str) -> u64 {
        self.removed.iter().filter(|(k, _, _)| *k == kind).map(|(_, _, l)| l).sum()
    }
}

/// A JPEG segment before the image data: marker, start (of the marker), and
/// total length (marker included).
struct Segment {
    marker: u8,
    start: usize,
    len: usize,
}

impl Segment {
    fn payload(&self) -> (usize, usize) {
        (self.start + 4, self.len - 4)
    }
}

/// The JPEG's segments up to the start of scan.
fn segments(jpeg: &[u8]) -> Result<Vec<Segment>> {
    if !jpeg.starts_with(&[0xff, 0xd8]) {
        bail!("not a JPEG");
    }
    let mut out = Vec::new();
    let mut p = 2;
    while p + 4 <= jpeg.len() {
        if jpeg[p] != 0xff {
            bail!("malformed JPEG: no marker at {p}");
        }
        let marker = jpeg[p + 1];
        if marker == 0xda {
            return Ok(out); // start of scan: the image data follows
        }
        let len = 2 + u16::from_be_bytes([jpeg[p + 2], jpeg[p + 3]]) as usize;
        if len < 4 || p + len > jpeg.len() {
            bail!("malformed JPEG: segment at {p} runs past the file");
        }
        out.push(Segment { marker, start: p, len });
        p += len;
    }
    bail!("malformed JPEG: no start of scan")
}

/// The kind of an APP payload, from its identifier.
fn kind(marker: u8, payload: &[u8]) -> Option<&'static str> {
    match marker {
        0xe1 if payload.starts_with(EXIF) => Some("EXIF"),
        0xe1 if payload.starts_with(XMP) => Some("XMP"),
        0xe1 if payload.starts_with(XMP_EXTENDED) => Some("extended XMP"),
        // Already scrubbed: exactly the marker and zeros. With anything else
        // after the marker, it is data like any other, and is overwritten.
        0xe1 if payload.starts_with(SCRUBBED) && payload[SCRUBBED.len()..].iter().all(|&b| b == 0) => Some("scrubbed"),
        0xe1 if payload.starts_with(SCRUBBED) => Some("other data after the scrub marker"),
        _ => None,
    }
}

/// Whether the segments `run` (indices, consecutive) carry exactly the C2PA
/// manifest store, as JPEG's JUMBF transport splits it, and nothing else.
///
/// Each segment is an APP11 payload of a transport header (`JP`, the box
/// instance number `En`, the sequence number `Z`: 1, 2, ... in order, the same
/// `En` throughout) followed by the superbox header (`LBox`, `jumb`, and
/// `XLBox` when `LBox` is 1), repeated in every segment, then a part of the
/// superbox's content. Reassembled (the first segment's header once, each
/// segment's content), the superbox must have exactly its declared length:
/// bytes after the store, in the last segment or in a surplus segment, are not
/// the store. The content must start with a description box of the C2PA
/// manifest store's type, labelled `c2pa`, entirely within the first segment
/// and the store. Bytes that merely start with `JP` are not the store.
fn is_c2pa_store(jpeg: &[u8], segments: &[Segment], run: &[usize]) -> bool {
    let Some(&first) = run.first() else { return false };
    let payload = |i: usize| {
        let (ps, pl) = segments[i].payload();
        &jpeg[ps..ps + pl]
    };
    // The superbox header, from the first segment.
    let p0 = payload(first);
    if segments[first].marker != 0xeb || p0.len() < 16 || &p0[..2] != JUMBF || &p0[12..16] != b"jumb" {
        return false;
    }
    let lbox = u32::from_be_bytes([p0[8], p0[9], p0[10], p0[11]]) as u64;
    let (declared, header_len) = match lbox {
        1 if p0.len() >= 24 => (u64::from_be_bytes(p0[16..24].try_into().expect("8 bytes")), 16),
        0 | 1 => return false, // "to the end of the file", or a truncated XLBox: not a bounded store
        n => (n, 8),
    };
    let header = &p0[8..8 + header_len];
    let instance = &p0[2..4];
    let mut reassembled: u64 = 0;
    for (n, &i) in run.iter().enumerate() {
        let p = payload(i);
        if segments[i].marker != 0xeb || p.len() < 8 + header_len || &p[..2] != JUMBF || &p[2..4] != instance {
            return false;
        }
        if u32::from_be_bytes([p[4], p[5], p[6], p[7]]) != n as u32 + 1 || &p[8..8 + header_len] != header {
            return false;
        }
        // The first segment counts its header; every segment its content.
        let content = (p.len() - 8 - header_len) as u64;
        reassembled += content + if n == 0 { header_len as u64 } else { 0 };
        if n > 0 && content == 0 {
            return false; // a continuation carrying nothing
        }
    }
    if reassembled != declared {
        return false; // trailing bytes, a surplus segment, or a truncated store
    }
    // The description box: LBox (4) 'jumd' (4) UUID (16) toggles (1) label.
    let d = &p0[8 + header_len..];
    if d.len() < 30 || &d[4..8] != b"jumd" || d[8..24] != C2PA_STORE_UUID || d[24] & 0x02 == 0 || &d[25..30] != b"c2pa\0" {
        return false;
    }
    let d_len = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) as usize;
    d_len >= 30 && d_len <= d.len() && (header_len + d_len) as u64 <= declared
}

/// Scrub `asset` (in memory, `format` its file extension) given its hard
/// binding's exclusions, (start, length) each.
pub fn scrub(asset: &mut [u8], format: &str, exclusions: &[(u64, u64)]) -> Result<ScrubReport> {
    // Every exclusion validated first, with checked arithmetic: a malformed
    // one is an error, and the asset is unchanged.
    let ranges = exclusions
        .iter()
        .map(|&(start, length)| {
            let end = start.checked_add(length).ok_or_else(|| anyhow!("an exclusion overflows ({start} + {length})"))?;
            let (s, e) = (usize::try_from(start)?, usize::try_from(end)?);
            if e > asset.len() {
                bail!("the exclusion [{start}, {end}) runs past the file ({} bytes)", asset.len());
            }
            Ok((s, e - s))
        })
        .collect::<Result<Vec<(usize, usize)>>>()?;
    let original = asset.to_vec();
    let mut report = ScrubReport::default();
    match format.to_ascii_lowercase().as_str() {
        "jpg" | "jpeg" => scrub_jpeg(asset, &ranges, &mut report)?,
        other => {
            // Nothing to scrub only if the sole exclusion is the store.
            if exclusions.len() > 1 {
                bail!("scrubbing metadata is supported for JPEG only; this {other} has {} excluded ranges besides the manifest store", exclusions.len() - 1);
            }
        }
    }
    // The invariant: no byte outside the exclusions has changed.
    let mut excluded = vec![false; asset.len()];
    for &(s, l) in &ranges {
        excluded[s..s + l].iter_mut().for_each(|x| *x = true);
    }
    if asset.iter().zip(&original).zip(&excluded).any(|((a, o), x)| a != o && !x) {
        bail!("internal error: scrubbing changed a byte the hard binding covers");
    }
    Ok(report)
}

fn scrub_jpeg(jpeg: &mut [u8], exclusions: &[(usize, usize)], report: &mut ScrubReport) -> Result<()> {
    let segments = segments(jpeg)?;
    let mut covered = vec![false; segments.len()];
    // First recognize every excluded range, so that a refusal changes nothing.
    let mut plan = Vec::new();
    for &(start, length) in exclusions {
        // The manifest store: one or more consecutive whole APP11 JUMBF segments.
        if let Some(first) = segments.iter().position(|s| s.start == start) {
            let mut end = start;
            let mut run = Vec::new();
            for (i, s) in segments.iter().enumerate().skip(first) {
                if end >= start + length || s.marker != 0xeb {
                    break;
                }
                end += s.len;
                run.push(i);
            }
            if end == start + length && is_c2pa_store(jpeg, &segments, &run) {
                run.iter().for_each(|&i| covered[i] = true);
                continue;
            }
        }
        let index = segments
            .iter()
            .position(|s| s.payload() == (start, length))
            .ok_or_else(|| anyhow!("the excluded range at {start} ({length} bytes) is neither whole manifest-store segments nor exactly one segment's payload; not scrubbing what is not recognized"))?;
        covered[index] = true;
        // The store's payload alone, in a single segment.
        if is_c2pa_store(jpeg, &segments, &[index]) {
            continue;
        }
        let segment = &segments[index];
        let kind = kind(segment.marker, &jpeg[start..start + length])
            .ok_or_else(|| anyhow!("the excluded range at {start} is an unrecognized segment (marker {:#04x}); not scrubbing what is not recognized", segment.marker))?;
        if kind != "scrubbed" {
            plan.push((kind, start, length));
        }
    }
    for (kind, start, length) in plan {
        let payload = &mut jpeg[start..start + length];
        payload.fill(0);
        let n = SCRUBBED.len().min(length);
        payload[..n].copy_from_slice(&SCRUBBED[..n]);
        report.removed.push((kind, start as u64, length as u64));
    }
    // Metadata the binding covers: reported, left in place.
    for (segment, covered) in segments.iter().zip(&covered) {
        if *covered || !(0xe0..=0xef).contains(&segment.marker) {
            continue;
        }
        let (s, l) = segment.payload();
        let name = match (segment.marker, kind(segment.marker, &jpeg[s..s + l])) {
            (_, Some(k)) => k.to_string(),
            (0xe0, _) => "JFIF".into(),
            (0xe2, _) if jpeg[s..s + l].starts_with(b"ICC_PROFILE\0") => "ICC profile".into(),
            (0xe2, _) if jpeg[s..s + l].starts_with(b"MPF\0") => "multi-picture index (MPF)".into(),
            (m, _) => format!("APP{}", m - 0xe0),
        };
        report.bound.push(format!("{name} ({} bytes, signed)", l));
    }
    // Data after the main image (for example, an MPF gain-map image).
    if let Some(eoi) = main_image_end(jpeg, &segments) {
        if eoi < jpeg.len() {
            report.bound.push(format!("data after the main image ({} bytes, signed; for example, a gain-map image and its metadata)", jpeg.len() - eoi));
        }
    }
    Ok(())
}

/// The offset just after the main image's end-of-image marker.
fn main_image_end(jpeg: &[u8], segments: &[Segment]) -> Option<usize> {
    let last = segments.last()?;
    let mut p = last.start + last.len; // the start-of-scan marker
    // Skip the SOS header, then scan entropy-coded data for EOI (FF D9),
    // stepping over stuffed bytes (FF 00) and restart markers (FF D0-D7).
    let len = 2 + u16::from_be_bytes([*jpeg.get(p + 2)?, *jpeg.get(p + 3)?]) as usize;
    p += len;
    while p + 1 < jpeg.len() {
        if jpeg[p] == 0xff {
            match jpeg[p + 1] {
                0xd9 => return Some(p + 2),
                // A fill byte: the marker, if any, starts at the next byte.
                0xff => p += 1,
                // A stuffed zero or a restart marker: skip both bytes.
                _ => p += 2,
            }
        } else {
            p += 1;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(marker: u8, payload: &[u8]) -> Vec<u8> {
        let len = (payload.len() + 2) as u16;
        [&[0xff, marker][..], &len.to_be_bytes(), payload].concat()
    }

    /// The C2PA manifest store as JPEG's JUMBF transport carries it, split
    /// into `parts` APP11 segments: a `jumb` superbox whose description box
    /// has the store's type and label, then `content`. `uuid` and the
    /// sequence numbers can be changed for negative tests.
    fn store_segments(content: &[u8], parts: usize, uuid: [u8; 16], sequence: impl Fn(usize) -> u32) -> Vec<Vec<u8>> {
        let mut desc = Vec::new();
        desc.extend(((8 + 16 + 1 + 5) as u32).to_be_bytes());
        desc.extend(b"jumd");
        desc.extend(uuid);
        desc.push(0x03); // requestable, label present
        desc.extend(b"c2pa\0");
        let body = [desc.as_slice(), content].concat();
        let header = [((body.len() + 8) as u32).to_be_bytes().as_slice(), b"jumb"].concat();
        let chunk = body.len().div_ceil(parts);
        body.chunks(chunk)
            .enumerate()
            .map(|(n, c)| {
                let payload = [JUMBF, &[0, 1][..], &sequence(n).to_be_bytes(), &header, c].concat();
                segment(0xeb, &payload)
            })
            .collect()
    }

    /// The store's boxes: long enough that, split in three, the first
    /// segment holds the whole description box, as in real stores.
    fn canonical_store(parts: usize) -> Vec<Vec<u8>> {
        store_segments(&[b'b'; 200], parts, C2PA_STORE_UUID, |n| n as u32 + 1)
    }

    /// A JPEG with EXIF, the manifest store, XMP, extended XMP, an ICC
    /// profile, a tiny scan, and data after the image; and the exclusions of
    /// its EXIF, store (whole segments, as real assets exclude it), XMP, and
    /// extended XMP.
    fn jpeg() -> (Vec<u8>, Vec<(u64, u64)>) {
        jpeg_with_store(canonical_store(1))
    }

    fn jpeg_with_store(store: Vec<Vec<u8>>) -> (Vec<u8>, Vec<(u64, u64)>) {
        let exif = [EXIF, b"II*\0\x08\0\0\0Make: Example Phone 9"].concat();
        let xmp = [XMP, b"<x:xmpmeta>Example Phone 9</x:xmpmeta>"].concat();
        let ext = [XMP_EXTENDED, b"0123456789abcdef0123456789abcdef secret depth data"].concat();
        let icc = [b"ICC_PROFILE\0".as_slice(), b"\x01\x01 profile"].concat();
        let mut out = vec![0xff, 0xd8];
        let mut exclusions = Vec::new();
        exclusions.push((out.len() as u64 + 4, exif.len() as u64));
        out.extend(segment(0xe1, &exif));
        let store_start = out.len() as u64;
        store.iter().for_each(|s| out.extend(s));
        exclusions.push((store_start, out.len() as u64 - store_start));
        for payload in [&xmp, &ext] {
            exclusions.push((out.len() as u64 + 4, payload.len() as u64));
            out.extend(segment(0xe1, payload));
        }
        out.extend(segment(0xe2, &icc));
        out.extend(segment(0xda, b"\x01\x01\0\0?\0")); // start of scan
        out.extend(b"\x12\x34\xff\x00\x56"); // entropy-coded data, with a stuffed byte
        out.extend([0xff, 0xff, 0xd9]); // end of image, after a fill byte
        out.extend(b"\xff\xd8 appended gain map, Example Phone 9");
        (out, exclusions)
    }

    fn refused(asset: &[u8], exclusions: &[(u64, u64)]) -> String {
        let mut a = asset.to_vec();
        let err = scrub(&mut a, "jpg", exclusions).unwrap_err().to_string();
        assert_eq!(a, asset, "a refused scrub changed the asset");
        err
    }

    #[test]
    fn scrubs_exif_and_xmp_and_keeps_everything_else() {
        let (original, exclusions) = jpeg();
        let mut scrubbed = original.clone();
        let report = scrub(&mut scrubbed, "jpg", &exclusions).unwrap();
        assert_eq!(scrubbed.len(), original.len());
        let kinds: Vec<_> = report.removed.iter().map(|(k, _, _)| *k).collect();
        assert_eq!(kinds, ["EXIF", "XMP", "extended XMP"]);
        for &(s, l) in &exclusions {
            let range = &scrubbed[s as usize..(s + l) as usize];
            assert!(!range.windows(7).any(|w| w == b"Example"), "an excluded range still holds the metadata");
        }
        let (store_start, store_len) = exclusions[1];
        let store = store_start as usize..(store_start + store_len) as usize;
        assert_eq!(scrubbed[store.clone()], original[store]);
        assert!(report.bound.iter().any(|b| b.starts_with("ICC profile")), "{:?}", report.bound);
        assert!(report.bound.iter().any(|b| b.starts_with("data after the main image")), "{:?}", report.bound);
        // Scrubbing again changes nothing: the scrubbed payloads are canonical.
        let mut again = scrubbed.clone();
        let report2 = scrub(&mut again, "jpg", &exclusions).unwrap();
        assert_eq!(again, scrubbed);
        assert!(report2.removed.is_empty());
    }

    #[test]
    fn refuses_what_it_does_not_recognize() {
        let (original, exclusions) = jpeg();
        let mut partial = exclusions.clone();
        partial[0].1 -= 1;
        assert!(refused(&original, &partial).contains("not scrubbing what is not recognized"));
        // An excluded ICC profile (an unrecognized kind).
        let segs = segments(&original).unwrap();
        let icc = segs.iter().find(|s| s.marker == 0xe2).unwrap();
        let (s, l) = icc.payload();
        let mut with_icc = exclusions.clone();
        with_icc.push((s as u64, l as u64));
        assert!(refused(&original, &with_icc).contains("unrecognized segment"));
        // Other formats: only the store may be excluded.
        let mut c = original.clone();
        assert!(scrub(&mut c, "png", &[(8, 100)]).is_ok());
        assert!(scrub(&mut c, "png", &[(8, 100), (200, 10)]).is_err());
    }

    #[test]
    fn a_jpeg_with_only_the_store_excluded_is_unchanged() {
        let (original, exclusions) = jpeg();
        let mut a = original.clone();
        let report = scrub(&mut a, "jpg", &exclusions[1..2]).unwrap();
        assert_eq!(a, original);
        assert!(report.removed.is_empty());
        assert!(report.bound.iter().any(|b| b.starts_with("EXIF")), "{:?}", report.bound);
        assert!(report.bound.iter().any(|b| b.starts_with("XMP")), "{:?}", report.bound);
    }

    /// The store is recognized by its structure, not by `JP` (PR #44 review):
    /// a split store is accepted; unrelated JUMBF, a malformed JP payload, or
    /// unexpected continuations are refused.
    #[test]
    fn the_store_is_recognized_by_its_structure() {
        // A store split over three segments.
        let (asset, exclusions) = jpeg_with_store(canonical_store(3));
        let mut a = asset.clone();
        assert_eq!(scrub(&mut a, "jpg", &exclusions).unwrap().removed.len(), 3);
        // The store's payload alone, in one segment, is accepted too.
        let (asset1, ex1) = jpeg();
        let mut b = asset1.clone();
        assert!(scrub(&mut b, "jpg", &[(ex1[1].0 + 4, ex1[1].1 - 4)]).is_ok());

        let other_uuid = [0x11; 16];
        let cases: Vec<(&str, Vec<Vec<u8>>)> = vec![
            ("unrelated JUMBF", store_segments(b"another standard's boxes", 1, other_uuid, |n| n as u32 + 1)),
            ("a malformed JP payload", vec![segment(0xeb, b"JP arbitrary data; private-camera-serial-123456")]),
            ("continuations out of order", store_segments(&[b'b'; 200], 3, C2PA_STORE_UUID, |n| [1, 3, 2][n])),
            ("a sequence not starting at 1", store_segments(b"the manifest store's boxes", 1, C2PA_STORE_UUID, |_| 2)),
        ];
        for (name, store) in cases {
            let (asset, exclusions) = jpeg_with_store(store);
            let err = refused(&asset, &exclusions);
            assert!(err.contains("not recognized"), "{name}: {err}");
        }
        // A continuation of another instance in the run.
        let mut store = canonical_store(2);
        let mut second = store[1].clone();
        second[4 + 2..4 + 4].copy_from_slice(&[0, 2]); // En
        store[1] = second;
        let (asset, exclusions) = jpeg_with_store(store);
        assert!(refused(&asset, &exclusions).contains("not recognized"));
    }

    /// A payload starting with the scrub marker is already scrubbed only if
    /// the rest is zeros (PR #44 review); otherwise it is overwritten.
    #[test]
    fn a_marker_with_data_after_it_is_overwritten() {
        let (mut asset, exclusions) = jpeg();
        let payload = [SCRUBBED, b"private-camera-serial-123456"].concat();
        // Replace the extended XMP payload (same length) with the marker and data.
        let (s, l) = (exclusions[3].0 as usize, exclusions[3].1 as usize);
        assert!(l >= payload.len());
        let mut fake = vec![0u8; l];
        fake[..payload.len()].copy_from_slice(&payload);
        asset[s..s + l].copy_from_slice(&fake);
        let report = scrub(&mut asset, "jpg", &exclusions).unwrap();
        assert!(report.removed.iter().any(|(k, _, _)| *k == "other data after the scrub marker"), "{report:?}");
        assert!(!asset.windows(14).any(|w| w == b"private-camera"), "the identifier survived");
    }

    /// Malformed exclusions are errors, never panics, and change nothing
    /// (PR #44 review).
    #[test]
    fn malformed_exclusions_are_refused() {
        let (asset, _) = jpeg();
        for (name, exclusions) in [
            ("overflowing", vec![(1, u64::MAX)]),
            ("past the end", vec![(asset.len() as u64 - 1, 2)]),
            ("starting past the end", vec![(asset.len() as u64 + 5, 0)]),
        ] {
            for format in ["jpg", "png"] {
                let mut a = asset.clone();
                assert!(scrub(&mut a, format, &exclusions).is_err(), "{name} ({format}): accepted");
                assert_eq!(a, asset, "{name} ({format}): changed the asset");
            }
        }
    }

    /// Exactly the declared store, and nothing after it (PR #44 follow-up):
    /// bytes past the superbox's length, in the same segment or a surplus
    /// one, are not the store; nor is a truncated store or a description box
    /// claiming more than the store.
    #[test]
    fn the_store_has_exactly_its_declared_extent() {
        let serial = b"\0\0\0\x24free private-camera-serial-123456";
        // Extra bytes after the store, in the first (only) segment.
        let mut one = canonical_store(1);
        let len = one[0].len() + serial.len() - 2;
        one[0].extend(serial);
        one[0][2..4].copy_from_slice(&(len as u16).to_be_bytes());
        // Extra bytes in a second segment, with the same instance, header, and sequence 2.
        let mut two = canonical_store(1);
        let p = &two[0][4..];
        let header = p[8..16].to_vec();
        let extra = [JUMBF, &[0, 1][..], &2u32.to_be_bytes(), &header, serial].concat();
        two.push(segment(0xeb, &extra));
        // A truncated store: its last byte missing.
        let mut short = canonical_store(1);
        short[0].pop();
        let l = short[0].len() - 2;
        short[0][2..4].copy_from_slice(&(l as u16).to_be_bytes());
        // A description box claiming more than the store holds.
        let mut wide = canonical_store(1);
        let d = 4 + 8 + 8; // segment header, transport header, superbox header
        wide[0][d..d + 4].copy_from_slice(&10_000u32.to_be_bytes());
        for (name, store) in [("extra bytes in the segment", one), ("extra bytes in a surplus segment", two), ("a truncated store", short), ("a description box beyond the store", wide)] {
            let (asset, exclusions) = jpeg_with_store(store);
            let err = refused(&asset, &exclusions);
            assert!(err.contains("not recognized"), "{name}: {err}");
        }
        // Controls: single-segment and split stores of exactly their length.
        for parts in [1, 2, 3] {
            let (asset, exclusions) = jpeg_with_store(canonical_store(parts));
            let mut a = asset.clone();
            assert!(scrub(&mut a, "jpg", &exclusions).is_ok(), "a store in {parts} segment(s): refused");
        }
    }

}
