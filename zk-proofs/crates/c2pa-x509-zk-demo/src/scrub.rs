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
        0xe1 if payload.starts_with(SCRUBBED) => Some("scrubbed"),
        0xeb if payload.starts_with(JUMBF) => Some("manifest store"),
        _ => None,
    }
}

/// Scrub `asset` (in memory, `format` its file extension) given its hard
/// binding's exclusions, (start, length) each.
pub fn scrub(asset: &mut [u8], format: &str, exclusions: &[(u64, u64)]) -> Result<ScrubReport> {
    let original = asset.to_vec();
    let mut report = ScrubReport::default();
    match format.to_ascii_lowercase().as_str() {
        "jpg" | "jpeg" => scrub_jpeg(asset, exclusions, &mut report)?,
        other => {
            // Nothing to scrub only if the sole exclusion is the store.
            if exclusions.len() > 1 {
                bail!("scrubbing metadata is supported for JPEG only; this {other} has {} excluded ranges besides the manifest store", exclusions.len() - 1);
            }
        }
    }
    // The invariant: no byte outside the exclusions has changed.
    let mut excluded = vec![false; asset.len()];
    for &(start, length) in exclusions {
        let (s, e) = (start as usize, (start + length) as usize);
        if e > asset.len() {
            bail!("an exclusion runs past the file");
        }
        excluded[s..e].iter_mut().for_each(|x| *x = true);
    }
    if asset.iter().zip(&original).zip(&excluded).any(|((a, o), x)| a != o && !x) {
        bail!("internal error: scrubbing changed a byte the hard binding covers");
    }
    Ok(report)
}

fn scrub_jpeg(jpeg: &mut [u8], exclusions: &[(u64, u64)], report: &mut ScrubReport) -> Result<()> {
    let segments = segments(jpeg)?;
    let mut covered = vec![false; segments.len()];
    // First recognize every excluded range, so that a refusal changes nothing.
    let mut plan = Vec::new();
    for &(start, length) in exclusions {
        let (start, length) = (start as usize, length as usize);
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
            let is_store = end == start + length
                && !run.is_empty()
                && run.iter().all(|&i| {
                    let (ps, pl) = segments[i].payload();
                    kind(0xeb, &jpeg[ps..ps + pl]) == Some("manifest store")
                });
            if is_store {
                run.iter().for_each(|&i| covered[i] = true);
                continue;
            }
        }
        let index = segments
            .iter()
            .position(|s| s.payload() == (start, length))
            .ok_or_else(|| anyhow!("the excluded range at {start} ({length} bytes) is neither whole manifest-store segments nor exactly one segment's payload; not scrubbing what is not recognized"))?;
        covered[index] = true;
        let segment = &segments[index];
        let kind = kind(segment.marker, &jpeg[start..start + length])
            .ok_or_else(|| anyhow!("the excluded range at {start} is an unrecognized segment (marker {:#04x}); not scrubbing what is not recognized", segment.marker))?;
        if kind != "manifest store" && kind != "scrubbed" {
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

    /// A JPEG with EXIF, a manifest store, XMP, extended XMP, an ICC profile,
    /// a tiny scan, and data after the image; and the exclusions of its
    /// EXIF, store, XMP, and extended XMP payloads.
    fn jpeg() -> (Vec<u8>, Vec<(u64, u64)>) {
        let exif = [EXIF, b"II*\0\x08\0\0\0Make: Example Phone 9"].concat();
        let store = [JUMBF, b"\0\x01 the manifest store"].concat();
        let xmp = [XMP, b"<x:xmpmeta>Example Phone 9</x:xmpmeta>"].concat();
        let ext = [XMP_EXTENDED, b"0123456789abcdef0123456789abcdef secret depth data"].concat();
        let icc = [b"ICC_PROFILE\0".as_slice(), b"\x01\x01 profile"].concat();
        let mut out = vec![0xff, 0xd8];
        let mut exclusions = Vec::new();
        for (marker, payload, excluded) in [(0xe1, &exif, true), (0xeb, &store, true), (0xe1, &xmp, true), (0xe1, &ext, true), (0xe2, &icc, false)] {
            if marker == 0xeb {
                // The store, as real assets exclude it: the whole segment.
                exclusions.push((out.len() as u64, payload.len() as u64 + 4));
            } else if excluded {
                exclusions.push((out.len() as u64 + 4, payload.len() as u64));
            }
            out.extend(segment(marker, payload));
        }
        out.extend(segment(0xda, b"\x01\x01\0\0?\0")); // start of scan
        out.extend(b"\x12\x34\xff\x00\x56"); // entropy-coded data, with a stuffed byte
        out.extend([0xff, 0xff, 0xd9]); // end of image, after a fill byte
        out.extend(b"\xff\xd8 appended gain map, Example Phone 9");
        (out, exclusions)
    }

    #[test]
    fn scrubs_exif_and_xmp_and_keeps_everything_else() {
        let (original, exclusions) = jpeg();
        let mut scrubbed = original.clone();
        let report = scrub(&mut scrubbed, "jpg", &exclusions).unwrap();
        assert_eq!(scrubbed.len(), original.len());
        let kinds: Vec<_> = report.removed.iter().map(|(k, _, _)| *k).collect();
        assert_eq!(kinds, ["EXIF", "XMP", "extended XMP"]);
        // The identifying strings are gone from the excluded ranges...
        for &(s, l) in &exclusions {
            let range = &scrubbed[s as usize..(s + l) as usize];
            assert!(!range.windows(7).any(|w| w == b"Example"), "an excluded range still holds the metadata");
        }
        // ...the store is untouched, and so is every byte outside the exclusions.
        let (store_start, store_len) = exclusions[1];
        assert_eq!(scrubbed[store_start as usize..(store_start + store_len) as usize], original[store_start as usize..(store_start + store_len) as usize]);
        // Bound metadata is reported: the ICC profile, and the appended image.
        assert!(report.bound.iter().any(|b| b.starts_with("ICC profile")), "{:?}", report.bound);
        assert!(report.bound.iter().any(|b| b.starts_with("data after the main image")), "{:?}", report.bound);
        // Scrubbing again changes nothing.
        let mut again = scrubbed.clone();
        let report2 = scrub(&mut again, "jpg", &exclusions).unwrap();
        assert_eq!(again, scrubbed);
        assert!(report2.removed.is_empty());
    }

    #[test]
    fn refuses_what_it_does_not_recognize() {
        let (original, mut exclusions) = jpeg();
        // An exclusion covering part of a payload.
        let mut a = original.clone();
        let mut partial = exclusions.clone();
        partial[0].1 -= 1;
        assert!(scrub(&mut a, "jpg", &partial).unwrap_err().to_string().contains("not scrubbing what is not recognized"));
        // An excluded ICC profile (an unrecognized kind).
        let segs = segments(&original).unwrap();
        let icc = segs.iter().find(|s| s.marker == 0xe2).unwrap();
        let (s, l) = icc.payload();
        exclusions.push((s as u64, l as u64));
        let mut b = original.clone();
        assert!(scrub(&mut b, "jpg", &exclusions).unwrap_err().to_string().contains("unrecognized segment"));
        assert_eq!(b, original, "a refused scrub must not change the asset");
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
        // EXIF and XMP not excluded: signed, reported as bound.
        assert!(report.bound.iter().any(|b| b.starts_with("EXIF")), "{:?}", report.bound);
        assert!(report.bound.iter().any(|b| b.starts_with("XMP")), "{:?}", report.bound);
    }

    #[test]
    fn the_store_may_span_several_segments_or_be_excluded_as_a_payload() {
        let store1 = [JUMBF, b"\0\x01 first part"].concat();
        let store2 = [JUMBF, b"\0\x01 second part"].concat();
        let exif = [EXIF, b"II*\0 Example Phone 9"].concat();
        let mut out = vec![0xff, 0xd8];
        let store_start = out.len() as u64;
        out.extend(segment(0xeb, &store1));
        out.extend(segment(0xeb, &store2));
        let store_len = out.len() as u64 - store_start;
        let exif_payload = (out.len() as u64 + 4, exif.len() as u64);
        out.extend(segment(0xe1, &exif));
        out.extend(segment(0xda, b"\x01\x01\0\0?\0"));
        out.extend([0x12, 0xff, 0xd9]);
        let mut a = out.clone();
        let report = scrub(&mut a, "jpeg", &[(store_start, store_len), exif_payload]).unwrap();
        assert_eq!(report.removed.len(), 1);
        assert_eq!(a[..store_start as usize + store_len as usize], out[..store_start as usize + store_len as usize]);
        // A run that ends inside a segment is not the store.
        let mut b = out.clone();
        assert!(scrub(&mut b, "jpeg", &[(store_start, store_len - 1)]).is_err());
        // The store's payload alone is accepted too.
        let mut c = out.clone();
        assert!(scrub(&mut c, "jpeg", &[(store_start + 4, store1.len() as u64)]).is_ok());
    }
}
