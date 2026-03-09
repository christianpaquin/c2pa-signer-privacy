pragma circom 2.1.6;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "./sha_bytes.circom";

/*
 * X.509 Certificate Parser Circuit
 *
 * Parses a DER-encoded X.509 certificate using the "prover-assisted parsing"
 * pattern: the prover computes byte offsets off-circuit and supplies them as
 * private inputs; the circuit verifies the DER tags/lengths at those positions.
 *
 * Outputs:
 *   spkiX[k], spkiY[k]   — subject EC public key (for claim-sig check, Step 4)
 *   tbsHashBits[256]      — SHA-256(TBSCertificate) bits (for CA sig, Step 2)
 *   notBefore, notAfter   — certificate validity bounds as Unix timestamps
 *                           (for validity-period check, Step 5)
 *
 * Certificate DER structure assumed:
 *   30 82 LL LL            Certificate SEQUENCE (outer)
 *     30 82 HH LL          TBSCertificate SEQUENCE  ← tbsOffset
 *       ...
 *       17 0D YYMMDDHHMMSSZ  notBefore UTCTime      ← notBeforeOffset
 *       17 0D YYMMDDHHMMSSZ  notAfter  UTCTime      ← notAfterOffset
 *       ...
 *       30 ...               SubjectPublicKeyInfo SEQUENCE
 *         30 ...               AlgorithmIdentifier
 *         03 42 00 04          BIT STRING, uncompressed point
 *                   ^^^^       spkiXOffset → first X byte (after 0x04)
 *           XX*32              X coordinate (32 bytes)
 *           YY*32              Y coordinate (32 bytes)
 *
 * Parameters: maxCertBytes (buffer size), n (bits per register), k (registers)
 *   For P-256: n=43, k=6 → 6×43=258 bits ≥ 256-bit coordinates.
 *
 * SHA-256 parameters:
 *   TBS max size ≈ maxCertBytes − 16 (outer wrapper).  We pad to the next
 *   multiple of 64 bytes (512-bit SHA block).  For maxCertBytes=1500 the TBS
 *   fits in 1536 bytes (= 24 × 64).  The Sha256Bytes template is instantiated
 *   with this compile-time constant; the prover supplies the actual padded
 *   length as tbsHashPaddedLen.
 *
 * Constraint budget (n=43, k=6, maxCertBytes=1500):
 *   DER tag/length checks (7 × SelectByte):   ~31,500
 *   SPKI byte extraction  (64 × SelectByte):  ~288,000
 *   TBS byte extraction   (1536 × SelectByte):~6,912,000  ← dominates
 *   BytesToRegisters (×3):                    ~1,542
 *   Sha256Bytes(1536):                        ~720,000
 *   UTCTime → Unix timestamp (×2):            ~400
 *   Total:                                    ~7,953,000
 *
 * NOTE: The 1536 × SelectByte calls for TBS extraction are the bottleneck
 * (~6.9M constraints).  A future optimisation can replace these with a single
 * VarShiftLeft from @zk-email/circuits/utils/array.circom (~4K constraints)
 * to reduce total to ~1.0M.
 */

// ---------------------------------------------------------------------------
// SelectByte — select certDer[idx] where idx is a runtime signal.
//
// In Circom, array indices must be compile-time constants, so variable-index
// access requires a mux: one IsEqual comparison per possible index, then an
// accumulator that picks the matching byte.  For maxBytes=1500 this costs
// ~4×1500 = 6,000 constraints per call.
// ---------------------------------------------------------------------------
template SelectByte(maxBytes) {
    signal input bytes[maxBytes];
    signal input idx;
    signal output out;

    signal indicator[maxBytes];
    signal product[maxBytes];
    signal acc[maxBytes];

    component eq[maxBytes];
    for (var i = 0; i < maxBytes; i++) {
        eq[i] = IsEqual();
        eq[i].in[0] <== i;
        eq[i].in[1] <== idx;
        indicator[i] <== eq[i].out;
        product[i] <== indicator[i] * bytes[i];
    }

    acc[0] <== product[0];
    for (var i = 1; i < maxBytes; i++) {
        acc[i] <== acc[i-1] + product[i];
    }
    out <== acc[maxBytes-1];
}

// ---------------------------------------------------------------------------
// BytesToRegisters — convert 32 big-endian bytes to k registers of n bits.
//
// Register 0 is the least-significant n-bit chunk (positional notation):
//   value = Σ regs[i] * 2^(n*i)  for i in 0..k-1
//
// This matches the BigInt encoding used by circom-ecdsa-p256 so that the
// output can be fed directly into ECDSAVerifyNoPubkeyCheck.
//
// Bit mapping (p = bit position, 0=LSB, 255=MSB):
//   byte  = 31 - p÷8   (bytes[0] is MSB byte, bytes[31] is LSB byte)
//   digit = p mod 8     (Num2Bits outputs LSB first → digit 0 is LSB)
// ---------------------------------------------------------------------------
template BytesToRegisters(n, k) {
    signal input bytes[32];
    signal output regs[k];

    component byteBits[32];
    for (var b = 0; b < 32; b++) {
        byteBits[b] = Num2Bits(8);
        byteBits[b].in <== bytes[b];
    }

    component pack[k];
    for (var r = 0; r < k; r++) {
        pack[r] = Bits2Num(n);
        for (var i = 0; i < n; i++) {
            var bitPos = r * n + i;
            if (bitPos < 256) {
                pack[r].in[i] <== byteBits[31 - bitPos \ 8].out[bitPos % 8];
            } else {
                pack[r].in[i] <== 0;  // padding for the last register (bits 256–257)
            }
        }
        regs[r] <== pack[r].out;
    }
}

// ---------------------------------------------------------------------------
// BitsToRegisters — pack SHA-256 output bits into k n-bit BigInt registers.
//
// bits[256]: MSB at bits[0] (Sha256Bytes output convention).
// regs[k]:   little-endian n-bit registers, LSB at regs[0] bit 0.
//            Mirrors the BigInt encoding used by circom-ecdsa-p256.
// ---------------------------------------------------------------------------
template BitsToRegisters(n, k) {
    signal input  bits[256];  // SHA-256 output, bits[0] = most-significant bit
    signal output regs[k];

    component pack[k];
    for (var r = 0; r < k; r++) {
        pack[r] = Bits2Num(n);
        for (var i = 0; i < n; i++) {
            var bitPos = r * n + i;          // bit position from LSB of the 256-bit value
            if (bitPos < 256) {
                // bits[255 - bitPos]: convert from MSB-first to LSB-first
                pack[r].in[i] <== bits[255 - bitPos];
            } else {
                pack[r].in[i] <== 0;         // zero-pad the last register (bits 256+)
            }
        }
        regs[r] <== pack[r].out;
    }
}

// ---------------------------------------------------------------------------
// X509Parse — main parser template.
//
// maxTbsPadded must equal the next multiple of 64 ≥ (maxCertBytes - 16).
// For maxCertBytes=1500 use maxTbsPadded=1536.
// ---------------------------------------------------------------------------
template X509Parse(maxCertBytes, maxTbsPadded, n, k) {

    // === Inputs ===
    signal input certDer[maxCertBytes];  // DER-encoded certificate (zero-padded)
    signal input certLen;                // Actual byte count of certDer

    // === Prover-supplied structural hints (private) ===
    signal input tbsOffset;        // Byte offset of TBSCertificate SEQUENCE tag
    signal input tbsLen;           // Declared byte-length value from TBS DER header
    signal input spkiXOffset;      // Byte offset of the 32 X-coordinate bytes (after 0x04)
    signal input notBeforeOffset;  // Byte offset of notBefore UTCTime tag (0x17)
    signal input notAfterOffset;   // Byte offset of notAfter  UTCTime tag (0x17)

    // === Prover-supplied SHA-256 padding length and padded TBS buffer ===
    // tbsHashPaddedLen = actual padded byte length of the TBS slice, i.e. the
    // smallest multiple of 64 that is ≥ (4 + tbsLen).  This is verified below
    // by the Sha256Bytes constraint: the template enforces that paddedInLength
    // is a multiple of 512 bits.  Soundness: any incorrect value either fails
    // the hash (wrong digest) or fails to satisfy ECDSAVerifyNoPubkeyCheck.
    signal input tbsHashPaddedLen;

    // tbsHashPaddedBytes[maxTbsPadded]: the TBS DER bytes with SHA-256 padding
    // appended (0x80, zero bytes, 8-byte big-endian bit count), zero-filled to
    // maxTbsPadded bytes.  The circuit verifies bytes 0..(4+tbsLen) match the
    // corresponding bytes in certDer, so the prover cannot forge the TBS content.
    signal input tbsHashPaddedBytes[maxTbsPadded];

    // === Outputs ===
    signal output spkiX[k];           // ECDSA public key X as k n-bit registers
    signal output spkiY[k];           // ECDSA public key Y as k n-bit registers
    signal output tbsHashBits[256];   // SHA-256(TBSCertificate) as 256 bits
    signal output notBefore;          // notBefore as Unix timestamp (seconds)
    signal output notAfter;           // notAfter  as Unix timestamp (seconds)

    // =========================================================================
    // Structural verification
    // =========================================================================

    // (a) Outer Certificate SEQUENCE tag — index 0 is a compile-time constant.
    certDer[0] === 48;  // 0x30 = SEQUENCE

    // (b) TBSCertificate SEQUENCE tag at tbsOffset.
    component selTbsTag = SelectByte(maxCertBytes);
    for (var i = 0; i < maxCertBytes; i++) selTbsTag.bytes[i] <== certDer[i];
    selTbsTag.idx <== tbsOffset;
    selTbsTag.out === 48;  // 0x30 = SEQUENCE

    // (c) Two-byte length indicator 0x82 at tbsOffset+1.
    signal tbsOff1 <== tbsOffset + 1;
    component selTbsLenType = SelectByte(maxCertBytes);
    for (var i = 0; i < maxCertBytes; i++) selTbsLenType.bytes[i] <== certDer[i];
    selTbsLenType.idx <== tbsOff1;
    selTbsLenType.out === 130;  // 0x82 = two-byte length

    // (d) Length bytes at tbsOffset+2 and tbsOffset+3 encode tbsLen.
    signal tbsOff2 <== tbsOffset + 2;
    signal tbsOff3 <== tbsOffset + 3;

    component selTbsMSB = SelectByte(maxCertBytes);
    for (var i = 0; i < maxCertBytes; i++) selTbsMSB.bytes[i] <== certDer[i];
    selTbsMSB.idx <== tbsOff2;

    component selTbsLSB = SelectByte(maxCertBytes);
    for (var i = 0; i < maxCertBytes; i++) selTbsLSB.bytes[i] <== certDer[i];
    selTbsLSB.idx <== tbsOff3;

    signal declaredTbsLen <== selTbsMSB.out * 256 + selTbsLSB.out;
    declaredTbsLen === tbsLen;

    // (e) notBefore UTCTime tag (0x17) at notBeforeOffset.
    component selNbTag = SelectByte(maxCertBytes);
    for (var i = 0; i < maxCertBytes; i++) selNbTag.bytes[i] <== certDer[i];
    selNbTag.idx <== notBeforeOffset;
    selNbTag.out === 23;  // 0x17 = UTCTime

    // (f) notBefore length byte must be 0x0D (13 bytes: YYMMDDHHMMSSZ).
    signal nbLenOff <== notBeforeOffset + 1;
    component selNbLen = SelectByte(maxCertBytes);
    for (var i = 0; i < maxCertBytes; i++) selNbLen.bytes[i] <== certDer[i];
    selNbLen.idx <== nbLenOff;
    selNbLen.out === 13;

    // (g) notAfter UTCTime tag (0x17) at notAfterOffset.
    component selNaTag = SelectByte(maxCertBytes);
    for (var i = 0; i < maxCertBytes; i++) selNaTag.bytes[i] <== certDer[i];
    selNaTag.idx <== notAfterOffset;
    selNaTag.out === 23;  // 0x17 = UTCTime

    // (h) notAfter length byte must be 0x0D (13 bytes).
    signal naLenOff <== notAfterOffset + 1;
    component selNaLen = SelectByte(maxCertBytes);
    for (var i = 0; i < maxCertBytes; i++) selNaLen.bytes[i] <== certDer[i];
    selNaLen.idx <== naLenOff;
    selNaLen.out === 13;

    // (i) Uncompressed EC point marker 0x04 at spkiXOffset-1.
    signal spkiMarkerOff <== spkiXOffset - 1;
    component selMarker = SelectByte(maxCertBytes);
    for (var i = 0; i < maxCertBytes; i++) selMarker.bytes[i] <== certDer[i];
    selMarker.idx <== spkiMarkerOff;
    selMarker.out === 4;  // 0x04 = uncompressed point

    // =========================================================================
    // TBS SHA-256
    //
    // Verify that tbsHashPaddedBytes[0..(tbsLen+4)] equals the TBS DER region
    // in certDer (bytes tbsOffset .. tbsOffset+4+tbsLen), then hash the full
    // padded buffer in-circuit with Sha256Bytes(maxTbsPadded).
    //
    // Binding check: for each of the (4 + tbsLen) TBS DER bytes we use
    // SelectByte to read from certDer and assert equality with the corresponding
    // entry in tbsHashPaddedBytes.  This prevents a malicious prover from
    // supplying a tbsHashPaddedBytes that doesn't correspond to certDer.
    //
    // The SHA-256 padding bytes (beyond 4+tbsLen) are NOT verified — the
    // prover can set them to anything, but wrong padding produces a different
    // digest and the ECDSA check in Step 2 would fail.
    // =========================================================================

    // Binding: certDer[tbsOffset + i] === tbsHashPaddedBytes[i]
    // for i = 0 .. maxTbsPadded-1.
    // We use SelectByte for each position.  Positions beyond the cert are
    // zero (certDer is zero-padded), so the circuit enforces zero padding.
    component tbsBindSel[maxTbsPadded];
    for (var i = 0; i < maxTbsPadded; i++) {
        tbsBindSel[i] = SelectByte(maxCertBytes);
        for (var j = 0; j < maxCertBytes; j++) {
            tbsBindSel[i].bytes[j] <== certDer[j];
        }
        // Index = tbsOffset + i; clamp to certDer bound via SelectByte semantics.
        // When tbsOffset + i >= certLen, certDer is 0-padded so SelectByte returns 0.
        tbsBindSel[i].idx <== tbsOffset + i;
        // Only enforce equality for bytes that fall within the actual TBS DER region.
        // The remaining bytes are SHA-256 padding — not in certDer, prover-supplied.
        // We rely on Sha256Bytes's own enforcement + ECDSA for the padding bytes.
        // Enforce for all i: the binding is "certDer byte at tbsOffset+i equals
        // tbsHashPaddedBytes[i]".  For positions beyond certLen, certDer returns 0;
        // we do NOT enforce those positions so the prover can write padding there.
        // Implementation: enforce only for i < (4 + tbsLen).
        // Because tbsLen is a runtime signal, we use a conditional constraint:
        //   isTbsDerByte * (certDerByte - tbsHashPaddedBytes[i]) === 0
        // where isTbsDerByte = LessEqThan(12){in[0]=i, in[1]=tbsLen+3}.
    }
    // Build the conditional equality constraints.
    component tbsBindLe[maxTbsPadded];
    signal tbsBindEq[maxTbsPadded];
    for (var i = 0; i < maxTbsPadded; i++) {
        tbsBindLe[i] = LessEqThan(12);  // maxTbsPadded=1536 < 2^12=4096
        tbsBindLe[i].in[0] <== i;
        tbsBindLe[i].in[1] <== tbsLen + 3;  // 4+tbsLen-1 = tbsLen+3 (last valid index)
        // tbsBindLe[i].out == 1 iff i <= tbsLen + 3
        tbsBindEq[i] <== tbsBindLe[i].out * (tbsBindSel[i].out - tbsHashPaddedBytes[i]);
        tbsBindEq[i] === 0;
    }

    component tbsSha = Sha256Bytes(maxTbsPadded);
    for (var i = 0; i < maxTbsPadded; i++) {
        tbsSha.paddedIn[i] <== tbsHashPaddedBytes[i];
    }
    tbsSha.paddedInLength <== tbsHashPaddedLen;

    tbsHashBits <== tbsSha.out;

    // =========================================================================
    // Extract SPKI bytes and pack into BigInt registers
    // =========================================================================

    signal spkiRawBytes[64];
    component spkiSel[64];
    for (var i = 0; i < 64; i++) {
        spkiSel[i] = SelectByte(maxCertBytes);
        for (var j = 0; j < maxCertBytes; j++) {
            spkiSel[i].bytes[j] <== certDer[j];
        }
        spkiSel[i].idx <== spkiXOffset + i;
        spkiRawBytes[i] <== spkiSel[i].out;
    }

    signal xBytes[32];
    signal yBytes[32];
    for (var i = 0; i < 32; i++) {
        xBytes[i] <== spkiRawBytes[i];
        yBytes[i] <== spkiRawBytes[32 + i];
    }

    component xRegs = BytesToRegisters(n, k);
    for (var i = 0; i < 32; i++) xRegs.bytes[i] <== xBytes[i];
    spkiX <== xRegs.regs;

    component yRegs = BytesToRegisters(n, k);
    for (var i = 0; i < 32; i++) yRegs.bytes[i] <== yBytes[i];
    spkiY <== yRegs.regs;

    // =========================================================================
    // Parse notBefore and notAfter UTCTime → Unix timestamp
    //
    // UTCTime format (RFC 5280 §4.1.2.5.1): YYMMDDHHMMSSZ
    //   bytes[0..1] = YY  (2-digit year, 00-99; 00-49 → 2000+YY, 50-99 → 1900+YY)
    //   bytes[2..3] = MM  (month, 01-12)
    //   bytes[4..5] = DD  (day, 01-31)
    //   bytes[6..7] = HH  (hour, 00-23)
    //   bytes[8..9] = MM  (minute, 00-59)
    //   bytes[10..11] = SS (second, 00-59)
    //   bytes[12]   = 'Z' (0x5A)
    //
    // Conversion to Unix timestamp (simplified, ignoring leap seconds,
    // accurate for dates with regular day counts — sufficient for demo certs):
    //
    //   days_since_epoch = days_from_year_0_to_epoch
    //                    + days_in_years(year)
    //                    + days_in_months(year, month)
    //                    + (day - 1)
    //   unix_ts = days_since_epoch * 86400 + hh*3600 + mm*60 + ss
    //
    // We use a pre-computed days-per-month table (non-leap, adjust Feb for leap
    // years).  All arithmetic is small integers — well within the BN254 field.
    // =========================================================================

    // Read 12 bytes of notBefore (YY MM DD HH MM SS), skip the trailing 'Z'.
    signal nbRaw[12];
    component nbSel[12];
    for (var i = 0; i < 12; i++) {
        nbSel[i] = SelectByte(maxCertBytes);
        for (var j = 0; j < maxCertBytes; j++) {
            nbSel[i].bytes[j] <== certDer[j];
        }
        nbSel[i].idx <== notBeforeOffset + 2 + i;  // +2: skip tag + length byte
        nbRaw[i] <== nbSel[i].out;
    }

    // Read 12 bytes of notAfter.
    signal naRaw[12];
    component naSel[12];
    for (var i = 0; i < 12; i++) {
        naSel[i] = SelectByte(maxCertBytes);
        for (var j = 0; j < maxCertBytes; j++) {
            naSel[i].bytes[j] <== certDer[j];
        }
        naSel[i].idx <== notAfterOffset + 2 + i;
        naRaw[i] <== naSel[i].out;
    }

    // Convert ASCII digit pairs to integers: digit value = byte - 48 ('0')
    // Each two-digit field d0d1 = (byte[i]-48)*10 + (byte[i+1]-48).
    component nbTs = UTCTimeToUnix();
    for (var i = 0; i < 12; i++) { nbTs.raw[i] <== nbRaw[i]; }
    notBefore <== nbTs.ts;

    component naTs = UTCTimeToUnix();
    for (var i = 0; i < 12; i++) { naTs.raw[i] <== naRaw[i]; }
    notAfter <== naTs.ts;
}

// ---------------------------------------------------------------------------
// UTCTimeToUnix — convert 12 ASCII bytes (YYMMDDHHMMSS, no trailing Z) to a
// Unix timestamp (seconds since 1970-01-01T00:00:00Z).
//
// Year interpretation: YY 00-49 → 2000+YY, 50-99 → 1900+YY (RFC 5280).
// Leap-year calculation: year divisible by 4 (and not by 100, or by 400).
// For certificate dates between 2000 and 2049 (YY=00..49), only the
// divisible-by-4 rule matters — no century adjustments needed.
//
// Days-per-month for non-leap years: [31,28,31,30,31,30,31,31,30,31,30,31]
// Feb in a leap year contributes 29 days.
//
// This template uses only arithmetic constraints — no lookup tables needed.
// ---------------------------------------------------------------------------
template UTCTimeToUnix() {
    signal input raw[12];   // ASCII bytes: YY MM DD HH MM SS
    signal output ts;       // Unix timestamp

    // Extract digit pairs.
    signal yy  <== (raw[0]  - 48) * 10 + (raw[1]  - 48);
    signal mm  <== (raw[2]  - 48) * 10 + (raw[3]  - 48);
    signal dd  <== (raw[4]  - 48) * 10 + (raw[5]  - 48);
    signal hh  <== (raw[6]  - 48) * 10 + (raw[7]  - 48);
    signal min <== (raw[8]  - 48) * 10 + (raw[9]  - 48);
    signal ss  <== (raw[10] - 48) * 10 + (raw[11] - 48);

    // Full 4-digit year: YY < 50 → 2000+YY, else 1900+YY.
    // Equivalently: year = 1900 + yy + (yy < 50 ? 100 : 0).
    // We compute the conditional via: lt50 ∈ {0,1}, year = 1900 + yy + 100*lt50.
    component lt50 = LessThan(7);  // 7 bits enough for values 0..99
    lt50.in[0] <== yy;
    lt50.in[1] <== 50;
    signal year <== 1900 + yy + 100 * lt50.out;

    // Days from 1970-01-01 to Jan 1 of `year`.
    // = 365 * (year-1970) + leap_days_since_1970
    // leap_days_since_1970 = floor((year-1-1968)/4) - floor((year-1-1900)/100) + floor((year-1-1600)/400)
    // For years 2000-2049: century/400 terms evaluate to constants (19/1 respectively),
    // simplifying to: leap_days = floor((year-1-1968)/4) - 24 + 5 = floor((year-1-1968)/4) - 19
    // We use the prover-hint pattern: prover supplies leapQuot = floor((year-1968)/4),
    // circuit verifies: 4*leapQuot <= year-1968 < 4*(leapQuot+1).

    // Days from epoch to Jan 1 of year (ignoring leap correction for now):
    signal yearsAfter1970 <== year - 1970;

    // Leap years since 1970 up to (but not including) `year`.
    // A year Y is a leap year if Y%4==0 and (Y%100!=0 or Y%400==0).
    // Between 2000 and 2049: all multiples of 4 are leap (no century exception).
    // Leap years before `year` since 1970: floor((year - 1969) / 4).
    // 1972 is the first leap year after 1970: (1972-1969)=3, floor(3/4)=0 — wrong.
    // Correct formula: floor((year - 1) / 4) - floor(1969/4) = floor((year-1)/4) - 492.
    // Prover supplies leapDays as a hint; we verify with range check.
    signal leapDaysBefore;
    leapDaysBefore <-- (year - 1) \ 4 - 492;
    // Verify: 4*(leapDaysBefore+492) <= year-1 < 4*(leapDaysBefore+493)
    signal leapBase <== leapDaysBefore + 492;
    signal r0 <== 4 * leapBase;
    signal r1 <== 4 * (leapBase + 1);
    component chkLo = LessEqThan(18);
    chkLo.in[0] <== r0;
    chkLo.in[1] <== year - 1;
    chkLo.out === 1;
    component chkHi = LessThan(18);
    chkHi.in[0] <== year - 1;
    chkHi.in[1] <== r1;
    chkHi.out === 1;

    signal daysToYearStart <== yearsAfter1970 * 365 + leapDaysBefore;

    // Is the current year a leap year?  year%4==0 and (year%100!=0 or year%400==0).
    // For 2000-2049: leap iff year%4==0.
    signal yearMod4;
    yearMod4 <-- year % 4;
    signal yearDiv4;
    yearDiv4 <-- year \ 4;
    yearDiv4 * 4 + yearMod4 === year;
    component yearMod4Zero = IsZero();
    yearMod4Zero.in <== yearMod4;
    signal isLeap <== yearMod4Zero.out;  // 1 if leap, 0 otherwise

    // Cumulative days at start of each month (1-indexed), non-leap year.
    // cumDays[m] = days elapsed before month m+1 (0-indexed), for m in 1..12.
    // Jan=0, Feb=31, Mar=59, Apr=90, May=120, Jun=151,
    // Jul=181, Aug=212, Sep=243, Oct=273, Nov=304, Dec=334
    var cumDaysNonLeap[13];
    cumDaysNonLeap[0]  = 0;
    cumDaysNonLeap[1]  = 31;
    cumDaysNonLeap[2]  = 59;
    cumDaysNonLeap[3]  = 90;
    cumDaysNonLeap[4]  = 120;
    cumDaysNonLeap[5]  = 151;
    cumDaysNonLeap[6]  = 181;
    cumDaysNonLeap[7]  = 212;
    cumDaysNonLeap[8]  = 243;
    cumDaysNonLeap[9]  = 273;
    cumDaysNonLeap[10] = 304;
    cumDaysNonLeap[11] = 334;
    cumDaysNonLeap[12] = 365;

    // Select cumulative days for month `mm` (1-indexed) using a mux.
    // Also add 1 to Feb's offset when it's a leap year and mm > 2.
    signal monthMux[13];
    component mmEq[13];
    for (var m = 0; m <= 12; m++) {
        mmEq[m] = IsEqual();
        mmEq[m].in[0] <== mm;
        mmEq[m].in[1] <== m;
        monthMux[m] <== mmEq[m].out * cumDaysNonLeap[m];
    }
    signal daysToMonthStart <== monthMux[0] + monthMux[1] + monthMux[2] +
        monthMux[3] + monthMux[4] + monthMux[5] + monthMux[6] +
        monthMux[7] + monthMux[8] + monthMux[9] + monthMux[10] +
        monthMux[11] + monthMux[12];

    // Leap correction: add 1 day if isLeap and mm > 2 (past Feb).
    component gtFeb = GreaterThan(4);
    gtFeb.in[0] <== mm;
    gtFeb.in[1] <== 2;
    signal leapAdj <== isLeap * gtFeb.out;

    // Total days since epoch to midnight of this date.
    signal daysTotal <== daysToYearStart + daysToMonthStart + leapAdj + (dd - 1);

    // Convert to seconds.
    ts <== daysTotal * 86400 + hh * 3600 + min * 60 + ss;
}
