pragma circom 2.1.6;

// Local copy of Sha256Bytes + Sha256General from @zk-email/circuits/lib/sha.circom,
// with the "include ./fp.circom" line removed.
//
// fp.circom (field arithmetic) is not used by Sha256Bytes but its transitive
// dependency on bigint-func.circom conflicts with bigint_func.circom from
// circom-ecdsa-p256/circom-pairing — both define the same function names
// (div_ceil, log_ceil, long_gt, etc.).  Circom has no include guards so the
// duplicate definitions cause a T2008 compile error.  Removing fp.circom
// resolves the conflict; the SHA-256 templates themselves do not use it.

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/sha256/constants.circom";
include "circomlib/circuits/sha256/sha256compression.circom";
include "circomlib/circuits/comparators.circom";
include "@zk-email/circuits/utils/array.circom";
include "@zk-email/circuits/utils/functions.circom";

/// Sha256Bytes — compute SHA-256 over pre-padded byte input.
/// Identical to @zk-email/circuits/lib/sha.circom :: Sha256Bytes.
///
/// @input  paddedIn[maxByteLength]  Pre-padded message bytes (SHA-256 padding applied by prover)
/// @input  paddedInLength           Byte length of the padded message (multiple of 64)
/// @output out[256]                 SHA-256 digest bits, MSB first (out[0] = MSB)
template Sha256Bytes(maxByteLength) {
    signal input paddedIn[maxByteLength];
    signal input paddedInLength;
    signal output out[256];

    var maxBits = maxByteLength * 8;
    component sha = Sha256General(maxBits);

    component bytes[maxByteLength];
    for (var i = 0; i < maxByteLength; i++) {
        bytes[i] = Num2Bits(8);
        bytes[i].in <== paddedIn[i];
        for (var j = 0; j < 8; j++) {
            sha.paddedIn[i*8+j] <== bytes[i].out[7-j];
        }
    }
    sha.paddedInLength <== paddedInLength * 8;

    for (var i = 0; i < 256; i++) {
        out[i] <== sha.out[i];
    }
}

/// Sha256General — variable-length SHA-256 over pre-padded bit input.
/// Adapted from @zk-email/circuits/lib/sha.circom :: Sha256General.
/// maxBitLength must be a multiple of 512.
template Sha256General(maxBitLength) {
    assert(maxBitLength % 512 == 0);

    var maxBitsPaddedBits = log2Ceil(maxBitLength);

    signal input paddedIn[maxBitLength];
    signal input paddedInLength;
    signal output out[256];

    signal inBlockIndex;

    var i;
    var k;
    var j;
    var maxBlocks;
    maxBlocks = (maxBitLength\512);

    inBlockIndex <-- (paddedInLength >> 9);
    paddedInLength === inBlockIndex * 512;

    component bitLengthVerifier = LessEqThan(maxBitsPaddedBits);
    bitLengthVerifier.in[0] <== paddedInLength;
    bitLengthVerifier.in[1] <== maxBitLength;
    bitLengthVerifier.out === 1;

    component ha0 = H(0);
    component hb0 = H(1);
    component hc0 = H(2);
    component hd0 = H(3);
    component he0 = H(4);
    component hf0 = H(5);
    component hg0 = H(6);
    component hh0 = H(7);

    component sha256compression[maxBlocks];

    for (i=0; i<maxBlocks; i++) {
        sha256compression[i] = Sha256compression();

        if (i==0) {
            for (k=0; k<32; k++) {
                sha256compression[i].hin[0*32+k] <== ha0.out[k];
                sha256compression[i].hin[1*32+k] <== hb0.out[k];
                sha256compression[i].hin[2*32+k] <== hc0.out[k];
                sha256compression[i].hin[3*32+k] <== hd0.out[k];
                sha256compression[i].hin[4*32+k] <== he0.out[k];
                sha256compression[i].hin[5*32+k] <== hf0.out[k];
                sha256compression[i].hin[6*32+k] <== hg0.out[k];
                sha256compression[i].hin[7*32+k] <== hh0.out[k];
            }
        } else {
            for (k=0; k<32; k++) {
                sha256compression[i].hin[32*0+k] <== sha256compression[i-1].out[32*0+31-k];
                sha256compression[i].hin[32*1+k] <== sha256compression[i-1].out[32*1+31-k];
                sha256compression[i].hin[32*2+k] <== sha256compression[i-1].out[32*2+31-k];
                sha256compression[i].hin[32*3+k] <== sha256compression[i-1].out[32*3+31-k];
                sha256compression[i].hin[32*4+k] <== sha256compression[i-1].out[32*4+31-k];
                sha256compression[i].hin[32*5+k] <== sha256compression[i-1].out[32*5+31-k];
                sha256compression[i].hin[32*6+k] <== sha256compression[i-1].out[32*6+31-k];
                sha256compression[i].hin[32*7+k] <== sha256compression[i-1].out[32*7+31-k];
            }
        }

        for (k=0; k<512; k++) {
            sha256compression[i].inp[k] <== paddedIn[i*512+k];
        }
    }

    component arraySelectors[256];
    for (k=0; k<256; k++) {
        arraySelectors[k] = ItemAtIndex(maxBlocks);
        for (j=0; j<maxBlocks; j++) {
            arraySelectors[k].in[j] <== sha256compression[j].out[k];
        }
        arraySelectors[k].index <== inBlockIndex - 1;
        out[k] <== arraySelectors[k].out;
    }
}
