package statement

// Sizes are the circuit's maximum input lengths (THIRD-PARTY-STATEMENT.md,
// Q4). Hashing costs follow the maxima, not the actual lengths; inputs over a
// limit are refused.
type Sizes struct {
	MaxProtected  int // the original protected header (holds x5chain)
	MaxClaim      int // the claim
	MaxTBS        int // the signer certificate's TBSCertificate, DER header included
	MaxExtensions int // certificate extensions walked
	MaxEKUs       int // purposes in the extended key usage extension
}

// DefaultSizes are the limits proposed in E2a: protected header 2 KB, claim
// 1 KB, signer TBS 1 KB. A real device-signed asset has a 1,528-byte
// protected header, a 377-byte claim, and a 661-byte TBS with 8 extensions.
var DefaultSizes = Sizes{MaxProtected: 2048, MaxClaim: 1024, MaxTBS: 1024, MaxExtensions: 16, MaxEKUs: 8}

// Fixed layout of the hashed structures. The claim signature's Sig_structure
// is ["Signature1", P, h'', claim]:
//
//	84 6A "Signature1"   59 Lp Lp   P   40   58 Lc | 59 Lc Lc   claim
//
// and the protected header P is {1: -7, 33: [signer certificate, ...]}:
//
//	A2 01 26 18 21 8n 59 Ll Ll   30 82 .. ..   30 82 .. ..   (TBSCertificate)
//
// so the signer certificate and its TBS start at fixed offsets. Both real
// device-signed assets and c2pa-rs produce exactly this encoding; others are
// refused. The time stamp's countersignature structure (v2) is
// ["CounterSignature", P, h'', bstr(bstr(signature))]:
//
//	84 70 "CounterSignature"   59 Lp Lp   P   40   58 42 58 40 (r || s)
const (
	sigPrefixLen      = 12 // 84 6A "Signature1"
	protectedOffset   = 15 // after the protected header's 59 Lp Lp
	leafOffset        = protectedOffset + 9
	tbsOffset         = leafOffset + 4
	tbsContentOffset  = tbsOffset + 4
	csPrefixLen       = 18 // 84 70 "CounterSignature"
	csProtectedOffset = 21
	csTailLen         = 5 + 64
	signatureLen      = 64 // ES256: r || s
	claimChunk        = 31 // claim bytes per public field element
	spkiLen           = 91 // a P-256 SubjectPublicKeyInfo
)

var (
	sigContext = append([]byte{0x84, 0x6a}, "Signature1"...)
	csContext  = append([]byte{0x84, 0x70}, "CounterSignature"...)
	// The protected header's start: a map of two entries, alg (1) = ES256
	// (-7), then x5chain (33) as an array (the count byte follows).
	protectedStart = []byte{0xa2, 0x01, 0x26, 0x18, 0x21}
	// TBSCertificate version [0] EXPLICIT INTEGER 2 (v3).
	tbsVersion = []byte{0xa0, 0x03, 0x02, 0x01, 0x02}
	// The DER prefix of a P-256 SubjectPublicKeyInfo, up to the key's X and Y.
	p256SPKIPrefix = []byte{
		0x30, 0x59, 0x30, 0x13,
		0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
		0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
		0x03, 0x42, 0x00, 0x04,
	}
	oidExtKeyUsage      = []byte{0x55, 0x1d, 0x25} // 2.5.29.37
	oidBasicConstraints = []byte{0x55, 0x1d, 0x13} // 2.5.29.19
	// 1.3.6.1.4.1.62558.2.1, C2PA claim signing.
	oidClaimSigning = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xe8, 0x5e, 0x02, 0x01}
)

func (s Sizes) sigStructureLen() int { return protectedOffset + s.MaxProtected + 1 + 3 + s.MaxClaim }
func (s Sizes) countersignatureLen() int {
	return csProtectedOffset + s.MaxProtected + csTailLen
}
func (s Sizes) claimElements() int { return (s.MaxClaim + claimChunk - 1) / claimChunk }
