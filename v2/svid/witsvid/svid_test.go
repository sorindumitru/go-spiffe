package witsvid_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/witsvid"
	"github.com/stretchr/testify/require"
)

var (
	key1, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
)

func TestMarshal(t *testing.T) {
	// Generate trust domain
	trustDomain1 := spiffeid.RequireTrustDomainFromString("trustdomain")

	// Generate Token
	claims := jwt.Claims{
		Subject: spiffeid.RequireFromPath(trustDomain1, "/host").String(),
		Issuer:  "issuer",
		Expiry:  jwt.NewNumericDate(time.Now()),
	}
	token := generateToken(t, claims, key1, "key1")

	// Create SVID
	svid, err := witsvid.ParseInsecure(token)
	require.NoError(t, err)
	// Validate token is returned
	require.Equal(t, token, svid.Marshal())

	// Update SVID does not affect token
	svid.ID = spiffeid.RequireFromPath(trustDomain1, "/host2")
	require.Equal(t, token, svid.Marshal())

	// Empty Marshall when no token
	svid = &witsvid.SVID{}
	require.Empty(t, svid.Marshal())
}

// Generate generates a signed string token
func generateToken(tb testing.TB, claims jwt.Claims, signer crypto.Signer, keyID string) string {
	// Get signer algorithm
	alg, err := getSignerAlgorithm(signer)
	require.NoError(tb, err)

	// Create signer using crypto.Signer and its algorithm along with provided key ID
	jwtSigner, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: alg,
			Key: jose.JSONWebKey{
				Key:   cryptosigner.Opaque(signer),
				KeyID: keyID,
			},
		},
		new(jose.SignerOptions).WithType("JWT"),
	)
	require.NoError(tb, err)

	// Sign and serialize token
	token, err := jwt.Signed(jwtSigner).Claims(claims).Serialize()
	require.NoError(tb, err)

	return token
}

// getSignerAlgorithm deduces signer algorithm and return it
func getSignerAlgorithm(signer crypto.Signer) (jose.SignatureAlgorithm, error) {
	switch publicKey := signer.Public().(type) {
	case *rsa.PublicKey:
		// Prevent the use of keys smaller than 2048 bits
		if publicKey.Size() < 256 {
			return "", fmt.Errorf("unsupported RSA key size: %d", publicKey.Size())
		}
		return jose.RS256, nil
	case *ecdsa.PublicKey:
		params := publicKey.Params()
		switch params.BitSize {
		case 256:
			return jose.ES256, nil
		case 384:
			return jose.ES384, nil
		default:
			return "", fmt.Errorf("unable to determine signature algorithm for EC public key size %d", params.BitSize)
		}
	case ed25519.PublicKey:
		return jose.EdDSA, nil
	default:
		return "", fmt.Errorf("unable to determine signature algorithm for public key type %T", publicKey)
	}
}
