package witsvid

import (
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/zeebo/errs"
)

var (
	allowedSignatureAlgorithms = []jose.SignatureAlgorithm{
		jose.RS256,
		jose.RS384,
		jose.RS512,
		jose.ES256,
		jose.ES384,
		jose.ES512,
		jose.PS256,
		jose.PS384,
		jose.PS512,
	}

	witsvidErr = errs.Class("witsvid")
)

// tokenValidator validates the token and returns the claims
type tokenValidator = func(*jwt.JSONWebToken, spiffeid.TrustDomain) (map[string]interface{}, error)

// SVID represents a WIT-SVID.
type SVID struct {
	// ID is the SPIFFE ID of the WIT-SVID as present in the 'sub' claim
	ID spiffeid.ID
	// Expiry is the expiration time of WIT-SVID as present in 'exp' claim
	Expiry time.Time
	// Claims is the parsed claims from token
	Claims map[string]interface{}
	// Hint is an operator-specified string used to provide guidance on how this
	// identity should be used by a workload when more than one SVID is returned.
	Hint string

	// token is the serialized WIT token
	token string
}

// ParseAndValidate parses and validates a WIT-SVID token and returns the
// WIT-SVID. The WIT-SVID signature is verified using the JWT bundle source.
func ParseAndValidate(token string, bundles jwtbundle.Source) (*SVID, error) {
	return parse(token, func(tok *jwt.JSONWebToken, trustDomain spiffeid.TrustDomain) (map[string]interface{}, error) {
		// Obtain the key ID from the header
		keyID := tok.Headers[0].KeyID
		if keyID == "" {
			return nil, witsvidErr.New("token header missing key id")
		}

		// Get JWT Bundle
		bundle, err := bundles.GetJWTBundleForTrustDomain(trustDomain)
		if err != nil {
			return nil, witsvidErr.New("no bundle found for trust domain %q", trustDomain)
		}

		// Find JWT authority using the key ID from the token header
		authority, ok := bundle.FindJWTAuthority(keyID)
		if !ok {
			return nil, witsvidErr.New("no JWT authority %q found for trust domain %q", keyID, trustDomain)
		}

		// Obtain and verify the token claims using the obtained JWT authority
		claimsMap := make(map[string]interface{})
		if err := tok.Claims(authority, &claimsMap); err != nil {
			return nil, witsvidErr.New("unable to get claims from token: %v", err)
		}

		return claimsMap, nil
	})
}

// ParseInsecure parses and validates a WIT-SVID token and returns the
// WIT-SVID. The WIT-SVID signature is not verified.
func ParseInsecure(token string) (*SVID, error) {
	return parse(token, func(tok *jwt.JSONWebToken, td spiffeid.TrustDomain) (map[string]interface{}, error) {
		// Obtain the token claims insecurely, i.e. without signature verification
		claimsMap := make(map[string]interface{})
		if err := tok.UnsafeClaimsWithoutVerification(&claimsMap); err != nil {
			return nil, witsvidErr.New("unable to get claims from token: %v", err)
		}

		return claimsMap, nil
	})
}

// Marshal returns the WIT-SVID marshaled to a string. The returned value is
// the same token value originally passed to ParseAndValidate.
func (svid *SVID) Marshal() string {
	return svid.token
}

func parse(token string, getClaims tokenValidator) (*SVID, error) {
	// Parse serialized token
	tok, err := jwt.ParseSigned(token, allowedSignatureAlgorithms)
	if err != nil {
		return nil, witsvidErr.New("unable to parse WIT token")
	}

	// Parse out the unverified claims. We need to look up the key by the trust
	// domain of the SPIFFE ID.
	var claims jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, witsvidErr.New("unable to get claims from token: %v", err)
	}

	switch {
	case claims.Subject == "":
		return nil, witsvidErr.New("token missing subject claim")
	case claims.Expiry == nil:
		return nil, witsvidErr.New("token missing exp claim")
	}

	spiffeID, err := spiffeid.FromString(claims.Subject)
	if err != nil {
		return nil, witsvidErr.New("token has an invalid subject claim: %v", err)
	}

	// Create generic map of claims
	claimsMap, err := getClaims(tok, spiffeID.TrustDomain())
	if err != nil {
		return nil, err
	}

	// Validate the standard claims.
	if err := claims.Validate(jwt.Expected{
		Time: time.Now(),
	}); err != nil {
		// Convert expected validation errors for pretty errors
		switch err {
		case jwt.ErrExpired:
			err = witsvidErr.New("token has expired")
		}
		return nil, err
	}

	return &SVID{
		ID:     spiffeID,
		Expiry: claims.Expiry.Time().UTC(),
		Claims: claimsMap,
		token:  token,
	}, nil
}
