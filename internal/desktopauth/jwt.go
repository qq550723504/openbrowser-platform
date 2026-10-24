package desktopauth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"time"
	"unicode"
)

type jwk struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Alg string   `json:"alg"`
	Use string   `json:"use"`
	Ops []string `json:"key_ops"`
	N   string   `json:"n"`
	E   string   `json:"e"`
}

type jwtHeader struct {
	Alg  string          `json:"alg"`
	Kid  string          `json:"kid"`
	Typ  string          `json:"typ"`
	Crit json.RawMessage `json:"crit"`
	B64  json.RawMessage `json:"b64"`
}

type claims struct {
	Issuer          string          `json:"iss"`
	Subject         string          `json:"sub"`
	Audience        json.RawMessage `json:"aud"`
	AuthorizedParty string          `json:"azp"`
	Nonce           string          `json:"nonce"`
	Expires         int64           `json:"exp"`
	Issued          int64           `json:"iat"`
	NotBefore       int64           `json:"nbf"`
}

func verifyIDToken(raw, nonce string, cfg Config, keyset []byte, now time.Time) (Identity, time.Time, error) {
	fail := func() (Identity, time.Time, error) { return Identity{}, time.Time{}, ErrLogin }
	if len(raw) > 32768 {
		return fail()
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return fail()
	}
	h, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fail()
	}
	var header jwtHeader
	if strictJSON(h, &header) != nil || header.Alg != "RS256" || header.Kid == "" || len(header.Kid) > 200 ||
		(header.Typ != "" && header.Typ != "JWT") || len(header.Crit) != 0 || len(header.B64) != 0 {
		return fail()
	}
	var keys struct {
		Keys []jwk `json:"keys"`
	}
	if strictJSON(keyset, &keys) != nil || len(keys.Keys) > 100 {
		return fail()
	}
	var key *rsa.PublicKey
	for _, candidate := range keys.Keys {
		if candidate.Kid != header.Kid {
			continue
		}
		if key != nil || candidate.Kty != "RSA" || (candidate.Alg != "" && candidate.Alg != "RS256") ||
			(candidate.Use != "" && candidate.Use != "sig") || (len(candidate.Ops) > 0 && !contains(candidate.Ops, "verify")) {
			return fail()
		}
		n, e1 := base64.RawURLEncoding.DecodeString(candidate.N)
		e, e2 := base64.RawURLEncoding.DecodeString(candidate.E)
		if e1 != nil || e2 != nil || len(e) == 0 || len(e) > 4 {
			return fail()
		}
		exponent := new(big.Int).SetBytes(e).Int64()
		modulus := new(big.Int).SetBytes(n)
		if exponent < 3 || exponent > 2147483647 || exponent%2 == 0 || modulus.BitLen() < 2048 || modulus.BitLen() > 8192 {
			return fail()
		}
		key = &rsa.PublicKey{N: modulus, E: int(exponent)}
	}
	if key == nil {
		return fail()
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fail()
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return fail()
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fail()
	}
	var c claims
	if strictJSON(payload, &c) != nil || c.Issuer != cfg.Issuer || c.Subject == "" || len(c.Subject) > 255 ||
		strings.ContainsFunc(c.Subject, unicode.IsControl) || subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(nonce)) != 1 ||
		c.Expires <= now.Unix() || c.Issued <= 0 || c.Issued > now.Unix()+30 || c.Issued >= c.Expires || c.NotBefore > now.Unix() {
		return fail()
	}
	var audience []string
	var single string
	if json.Unmarshal(c.Audience, &single) == nil {
		audience = []string{single}
	} else if json.Unmarshal(c.Audience, &audience) != nil {
		return fail()
	}
	if !contains(audience, cfg.ClientID) || (len(audience) > 1 && c.AuthorizedParty != cfg.ClientID) ||
		(c.AuthorizedParty != "" && c.AuthorizedParty != cfg.ClientID) {
		return fail()
	}
	return Identity{Issuer: c.Issuer, Subject: c.Subject}, time.Unix(c.Expires, 0), nil
}
