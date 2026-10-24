package desktopauth

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestJWTRejectsSignatureAlgorithmAndAmbiguousDocuments(t *testing.T) {
	key := fixtureKey(t)
	now := time.Now()
	cfg := Config{Issuer: "https://issuer.example", ClientID: "desktop"}
	c := map[string]any{"iss": cfg.Issuer, "sub": "one", "aud": cfg.ClientID, "nonce": "nonce", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	keys, _ := json.Marshal(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "fixture-key", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	valid := signJWT(key, c)
	if _, _, err := verifyIDToken(valid, "nonce", cfg, keys, now); err != nil {
		t.Fatal("valid fixture token rejected")
	}
	parts := strings.Split(valid, ".")
	badSignature := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString([]byte("bad-signature"))
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"fixture-key"}`)) + "." + parts[1] + "."
	for _, raw := range []string{badSignature, none, strings.Repeat("x", 33000), "not.jwt"} {
		if _, _, err := verifyIDToken(raw, "nonce", cfg, keys, now); err == nil {
			t.Fatal("invalid signature/algorithm accepted")
		}
	}
	for _, raw := range []string{`{"issuer":"one","issuer":"two"}`, `{"outer":{"a":1,"a":2}}`, `{} {}`, `{"x":[1,]}`} {
		var v any
		if strictJSON([]byte(raw), &v) == nil {
			t.Fatal("ambiguous JSON accepted")
		}
	}
}
