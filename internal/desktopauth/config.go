// Package desktopauth implements an in-memory, fail-closed native OIDC client.
// It deliberately supports only authorization code + S256 PKCE and RS256 ID tokens.
package desktopauth

import (
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode"
)

var (
	ErrUnauthenticated = errors.New("authentication_required")
	ErrConfiguration   = errors.New("identity_configuration_required")
	ErrLogin           = errors.New("identity_login_failed")
	ErrCancelled       = errors.New("identity_login_cancelled")
)

// Config contains public client metadata only. No secret or skip-login flag exists.
type Config struct {
	Issuer   string
	ClientID string
}

func (c Config) valid() bool { return len(c.ConfigurationIssues()) == 0 }

// ConfigurationIssues names public configuration problems without echoing values.
func (c Config) ConfigurationIssues() []string {
	issues := []string{}
	if c.Issuer == "" {
		issues = append(issues, "identity_issuer_required")
	} else if !secureURL(c.Issuer) {
		issues = append(issues, "identity_issuer_invalid")
	}
	if c.ClientID == "" {
		issues = append(issues, "identity_client_id_required")
	} else if len(c.ClientID) > 256 || strings.TrimSpace(c.ClientID) != c.ClientID || strings.ContainsFunc(c.ClientID, unicode.IsControl) {
		issues = append(issues, "identity_client_id_invalid")
	}
	return issues
}

func secureURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil &&
		u.RawQuery == "" && u.Fragment == "" && u.Opaque == "" && !strings.ContainsFunc(raw, unicode.IsControl)
}

// Status is the only authentication DTO exposed to the renderer. Never add tokens.
type Status struct {
	Generation uint64    `json:"generation"`
	State      string    `json:"state"`
	Configured bool      `json:"configured"`
	Subject    string    `json:"subject,omitempty"`
	Issuer     string    `json:"issuer,omitempty"`
	ExpiresAt  time.Time `json:"expiresAt,omitempty"`
	ErrorCode  string    `json:"errorCode,omitempty"`
	APIGranted bool      `json:"apiGranted"`
}

// Identity is verified server-side and never accepted from renderer input.
type Identity struct {
	Issuer  string
	Subject string
}

type discovery struct {
	Issuer           string   `json:"issuer"`
	Authorization    string   `json:"authorization_endpoint"`
	Token            string   `json:"token_endpoint"`
	JWKS             string   `json:"jwks_uri"`
	Challenges       []string `json:"code_challenge_methods_supported"`
	Signing          []string `json:"id_token_signing_alg_values_supported"`
	ResponseTypes    []string `json:"response_types_supported"`
	GrantTypes       []string `json:"grant_types_supported"`
	TokenAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func (d discovery) valid(c Config) bool {
	return d.Issuer == c.Issuer && secureURL(d.Authorization) && secureURL(d.Token) && secureURL(d.JWKS) &&
		contains(d.Challenges, "S256") && contains(d.Signing, "RS256") && contains(d.ResponseTypes, "code")
}
