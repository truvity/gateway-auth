package gatewayauth

import (
	"github.com/lestrrat-go/jwx/v4/jwt"
)

// ClaimsMapper names the claims an Identity is built from. The zero value uses
// the OIDC-standard names with "groups" for roles — the fleet's rbac-mapper
// claim. Another provider can point RolesClaim at "roles" or "realm_access".
type ClaimsMapper struct {
	NameClaim  string
	EmailClaim string
	RolesClaim string
}

func (m ClaimsMapper) withDefaults() ClaimsMapper {
	if m.NameClaim == "" {
		m.NameClaim = "name"
	}

	if m.EmailClaim == "" {
		m.EmailClaim = "email"
	}

	if m.RolesClaim == "" {
		m.RolesClaim = "groups"
	}

	return m
}

// identity reads the claims a service cares about off a verified token.
//
// Claims are read one at a time rather than into a struct, because the roles
// claim is named by configuration and because providers disagree about whether
// a single group arrives as a string or a one-element array.
func (m ClaimsMapper) identity(token jwt.Token, raw string) Identity {
	m = m.withDefaults()
	subject, _ := token.Subject()

	return Identity{
		Subject: subject,
		Name:    stringClaim(token, m.NameClaim),
		Email:   stringClaim(token, m.EmailClaim),
		Roles:   claimValues(token, m.RolesClaim),
		Token:   raw,
		Claims:  claimsMap(token),
	}
}

// claimsMap materializes every claim, so a service can read app-specific ones
// (an emp:{slug}, a tenant id) the typed fields do not cover.
func claimsMap(token jwt.Token) map[string]any {
	keys := token.Keys()
	if len(keys) == 0 {
		return nil
	}

	out := make(map[string]any, len(keys))

	for _, key := range keys {
		if value, ok := token.Field(key); ok {
			out[key] = value
		}
	}

	return out
}

func stringClaim(token jwt.Token, name string) string {
	raw, ok := token.Field(name)
	if !ok {
		return ""
	}

	value, _ := raw.(string)

	return value
}

// claimValues reads a claim that may be a string or an array of strings, and
// returns nothing for anything else. Getting this wrong silently strips
// everyone's role, so both shapes are handled explicitly.
func claimValues(token jwt.Token, name string) []string {
	raw, ok := token.Field(name)
	if !ok {
		return nil
	}

	return stringsFrom(raw)
}

// stringsFrom normalizes the shapes a roles claim arrives in. A decoded JWT
// yields []any for arrays, but a caller constructing a token by hand — the
// tests do — produces []string.
func stringsFrom(raw any) []string {
	switch value := raw.(type) {
	case string:
		return []string{value}
	case []string:
		return value
	case []any:
		values := make([]string, 0, len(value))

		for _, item := range value {
			if s, ok := item.(string); ok {
				values = append(values, s)
			}
		}

		return values
	default:
		return nil
	}
}
