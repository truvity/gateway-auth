package gatewayauth

import (
	"reflect"
	"testing"
)

// stringsFrom normalizes the shapes a roles claim arrives in. A decoded JWT
// yields []any for arrays; a hand-built token yields []string. Getting this
// wrong silently strips everyone's role, so every shape is pinned down.
func TestStringsFrom(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  any
		want []string
	}{
		{"absent", nil, nil},
		{"single string", "a", []string{"a"}},
		{"string slice", []string{"a", "b"}, []string{"a", "b"}},
		{"decoded JSON array", []any{"a", "b"}, []string{"a", "b"}},
		{"array with a non-string entry", []any{"a", 42}, []string{"a"}},
		{"empty array", []any{}, []string{}},
		{"a number is not a role", 42, nil},
		{"an object is not a role", map[string]any{"a": 1}, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := stringsFrom(tc.raw); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("stringsFrom(%#v) = %#v, want %#v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestClaimsMapperWithDefaults(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   ClaimsMapper
		want ClaimsMapper
	}{
		{
			name: "zero value uses OIDC names with groups for roles",
			in:   ClaimsMapper{},
			want: ClaimsMapper{NameClaim: "name", EmailClaim: "email", RolesClaim: "groups"},
		},
		{
			name: "explicit values are kept",
			in:   ClaimsMapper{NameClaim: "display", EmailClaim: "mail", RolesClaim: "roles"},
			want: ClaimsMapper{NameClaim: "display", EmailClaim: "mail", RolesClaim: "roles"},
		},
		{
			name: "partial override fills only the gaps",
			in:   ClaimsMapper{RolesClaim: "realm_access"},
			want: ClaimsMapper{NameClaim: "name", EmailClaim: "email", RolesClaim: "realm_access"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.in.withDefaults(); got != tc.want {
				t.Fatalf("withDefaults() = %#v, want %#v", got, tc.want)
			}
		})
	}
}
