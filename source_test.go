package gatewayauth

import (
	"reflect"
	"testing"
)

// fakeHeaders is a map-backed Headers for tests. Keys are matched verbatim, so
// tests use the same header-name constants the sources ask for.
type fakeHeaders map[string]string

func (f fakeHeaders) Get(name string) string { return f[name] }

func TestHeaderSourceToken(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		source  HeaderSource
		headers fakeHeaders
		want    string
		ok      bool
	}{
		{
			name:    "verbatim present",
			source:  HeaderSource{Name: HeaderAccessToken},
			headers: fakeHeaders{HeaderAccessToken: "abc.def.ghi"},
			want:    "abc.def.ghi",
			ok:      true,
		},
		{
			name:    "verbatim trims surrounding space",
			source:  HeaderSource{Name: HeaderAccessToken},
			headers: fakeHeaders{HeaderAccessToken: "  abc.def.ghi  "},
			want:    "abc.def.ghi",
			ok:      true,
		},
		{
			name:    "verbatim absent",
			source:  HeaderSource{Name: HeaderAccessToken},
			headers: fakeHeaders{},
			want:    "",
			ok:      false,
		},
		{
			name:    "verbatim empty",
			source:  HeaderSource{Name: HeaderAccessToken},
			headers: fakeHeaders{HeaderAccessToken: "   "},
			want:    "",
			ok:      false,
		},
		{
			name:    "bearer canonical",
			source:  HeaderSource{Name: HeaderAuthorization, Scheme: "Bearer"},
			headers: fakeHeaders{HeaderAuthorization: "Bearer abc.def.ghi"},
			want:    "abc.def.ghi",
			ok:      true,
		},
		{
			// RFC 7235 makes the scheme case-insensitive, and proxies vary it.
			name:    "bearer lowercase scheme",
			source:  HeaderSource{Name: HeaderAuthorization, Scheme: "Bearer"},
			headers: fakeHeaders{HeaderAuthorization: "bearer abc.def.ghi"},
			want:    "abc.def.ghi",
			ok:      true,
		},
		{
			name:    "bearer mixed-case scheme",
			source:  HeaderSource{Name: HeaderAuthorization, Scheme: "Bearer"},
			headers: fakeHeaders{HeaderAuthorization: "BeArEr abc.def.ghi"},
			want:    "abc.def.ghi",
			ok:      true,
		},
		{
			name:    "bearer trailing space around token",
			source:  HeaderSource{Name: HeaderAuthorization, Scheme: "Bearer"},
			headers: fakeHeaders{HeaderAuthorization: "Bearer   abc.def.ghi  "},
			want:    "abc.def.ghi",
			ok:      true,
		},
		{
			name:    "bearer scheme but empty token",
			source:  HeaderSource{Name: HeaderAuthorization, Scheme: "Bearer"},
			headers: fakeHeaders{HeaderAuthorization: "Bearer "},
			want:    "",
			ok:      false,
		},
		{
			name:    "bearer wrong scheme",
			source:  HeaderSource{Name: HeaderAuthorization, Scheme: "Bearer"},
			headers: fakeHeaders{HeaderAuthorization: "Basic dXNlcjpwYXNz"},
			want:    "",
			ok:      false,
		},
		{
			// A bare token with no scheme is not what a Bearer source accepts.
			name:    "bearer no scheme",
			source:  HeaderSource{Name: HeaderAuthorization, Scheme: "Bearer"},
			headers: fakeHeaders{HeaderAuthorization: "abc.def.ghi"},
			want:    "",
			ok:      false,
		},
		{
			// Value shorter than the scheme prefix must not slice out of range.
			name:    "bearer value shorter than prefix",
			source:  HeaderSource{Name: HeaderAuthorization, Scheme: "Bearer"},
			headers: fakeHeaders{HeaderAuthorization: "Bea"},
			want:    "",
			ok:      false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := tc.source.Token(tc.headers)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("Token() = (%q, %v), want (%q, %v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestChainSourceOrder(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		headers fakeHeaders
		want    string
		ok      bool
	}{
		{
			name:    "empty picks nothing",
			headers: fakeHeaders{},
			want:    "",
			ok:      false,
		},
		{
			name:    "only authorization present",
			headers: fakeHeaders{HeaderAuthorization: "Bearer from-auth"},
			want:    "from-auth",
			ok:      true,
		},
		{
			name:    "only access-token present",
			headers: fakeHeaders{HeaderAccessToken: "from-access"},
			want:    "from-access",
			ok:      true,
		},
		{
			// The first source in the chain wins even when both are present.
			name: "both present: first source wins",
			headers: fakeHeaders{
				HeaderAccessToken:   "from-access",
				HeaderAuthorization: "Bearer from-auth",
			},
			want: "from-access",
			ok:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := DefaultSource().Token(tc.headers)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("DefaultSource().Token() = (%q, %v), want (%q, %v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestDefaultSourceFallsBackToAuthorization(t *testing.T) {
	t.Parallel()

	// No oauth2-proxy header — a direct API caller with a bearer token still
	// resolves.
	got, ok := DefaultSource().Token(fakeHeaders{HeaderAuthorization: "Bearer direct"})
	if !ok || got != "direct" {
		t.Fatalf("fallback to Authorization = (%q, %v), want (%q, true)", got, ok, "direct")
	}
}

func TestSplitAndTrim(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"only commas and spaces", " , , ", nil},
		{"single", "operators", []string{"operators"}},
		{"trims each", " a , b ,c", []string{"a", "b", "c"}},
		{"drops empties", "a,,b,", []string{"a", "b"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := splitAndTrim(tc.in, ","); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("splitAndTrim(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}
