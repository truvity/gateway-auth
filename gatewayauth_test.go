package gatewayauth

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestIdentityHasRole(t *testing.T) {
	t.Parallel()

	id := Identity{Roles: []string{"a:read", "a:write"}}

	cases := []struct {
		role string
		want bool
	}{
		{"a:read", true},
		{"a:write", true},
		{"a:admin", false},
		{"", false},
	}

	for _, tc := range cases {
		if got := id.HasRole(tc.role); got != tc.want {
			t.Errorf("HasRole(%q) = %v, want %v", tc.role, got, tc.want)
		}
	}

	// The zero identity holds no roles.
	if (Identity{}).HasRole("a:read") {
		t.Error("zero Identity must not hold any role")
	}
}

func TestIdentityHasAnyRole(t *testing.T) {
	t.Parallel()

	id := Identity{Roles: []string{"a:read"}}

	cases := []struct {
		name  string
		roles []string
		want  bool
	}{
		{"none requested", nil, false},
		{"one match", []string{"a:read"}, true},
		{"no match", []string{"a:write", "a:admin"}, false},
		{"match among several", []string{"a:admin", "a:read"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := id.HasAnyRole(tc.roles...); got != tc.want {
				t.Fatalf("HasAnyRole(%v) = %v, want %v", tc.roles, got, tc.want)
			}
		})
	}
}

func TestContextRoundTrip(t *testing.T) {
	t.Parallel()

	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("a bare context must carry no identity")
	}

	want := Identity{Subject: "u-1", Name: "A Person"}
	ctx := WithIdentity(context.Background(), want)

	got, ok := FromContext(ctx)
	if !ok {
		t.Fatal("FromContext found nothing after WithIdentity")
	}

	if got.Subject != want.Subject || got.Name != want.Name {
		t.Fatalf("FromContext = %#v, want %#v", got, want)
	}
}

func TestDisabled(t *testing.T) {
	t.Parallel()

	auth := NewDisabled("svc:operator", "svc:viewer")

	if auth.Enabled() {
		t.Fatal("a disabled authenticator must report Enabled() == false")
	}

	// It authorizes everybody, ignoring the request entirely.
	id, err := auth.Authenticate(context.Background(), fakeHeaders{})
	if err != nil {
		t.Fatalf("disabled Authenticate returned error: %v", err)
	}

	if id.Subject != "local" || id.Email != "local@localhost" {
		t.Fatalf("unexpected fixed identity: %#v", id)
	}

	if !reflect.DeepEqual(id.Roles, []string{"svc:operator", "svc:viewer"}) {
		t.Fatalf("roles = %#v, want the ones passed to NewDisabled", id.Roles)
	}

	if !id.HasRole("svc:operator") {
		t.Error("disabled identity should hold the roles it was given")
	}
}

func TestHeaderTrust(t *testing.T) {
	t.Parallel()

	auth := NewHeaderTrust()

	if !auth.Enabled() {
		t.Fatal("header trust verifies presence of headers, so Enabled() == true")
	}

	cases := []struct {
		name        string
		headers     fakeHeaders
		wantErr     error
		wantSubject string
		wantName    string
		wantEmail   string
		wantRoles   []string
		wantToken   string
	}{
		{
			name: "full set of proxy headers",
			headers: fakeHeaders{
				HeaderUser:        "u-1",
				HeaderEmail:       "a@example.com",
				HeaderGroups:      "ops, viewers ,,writers",
				HeaderAccessToken: "tok-123",
			},
			wantSubject: "u-1",
			wantName:    "u-1",
			wantEmail:   "a@example.com",
			wantRoles:   []string{"ops", "viewers", "writers"},
			wantToken:   "tok-123",
		},
		{
			// Name falls back to the email when the user header is absent.
			name: "email only, name falls back to email",
			headers: fakeHeaders{
				HeaderEmail: "a@example.com",
			},
			wantSubject: "",
			wantName:    "a@example.com",
			wantEmail:   "a@example.com",
			wantRoles:   nil,
		},
		{
			name: "user only, no groups",
			headers: fakeHeaders{
				HeaderUser: "u-1",
			},
			wantSubject: "u-1",
			wantName:    "u-1",
			wantRoles:   nil,
		},
		{
			// Neither user nor email — the request did not come through the proxy.
			name:    "no identity headers at all",
			headers: fakeHeaders{HeaderAccessToken: "tok-only"},
			wantErr: ErrNoCredential,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			id, err := auth.Authenticate(context.Background(), tc.headers)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if id.Subject != tc.wantSubject || id.Name != tc.wantName || id.Email != tc.wantEmail {
				t.Fatalf("identity = %#v, want subject=%q name=%q email=%q",
					id, tc.wantSubject, tc.wantName, tc.wantEmail)
			}

			if !reflect.DeepEqual(id.Roles, tc.wantRoles) {
				t.Fatalf("roles = %#v, want %#v", id.Roles, tc.wantRoles)
			}

			if id.Token != tc.wantToken {
				t.Fatalf("token = %q, want %q", id.Token, tc.wantToken)
			}
		})
	}
}
