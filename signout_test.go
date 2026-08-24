package gatewayauth

import "testing"

func TestSignOutURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		prefix, redirect, want string
	}{
		{"", "", "/oauth2/sign_out"},
		{"/oauth2", "", "/oauth2/sign_out"},
		{"_gwauth", "", "/_gwauth/sign_out"},
		{"/_gwauth/", "", "/_gwauth/sign_out"},
		{"/oauth2", "/", "/oauth2/sign_out?rd=%2F"},
	}

	for _, c := range cases {
		if got := SignOutURL(c.prefix, c.redirect); got != c.want {
			t.Errorf("SignOutURL(%q,%q) = %q, want %q", c.prefix, c.redirect, got, c.want)
		}
	}
}
