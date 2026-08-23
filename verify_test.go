package gatewayauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

// discardLogger keeps the verifier's warnings out of the test output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeIssuer is an identity provider: a discovery document, a JWKS and a
// userinfo endpoint, served over a real listener so the verifier exercises its
// actual fetch path rather than an injected key.
type fakeIssuer struct {
	server *httptest.Server
	signer jwk.Key
	public jwk.Key
	// userinfoCalls counts hits on /userinfo, so a test can prove the cache
	// holds. Atomic because parallel subtests may share one issuer.
	userinfoCalls atomic.Int64
	// userinfoBody is what /userinfo returns; nil serves the default person.
	userinfoBody map[string]string
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()

	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	signer, err := jwk.Import[jwk.Key](raw)
	if err != nil {
		t.Fatalf("import key: %v", err)
	}

	mustSet(t, signer, jwk.KeyIDKey, "test-key")
	mustSet(t, signer, jwk.AlgorithmKey, jwa.RS256())

	public, err := jwk.PublicKeyOf(signer)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}

	issuer := &fakeIssuer{signer: signer, public: public}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":            issuer.server.URL,
			"jwks_uri":          issuer.server.URL + "/keys",
			"userinfo_endpoint": issuer.server.URL + "/userinfo",
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		set := jwk.NewSet()
		if err := set.AddKey(public); err != nil {
			t.Errorf("add key to set: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		issuer.userinfoCalls.Add(1)

		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		body := issuer.userinfoBody
		if body == nil {
			body = map[string]string{"sub": "u-1", "name": "A Person", "email": "a@example.com"}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})

	issuer.server = httptest.NewServer(mux)
	t.Cleanup(issuer.server.Close)

	return issuer
}

func mustSet(t *testing.T, key jwk.Key, name string, value any) {
	t.Helper()

	if err := key.Set(name, value); err != nil {
		t.Fatalf("set %q: %v", name, err)
	}
}

// token mints a signed token. mutate tweaks the builder before signing so a
// test can state exactly what is wrong with the token it presents.
func (f *fakeIssuer) token(t *testing.T, mutate func(b *jwt.Builder)) string {
	t.Helper()

	builder := jwt.NewBuilder().
		Issuer(f.server.URL).
		Subject("u-1").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Claim("name", "A Person").
		Claim("email", "a@example.com").
		Claim("groups", []string{"svc:operator"})

	if mutate != nil {
		mutate(builder)
	}

	token, err := builder.Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), f.signer))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	return string(signed)
}

func newTestVerifier(t *testing.T, cfg Config) Authenticator {
	t.Helper()

	if cfg.Logger == nil {
		cfg.Logger = discardLogger()
	}

	auth, err := NewVerifier(t.Context(), cfg)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	return auth
}

// accessTokenHeaders presents a token the oauth2-proxy way (verbatim header).
func accessTokenHeaders(raw string) fakeHeaders {
	return fakeHeaders{HeaderAccessToken: raw}
}

func TestVerifierAcceptsAGoodToken(t *testing.T) {
	t.Parallel()

	issuer := newFakeIssuer(t)
	auth := newTestVerifier(t, Config{Issuer: issuer.server.URL})

	raw := issuer.token(t, nil)

	id, err := auth.Authenticate(t.Context(), accessTokenHeaders(raw))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if !auth.Enabled() {
		t.Error("a verifying authenticator must report Enabled() == true")
	}

	if id.Subject != "u-1" {
		t.Errorf("Subject = %q, want u-1", id.Subject)
	}

	if id.Name != "A Person" || id.Email != "a@example.com" {
		t.Errorf("display claims = (%q, %q), want (A Person, a@example.com)", id.Name, id.Email)
	}

	if !reflect.DeepEqual(id.Roles, []string{"svc:operator"}) {
		t.Errorf("Roles = %#v, want [svc:operator]", id.Roles)
	}

	if id.Token != raw {
		t.Error("Token must be the verified raw access token")
	}

	// Claims carries every claim for app-specific reads.
	if id.Claims == nil {
		t.Fatal("Claims must be populated")
	}

	if _, ok := id.Claims["groups"]; !ok {
		t.Error("Claims should contain the raw groups claim")
	}
}

func TestVerifierRejects(t *testing.T) {
	t.Parallel()

	issuer := newFakeIssuer(t)
	other := newFakeIssuer(t)
	auth := newTestVerifier(t, Config{Issuer: issuer.server.URL})

	cases := []struct {
		name    string
		headers func(t *testing.T) fakeHeaders
		wantErr error
	}{
		{
			name:    "no credential presented",
			headers: func(*testing.T) fakeHeaders { return fakeHeaders{} },
			wantErr: ErrNoCredential,
		},
		{
			name:    "malformed token",
			headers: func(*testing.T) fakeHeaders { return accessTokenHeaders("not-a-jwt") },
			wantErr: ErrInvalidToken,
		},
		{
			// A token minted by anyone else must not be accepted, even though
			// its signature is internally valid.
			name:    "signed by a different issuer",
			headers: func(t *testing.T) fakeHeaders { return accessTokenHeaders(other.token(t, nil)) },
			wantErr: ErrInvalidToken,
		},
		{
			// Claims the right issuer string but is signed with the wrong key —
			// the substitution a stolen-and-edited token would make.
			name: "issuer claim forged, wrong signing key",
			headers: func(t *testing.T) fakeHeaders {
				return accessTokenHeaders(other.token(t, func(b *jwt.Builder) {
					b.Issuer(issuer.server.URL)
				}))
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "wrong issuer claim",
			headers: func(t *testing.T) fakeHeaders {
				return accessTokenHeaders(issuer.token(t, func(b *jwt.Builder) {
					b.Issuer("https://somebody.else")
				}))
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "expired",
			headers: func(t *testing.T) fakeHeaders {
				return accessTokenHeaders(issuer.token(t, func(b *jwt.Builder) {
					b.Expiration(time.Now().Add(-time.Minute))
				}))
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "tampered signature",
			headers: func(t *testing.T) fakeHeaders {
				raw := issuer.token(t, nil)

				return accessTokenHeaders(raw[:len(raw)-2] + "xx")
			},
			wantErr: ErrInvalidToken,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := auth.Authenticate(t.Context(), tc.headers(t))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestVerifierChecksAudienceWhenConfigured(t *testing.T) {
	t.Parallel()

	issuer := newFakeIssuer(t)
	auth := newTestVerifier(t, Config{Issuer: issuer.server.URL, Audience: "svc"})

	wrong := issuer.token(t, func(b *jwt.Builder) { b.Audience([]string{"something-else"}) })
	if _, err := auth.Authenticate(t.Context(), accessTokenHeaders(wrong)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("wrong audience: error = %v, want ErrInvalidToken", err)
	}

	right := issuer.token(t, func(b *jwt.Builder) { b.Audience([]string{"svc"}) })
	if _, err := auth.Authenticate(t.Context(), accessTokenHeaders(right)); err != nil {
		t.Fatalf("matching audience rejected: %v", err)
	}
}

func TestVerifierEmptyAudienceAcceptsAny(t *testing.T) {
	t.Parallel()

	issuer := newFakeIssuer(t)
	auth := newTestVerifier(t, Config{Issuer: issuer.server.URL}) // Audience: ""

	// A token carrying some unrelated audience is still accepted, because the
	// gateway already checked audience.
	withAud := issuer.token(t, func(b *jwt.Builder) { b.Audience([]string{"anything"}) })
	if _, err := auth.Authenticate(t.Context(), accessTokenHeaders(withAud)); err != nil {
		t.Fatalf("token with audience rejected under empty-audience config: %v", err)
	}

	// So is a token with no audience at all.
	noAud := issuer.token(t, nil)
	if _, err := auth.Authenticate(t.Context(), accessTokenHeaders(noAud)); err != nil {
		t.Fatalf("token without audience rejected under empty-audience config: %v", err)
	}
}

// The roles claim arrives in several shapes; all must normalize to the same
// []string. A hand-built []string round-trips through JSON as a []any, so the
// scalar and array cases here cover the string and []any branches; the
// []string branch is pinned directly in TestStringsFrom.
func TestVerifierNormalizesRolesClaim(t *testing.T) {
	t.Parallel()

	issuer := newFakeIssuer(t)
	auth := newTestVerifier(t, Config{Issuer: issuer.server.URL})

	cases := []struct {
		name  string
		claim any
		want  []string
	}{
		{"scalar string", "svc:viewer", []string{"svc:viewer"}},
		{"array of strings", []string{"svc:viewer", "svc:operator"}, []string{"svc:viewer", "svc:operator"}},
		{"empty array", []string{}, []string{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			raw := issuer.token(t, func(b *jwt.Builder) { b.Claim("groups", tc.claim) })

			id, err := auth.Authenticate(t.Context(), accessTokenHeaders(raw))
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}

			if !reflect.DeepEqual(id.Roles, tc.want) {
				t.Fatalf("Roles = %#v, want %#v", id.Roles, tc.want)
			}
		})
	}
}

func TestVerifierCustomClaimsMapper(t *testing.T) {
	t.Parallel()

	issuer := newFakeIssuer(t)
	auth := newTestVerifier(t, Config{
		Issuer: issuer.server.URL,
		Claims: ClaimsMapper{NameClaim: "display", EmailClaim: "mail", RolesClaim: "roles"},
	})

	raw := issuer.token(t, func(b *jwt.Builder) {
		b.Claim("display", "Custom Name").
			Claim("mail", "custom@example.com").
			Claim("roles", []string{"r1", "r2"}).
			// The default claim names must be ignored under the custom mapper.
			Claim("name", "Ignored").
			Claim("groups", []string{"ignored"})
	})

	id, err := auth.Authenticate(t.Context(), accessTokenHeaders(raw))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if id.Name != "Custom Name" || id.Email != "custom@example.com" {
		t.Errorf("display claims = (%q, %q), want (Custom Name, custom@example.com)", id.Name, id.Email)
	}

	if !reflect.DeepEqual(id.Roles, []string{"r1", "r2"}) {
		t.Errorf("Roles = %#v, want [r1 r2]", id.Roles)
	}
}

func TestVerifierUsesConfiguredSource(t *testing.T) {
	t.Parallel()

	issuer := newFakeIssuer(t)
	auth := newTestVerifier(t, Config{
		Issuer: issuer.server.URL,
		Source: AuthorizationBearer(),
	})

	raw := issuer.token(t, nil)

	// The configured source reads only Authorization: the oauth2-proxy header
	// alone is not seen.
	if _, err := auth.Authenticate(t.Context(), accessTokenHeaders(raw)); !errors.Is(err, ErrNoCredential) {
		t.Fatalf("access-token header under bearer-only source: error = %v, want ErrNoCredential", err)
	}

	id, err := auth.Authenticate(t.Context(), fakeHeaders{HeaderAuthorization: "Bearer " + raw})
	if err != nil {
		t.Fatalf("bearer header rejected: %v", err)
	}

	if id.Subject != "u-1" {
		t.Errorf("Subject = %q, want u-1", id.Subject)
	}
}

func TestVerifierUserinfoFallback(t *testing.T) {
	t.Parallel()

	issuer := newFakeIssuer(t)
	auth := newTestVerifier(t, Config{Issuer: issuer.server.URL, UserinfoFallback: true})

	// An access token with roles but no display claims — Zitadel asserts those
	// into the ID token, not the access token.
	raw := issuer.token(t, func(b *jwt.Builder) {
		b.Claim("name", "").Claim("email", "")
	})

	id, err := auth.Authenticate(t.Context(), accessTokenHeaders(raw))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if id.Name != "A Person" || id.Email != "a@example.com" {
		t.Fatalf("userinfo did not fill display claims: %#v", id)
	}

	if got := issuer.userinfoCalls.Load(); got != 1 {
		t.Fatalf("userinfo hit %d times, want 1", got)
	}

	// The second request for the same subject is served from the cache.
	if _, err := auth.Authenticate(t.Context(), accessTokenHeaders(raw)); err != nil {
		t.Fatalf("second Authenticate: %v", err)
	}

	if got := issuer.userinfoCalls.Load(); got != 1 {
		t.Fatalf("userinfo hit %d times after a cached call, want 1", got)
	}
}

func TestVerifierUserinfoSkippedWhenTokenHasDisplayClaims(t *testing.T) {
	t.Parallel()

	issuer := newFakeIssuer(t)
	auth := newTestVerifier(t, Config{Issuer: issuer.server.URL, UserinfoFallback: true})

	// The token already carries name and email, so userinfo is never asked.
	raw := issuer.token(t, nil)

	id, err := auth.Authenticate(t.Context(), accessTokenHeaders(raw))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if id.Name != "A Person" {
		t.Errorf("Name = %q, want A Person", id.Name)
	}

	if got := issuer.userinfoCalls.Load(); got != 0 {
		t.Fatalf("userinfo hit %d times, want 0 when the token carries display claims", got)
	}
}

func TestVerifierUserinfoIgnoredForForeignSubject(t *testing.T) {
	t.Parallel()

	issuer := newFakeIssuer(t)
	// userinfo answers for a different subject than the token's — its claims
	// must never be displayed as the caller's.
	issuer.userinfoBody = map[string]string{"sub": "someone-else", "name": "Someone Else", "email": "x@example.com"}

	auth := newTestVerifier(t, Config{Issuer: issuer.server.URL, UserinfoFallback: true})

	raw := issuer.token(t, func(b *jwt.Builder) {
		b.Claim("name", "").Claim("email", "")
	})

	id, err := auth.Authenticate(t.Context(), accessTokenHeaders(raw))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if id.Name == "Someone Else" {
		t.Fatal("a foreign userinfo answer must not be displayed as the caller's")
	}

	if id.Name != "" || id.Email != "" {
		t.Fatalf("display claims should stay empty, got %#v", id)
	}
}

func TestVerifierUserinfoDisabledByDefault(t *testing.T) {
	t.Parallel()

	issuer := newFakeIssuer(t)
	auth := newTestVerifier(t, Config{Issuer: issuer.server.URL}) // UserinfoFallback: false

	raw := issuer.token(t, func(b *jwt.Builder) {
		b.Claim("name", "").Claim("email", "")
	})

	id, err := auth.Authenticate(t.Context(), accessTokenHeaders(raw))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if id.Name != "" || id.Email != "" {
		t.Errorf("display claims should stay empty with fallback off, got %#v", id)
	}

	if got := issuer.userinfoCalls.Load(); got != 0 {
		t.Fatalf("userinfo hit %d times with fallback off, want 0", got)
	}
}

func TestNewVerifierRequiresIssuer(t *testing.T) {
	t.Parallel()

	if _, err := NewVerifier(context.Background(), Config{}); err == nil {
		t.Fatal("NewVerifier with no issuer must fail")
	}
}

func TestNewVerifierDiscoveryIssuerMismatchIsFatal(t *testing.T) {
	t.Parallel()

	// Discovery naming a different issuer than the one configured means a
	// redirect landed us at somebody else's provider.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   "https://somebody.else",
			"jwks_uri": "https://somebody.else/keys",
		})
	}))
	t.Cleanup(server.Close)

	_, err := NewVerifier(context.Background(), Config{Issuer: server.URL, Logger: discardLogger()})
	if err == nil {
		t.Fatal("discovery issuer mismatch must be fatal")
	}
}

func TestOAuth2ProxyOIDCProfile(t *testing.T) {
	t.Parallel()

	issuer := newFakeIssuer(t)

	auth, err := OAuth2ProxyOIDC(t.Context(), discardLogger(), issuer.server.URL)
	if err != nil {
		t.Fatalf("OAuth2ProxyOIDC: %v", err)
	}

	// The profile uses DefaultSource, so the oauth2-proxy header resolves.
	raw := issuer.token(t, nil)

	id, err := auth.Authenticate(t.Context(), accessTokenHeaders(raw))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if id.Subject != "u-1" || !id.HasRole("svc:operator") {
		t.Fatalf("unexpected identity from profile preset: %#v", id)
	}
}
