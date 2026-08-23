package gatewayauth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// userinfoTTL bounds how long a userinfo answer is reused. Names change
// rarely; an hour keeps the endpoint out of the request path without making a
// rename invisible for the workday.
const userinfoTTL = time.Hour

// userinfoFetcher fills display claims (name, email) from the provider's
// userinfo endpoint, authenticating with the caller's own already-verified
// access token. Answers are cached per subject.
type userinfoFetcher struct {
	logger *slog.Logger
	uri    string
	client *http.Client

	mu    sync.Mutex
	cache map[string]userinfoEntry
	now   func() time.Time
}

type userinfoEntry struct {
	name      string
	email     string
	fetchedAt time.Time
}

func newUserinfoFetcher(logger *slog.Logger, uri string) *userinfoFetcher {
	return &userinfoFetcher{
		logger: logger,
		uri:    uri,
		client: newHTTPClient(),
		cache:  map[string]userinfoEntry{},
		now:    time.Now,
	}
}

// fill sets identity.Name/Email from userinfo. Failures only log — display
// claims are never worth failing a request over.
func (u *userinfoFetcher) fill(ctx context.Context, accessToken string, identity *Identity) {
	u.mu.Lock()
	cached, ok := u.cache[identity.Subject]
	u.mu.Unlock()

	if ok && u.now().Sub(cached.fetchedAt) < userinfoTTL {
		identity.Name, identity.Email = cached.name, cached.email

		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.uri, http.NoBody)
	if err != nil {
		return
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := u.client.Do(req)
	if err != nil {
		u.logger.WarnContext(ctx, "userinfo request failed", slog.Any("error", err))

		return
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		u.logger.WarnContext(ctx, "userinfo refused", slog.String("status", resp.Status))

		return
	}

	var body struct {
		Sub   string `json:"sub"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		u.logger.WarnContext(ctx, "userinfo undecodable", slog.Any("error", err))

		return
	}

	// The endpoint answered for whoever the token belongs to; require that to
	// be the caller before displaying anything.
	if body.Sub != identity.Subject {
		return
	}

	identity.Name, identity.Email = body.Name, body.Email

	u.mu.Lock()
	u.cache[identity.Subject] = userinfoEntry{name: body.Name, email: body.Email, fetchedAt: u.now()}
	u.mu.Unlock()
}
