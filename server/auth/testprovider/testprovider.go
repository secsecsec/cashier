package testprovider

import (
	"time"

	"github.com/nsheridan/cashier/server/auth"

	"golang.org/x/oauth2"
)

const (
	name = "testprovider"
)

// TestProvider is an implementation of `auth.Provider` for testing.
type TestProvider struct{}

var _ auth.Provider = (*TestProvider)(nil)

// New creates a new provider.
func New() *TestProvider {
	return &TestProvider{}
}

// Name returns the name of the provider.
func (c *TestProvider) Name() string {
	return name
}

// Valid validates the oauth token.
func (c *TestProvider) Valid(token *oauth2.Token) bool {
	return true
}

// Revoke disables the access token.
func (c *TestProvider) Revoke(token *oauth2.Token) error {
	return nil
}

// StartSession retrieves an authentication endpoint.
func (c *TestProvider) StartSession(state string) *auth.Session {
	return &auth.Session{
		AuthURL: "https://www.example.com/auth",
	}
}

// Exchange authorizes the session and returns an access token.
func (c *TestProvider) Exchange(code string) (*oauth2.Token, error) {
	return &oauth2.Token{
		AccessToken: "token",
		Expiry:      time.Now().Add(1 * time.Hour),
	}, nil
}

// Username retrieves the username portion of the user's email address.
func (c *TestProvider) Username(token *oauth2.Token) string {
	return "test"
}
