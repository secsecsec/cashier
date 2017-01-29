package google

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/nsheridan/cashier/server/auth"
	"github.com/nsheridan/cashier/server/config"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	googleapi "google.golang.org/api/oauth2/v2"
)

const (
	revokeURL = "https://accounts.google.com/o/oauth2/revoke?token=%s"
	name      = "google"
)

// Google is an implementation of `auth.Provider` for authenticating using a
// Google account.
type Google struct {
	config    *oauth2.Config
	domain    string
	whitelist map[string]bool
}

var _ auth.Provider = (*Google)(nil)

// New creates a new Google provider from a configuration.
func New(c *config.Auth) (*Google, error) {
	uw := make(map[string]bool)
	for _, u := range c.UsersWhitelist {
		uw[u] = true
	}
	if c.ProviderOpts["domain"] == "" && len(uw) == 0 {
		return nil, errors.New("either Google Apps domain or users whitelist must be specified")
	}

	return &Google{
		config: &oauth2.Config{
			ClientID:     c.OauthClientID,
			ClientSecret: c.OauthClientSecret,
			RedirectURL:  c.OauthCallbackURL,
			Endpoint:     google.Endpoint,
			Scopes:       []string{googleapi.UserinfoEmailScope, googleapi.UserinfoProfileScope},
		},
		domain:    c.ProviderOpts["domain"],
		whitelist: uw,
	}, nil
}

// A new oauth2 http client.
func (c *Google) newClient(token *oauth2.Token) *http.Client {
	return c.config.Client(oauth2.NoContext, token)
}

// Name returns the name of the provider.
func (c *Google) Name() string {
	return name
}

// Valid validates the oauth token.
func (c *Google) Valid(token *oauth2.Token) bool {
	if len(c.whitelist) > 0 && !c.whitelist[c.Email(token)] {
		return false
	}
	if !token.Valid() {
		return false
	}
	svc, err := googleapi.New(c.newClient(token))
	if err != nil {
		return false
	}
	t := svc.Tokeninfo()
	t.AccessToken(token.AccessToken)
	ti, err := t.Do()
	if err != nil {
		return false
	}
	if ti.Audience != c.config.ClientID {
		return false
	}
	ui, err := svc.Userinfo.Get().Do()
	if err != nil {
		return false
	}
	if c.domain != "" && ui.Hd != c.domain {
		return false
	}
	return true
}

// Revoke disables the access token.
func (c *Google) Revoke(token *oauth2.Token) error {
	h := c.newClient(token)
	_, err := h.Get(fmt.Sprintf(revokeURL, token.AccessToken))
	return err
}

// StartSession retrieves an authentication endpoint from Google.
func (c *Google) StartSession(state string) *auth.Session {
	return &auth.Session{
		AuthURL: c.config.AuthCodeURL(state, oauth2.SetAuthURLParam("hd", c.domain)),
	}
}

// Exchange authorizes the session and returns an access token.
func (c *Google) Exchange(code string) (*oauth2.Token, error) {
	return c.config.Exchange(oauth2.NoContext, code)
}

// Email retrieves the email address of the user.
func (c *Google) Email(token *oauth2.Token) string {
	svc, err := googleapi.New(c.newClient(token))
	if err != nil {
		return ""
	}
	ui, err := svc.Userinfo.Get().Do()
	if err != nil {
		return ""
	}
	return ui.Email
}

// Username retrieves the username portion of the user's email address.
func (c *Google) Username(token *oauth2.Token) string {
	return strings.Split(c.Email(token), "@")[0]
}
