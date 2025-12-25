package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

// Discord provider
type Discord struct {
	ClientID     string `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret string `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`
	TokenStyle   string `long:"token-style" env:"TOKEN_STYLE" default:"header" choice:"header" choice:"query" description:"How token is presented when querying the User URL"`

	OAuthProvider
}

// Name returns the name of the provider
func (d *Discord) Name() string {
	return "discord"
}

// Setup performs validation and setup
func (d *Discord) Setup() error {
	// Check parmas
	if d.ClientID == "" || d.ClientSecret == "" {
		return errors.New("providers.generic-oauth.client-id, providers.generic-oauth.client-secret must be set")
	}

	// Create oauth2 config
	d.Config = &oauth2.Config{
		ClientID:     d.ClientID,
		ClientSecret: d.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://discord.com/api/oauth2/authorize",
			TokenURL: "https://discord.com/api/oauth2/token",
		},
		Scopes: []string{"guilds.members.read"},
	}

	d.ctx = context.Background()

	return nil
}

// GetLoginURL provides the login url for the given redirect uri and state
func (d *Discord) GetLoginURL(redirectURI, state string) string {
	return d.OAuthGetLoginURL(redirectURI, state)
}

// ExchangeCode exchanges the given redirect uri and code for a token
func (d *Discord) ExchangeCode(redirectURI, code string) (string, error) {
	token, err := d.OAuthExchangeCode(redirectURI, code)
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

// GetUser uses the given token and returns a complete provider.User object
func (d *Discord) GetUser(token string) (User, error) {
	var user User

	req, err := http.NewRequest("GET", "https://discord.com/api/v10/users/@me/guilds/945631901257981962/member", nil)
	if err != nil {
		return user, err
	}

	if d.TokenStyle == "header" {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	} else if d.TokenStyle == "query" {
		q := req.URL.Query()
		q.Add("access_token", token)
		req.URL.RawQuery = q.Encode()
	}

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return user, err
	}

	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&user)

	return user, err
}
