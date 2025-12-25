package provider

import (
	"context"
	// "net/url"

	"golang.org/x/oauth2"
)

// Providers contains all the implemented providers
type Providers struct {
	Discord      Discord      `group:"Discord Provider" namespace:"discord" env-namespace:"DISCORD"`
	Google       Google       `group:"Google Provider" namespace:"google" env-namespace:"GOOGLE"`
	OIDC         OIDC         `group:"OIDC Provider" namespace:"oidc" env-namespace:"OIDC"`
	GenericOAuth GenericOAuth `group:"Generic OAuth2 Provider" namespace:"generic-oauth" env-namespace:"GENERIC_OAUTH"`
}

// Provider is used to authenticate users
type Provider interface {
	Name() string
	GetLoginURL(redirectURI, state string) string
	ExchangeCode(redirectURI, code string) (string, error)
	GetUser(token string) (User, error)
	Setup() error
}

type token struct {
	Token string `json:"access_token"`
}

// User is the authenticated user
type User struct {
	Avatar                     string      `json:"avatar"`
	Banner                     string      `json:"banner"`
	CommunicationDisabledUntil interface{} `json:"communication_disabled_until"`
	Flags                      int         `json:"flags"`
	JoinedAt                   string      `json:"joined_at"`
	Nick                       string      `json:"nick"`
	Pending                    bool        `json:"pending"`
	PremiumSince               interface{} `json:"premium_since"`
	Roles                      []string    `json:"roles"`
	UnusualDMActivityUntil     interface{} `json:"unusual_dm_activity_until"`
	User                       struct {
		ID                   string      `json:"id"`
		Username             string      `json:"username"`
		Avatar               string      `json:"avatar"`
		Discriminator        string      `json:"discriminator"`
		PublicFlags          int         `json:"public_flags"`
		Flags                int         `json:"flags"`
		Banner               interface{} `json:"banner"`
		AccentColor          int         `json:"accent_color"`
		GlobalName           string      `json:"global_name"`
		AvatarDecorationData interface{} `json:"avatar_decoration_data"`
		Collectibles         interface{} `json:"collectibles"`
		BannerColor          string      `json:"banner_color"`
		Clan                 interface{} `json:"clan"`
		PrimaryGuild         interface{} `json:"primary_guild"`
	} `json:"user"`
	Mute bool   `json:"mute"`
	Deaf bool   `json:"deaf"`
	Bio  string `json:"bio"`
}

// OAuthProvider is a provider using the oauth2 library
type OAuthProvider struct {
	Resource string `long:"resource" env:"RESOURCE" description:"Optional resource indicator"`

	Config *oauth2.Config
	ctx    context.Context
}

// ConfigCopy returns a copy of the oauth2 config with the given redirectURI
// which ensures the underlying config is not modified
func (p *OAuthProvider) ConfigCopy(redirectURI string) oauth2.Config {
	config := *p.Config
	config.RedirectURL = redirectURI
	return config
}

// OAuthGetLoginURL provides a base "GetLoginURL" for proiders using OAauth2
func (p *OAuthProvider) OAuthGetLoginURL(redirectURI, state string) string {
	config := p.ConfigCopy(redirectURI)

	if p.Resource != "" {
		return config.AuthCodeURL(state, oauth2.SetAuthURLParam("resource", p.Resource))
	}

	return config.AuthCodeURL(state)
}

// OAuthExchangeCode provides a base "ExchangeCode" for proiders using OAauth2
func (p *OAuthProvider) OAuthExchangeCode(redirectURI, code string) (*oauth2.Token, error) {
	config := p.ConfigCopy(redirectURI)
	return config.Exchange(p.ctx, code)
}
