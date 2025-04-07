package oauth2

import (
	"net/http"
)

type (
	// Client defines the main OAuth2 client interface used by applications
	Client interface {
		RequestUserInfo(provider ProviderType, accessToken string) (UserInfo, error)
		RequestAuthURL(provider ProviderType, state string) string
		RequestToken(provider ProviderType, code string) (TokenInfo, error)
	}

	// Provider defines the behavior that all OAuth2 providers must implement
	Provider interface {
		GetUserInfo(accessToken string) (UserInfo, error)
		GetAuthURL(state string) (string, error)
		GetToken(code string) (TokenInfo, error)
		GetProvider() ProviderType
	}

	// UserInfo defines the required fields retrieved from the OAuth2 provider
	UserInfo interface {
		GetID() string
		GetEmail() string
		GetName() string
		GetGender() string
		GetProfileImage() string
	}

	// TokenInfo defines the token information returned from the provider
	TokenInfo interface {
		GetAccessToken() string
		GetRefreshToken() string
		GetExpiry() int
	}

	// ProviderType is a named string for the provider key (e.g. "google", "kakao")
	ProviderType string

	// ProviderSetting is used to initialize a provider with required values
	ProviderSetting struct {
		Client       *http.Client
		ClientID     string
		ClientSecret string
		RedirectURL  string
	}

	// oauth2Client holds the registered providers
	oauth2Client struct {
		providers map[ProviderType]Provider
	}
)

// NewClient initializes a new OAuth2 client with the given providers
func NewClient(providers ...Provider) Client {
	oauthClient := &oauth2Client{
		providers: make(map[ProviderType]Provider),
	}

	for _, provider := range providers {
		oauthClient.providers[provider.GetProvider()] = provider
	}

	return oauthClient
}

// RequestUserInfo retrieves user information using the given access token
func (c *oauth2Client) RequestUserInfo(
	provider ProviderType,
	accessToken string,
) (UserInfo, error) {
	if oauthProvider, ok := c.providers[provider]; ok {
		return oauthProvider.GetUserInfo(accessToken)
	}

	return nil, ErrProviderNotSet
}

// RequestAuthURL generates the provider's authorization URL for user redirection
func (c *oauth2Client) RequestAuthURL(provider ProviderType, state string) string {
	if oauthProvider, ok := c.providers[provider]; ok {
		authURL, err := oauthProvider.GetAuthURL(state)
		if err != nil {
			return ""
		}
		return authURL
	}

	return ""
}

// RequestToken exchanges the authorization code for an access token
func (c *oauth2Client) RequestToken(provider ProviderType, code string) (TokenInfo, error) {
	if oauthProvider, ok := c.providers[provider]; ok {
		token, err := oauthProvider.GetToken(code)
		if err != nil {
			return nil, err
		}
		return token, nil
	}

	return nil, ErrProviderNotSet
}
