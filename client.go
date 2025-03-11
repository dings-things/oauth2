package oauth2

import (
	"errors"
	"net/http"
)

var (
	// ErrProviderNotSet : Error Provider Not Set
	ErrProviderNotSet = errors.New("Provider Not Set")
)

type (
	// Client : OAuth2 Client Interface
	Client interface {
		GetUserInfo(provider ProviderType, accessToken string) (UserInfo, error)
	}

	// Provider : OAuth2 Provider Interface
	Provider interface {
		GetUserInfo(client *http.Client, accessToken string) (UserInfo, error)
		GetProvider() ProviderType
	}

	// UserInfo : UserInfo Achieved by OAuth2
	UserInfo interface {
		GetID() string
		GetEmail() string
		GetName() string
	}

	// ProviderType : OAuth2 provider type
	ProviderType string

	// ProviderSetting : OAuth2 provider setting
	ProviderSetting struct {
		clientID     string
		clientSecret string
	}

	oauth2Client struct {
		client    *http.Client
		providers map[ProviderType]Provider
	}
)

// NewClient : Create OAuth2 Client
func NewClient(client *http.Client, providers ...Provider) Client {
	oauthClient := &oauth2Client{
		client:    client,
		providers: make(map[ProviderType]Provider),
	}

	for _, provider := range providers {
		oauthClient.providers[provider.GetProvider()] = provider
	}

	return oauthClient
}

// GetUserInfo : Get User Info by OAuth2
func (c *oauth2Client) GetUserInfo(provider ProviderType, accessToken string) (UserInfo, error) {
	if oauthProvider, ok := c.providers[provider]; ok {
		return oauthProvider.GetUserInfo(c.client, accessToken)
	}

	return nil, ErrProviderNotSet
}
