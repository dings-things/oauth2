package google_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/dings-things/oauth2"
	"github.com/dings-things/oauth2/google"
	"github.com/stretchr/testify/assert"
)

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newMockClient(fn roundTripperFunc) *http.Client {
	return &http.Client{Transport: fn}
}

func TestGoogleProvider_GetUserInfo(t *testing.T) {
	t.Run("successful user info retrieval", func(t *testing.T) {
		mockResp := googleUserInfoResponse{
			ID:    "123",
			Email: "test@example.com",
			Name:  "Test User",
		}
		mockBody, _ := json.Marshal(mockResp)
		client := newMockClient(func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, "Bearer test-token", req.Header.Get("Authorization"))
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(mockBody)),
			}, nil
		})

		provider := google.WithGoogleProvider(oauth2.ProviderSetting{
			Client:       client,
			ClientID:     "",
			ClientSecret: "",
			RedirectURL:  "",
		})

		user, err := provider.GetUserInfo("test-token")
		assert.NoError(t, err)
		assert.Equal(t, "123", user.GetID())
		assert.Equal(t, "test@example.com", user.GetEmail())
		assert.Equal(t, "Test User", user.GetName())
	})

	t.Run("error on user info request", func(t *testing.T) {
		client := newMockClient(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("network error")
		})

		provider := google.WithGoogleProvider(oauth2.ProviderSetting{
			Client:       client,
			ClientID:     "",
			ClientSecret: "",
			RedirectURL:  "",
		})

		_, err := provider.GetUserInfo("test-token")
		assert.Error(t, err)
	})
}

func TestGoogleProvider_GetAccessToken(t *testing.T) {
	t.Run("successful token exchange", func(t *testing.T) {
		mockResp := tokenInfoResponse{
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			ExpiresIn:    3600,
		}
		mockBody, _ := json.Marshal(mockResp)
		client := newMockClient(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(mockBody)),
			}, nil
		})

		provider := google.WithGoogleProvider(oauth2.ProviderSetting{
			Client:       client,
			ClientID:     "id",
			ClientSecret: "secret",
			RedirectURL:  "http://localhost",
		})

		token, err := provider.GetAccessToken("valid-code")
		assert.NoError(t, err)
		assert.Equal(t, "access-token", token.GetAccessToken())
		assert.Equal(t, "refresh-token", token.GetRefreshToken())
		assert.Equal(t, 3600, token.GetExpiry())
	})

	t.Run("empty code returns error", func(t *testing.T) {
		provider := google.WithGoogleProvider(oauth2.ProviderSetting{
			Client: &http.Client{},
		})
		_, err := provider.GetAccessToken("")
		assert.Error(t, err)
	})

	t.Run("http client returns error", func(t *testing.T) {
		client := newMockClient(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("connection failed")
		})
		provider := google.WithGoogleProvider(oauth2.ProviderSetting{
			Client:       client,
			ClientID:     "id",
			ClientSecret: "secret",
			RedirectURL:  "http://localhost",
		})
		_, err := provider.GetAccessToken("code")
		assert.Error(t, err)
	})
}

func TestGoogleProvider_GetAuthURL(t *testing.T) {
	t.Run("successful auth URL generation", func(t *testing.T) {
		provider := google.WithGoogleProvider(oauth2.ProviderSetting{
			Client:      &http.Client{},
			ClientID:    "client-id",
			RedirectURL: "http://localhost/callback",
		})

		authURL, err := provider.GetAuthURL("test-state")
		assert.NoError(t, err)

		parsedURL, err := url.Parse(authURL)
		assert.NoError(t, err)

		params := parsedURL.Query()
		assert.Equal(t, "client-id", params.Get("client_id"))
		assert.Equal(t, "http://localhost/callback", params.Get("redirect_uri"))
		assert.Equal(t, "code", params.Get("response_type"))
		assert.Equal(t, "openid email profile", params.Get("scope"))
		assert.Equal(t, "test-state", params.Get("state"))
		assert.Equal(t, "offline", params.Get("access_type"))
		assert.Equal(t, "consent", params.Get("prompt"))
	})

	t.Run("missing redirect URL", func(t *testing.T) {
		provider := google.WithGoogleProvider(oauth2.ProviderSetting{
			Client:   &http.Client{},
			ClientID: "client-id",
		})
		url, err := provider.GetAuthURL("state")
		assert.Error(t, err)
		assert.Empty(t, url)
	})
}

type googleUserInfoResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

type tokenInfoResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}
