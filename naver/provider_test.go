package naver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/dings-things/oauth2"
	"github.com/dings-things/oauth2/naver"
	"github.com/stretchr/testify/assert"
)

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newMockClient(fn roundTripperFunc) *http.Client {
	return &http.Client{Transport: fn}
}

func TestNaverProvider_GetUserInfo(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockResp := userInfoResponse{
			Resultcode: "00",
			Response: struct {
				ID           string `json:"id"`
				Email        string `json:"email"`
				Name         string `json:"name"`
				ProfileImage string `json:"profile_image"`
			}{
				ID:    "naver-id",
				Email: "naver@example.com",
				Name:  "naver-user",
			},
		}
		mockBody, _ := json.Marshal(mockResp)
		client := newMockClient(func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, "Bearer token", req.Header.Get("Authorization"))
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(mockBody)),
			}, nil
		})

		provider := naver.NewProvider(oauth2.ProviderSetting{
			Client: client,
		})

		info, err := provider.GetUserInfo(context.Background(), "token")
		assert.NoError(t, err)
		assert.Equal(t, "naver-id", info.GetID())
		assert.Equal(t, "naver@example.com", info.GetEmail())
		assert.Equal(t, "naver-user", info.GetName())
	})

	t.Run("network error", func(t *testing.T) {
		client := newMockClient(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("network error")
		})
		provider := naver.NewProvider(oauth2.ProviderSetting{Client: client})
		_, err := provider.GetUserInfo(context.Background(), "token")
		assert.Error(t, err)
	})
}

func TestNaverProvider_GetAccessToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockResp := tokenInfoResponse{
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			ExpiresIn:    "3600",
		}
		mockBody, _ := json.Marshal(mockResp)
		client := newMockClient(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(mockBody)),
			}, nil
		})
		provider := naver.NewProvider(oauth2.ProviderSetting{
			Client:       client,
			ClientID:     "id",
			ClientSecret: "secret",
			RedirectURL:  "http://localhost",
		})

		token, err := provider.GetToken(context.Background(), "code")
		assert.NoError(t, err)
		assert.Equal(t, "access-token", token.GetAccessToken())
		assert.Equal(t, "refresh-token", token.GetRefreshToken())
		assert.Equal(t, 3600, token.GetExpiry())
	})

	t.Run("empty code", func(t *testing.T) {
		provider := naver.NewProvider(oauth2.ProviderSetting{})
		_, err := provider.GetToken(context.Background(), "")
		assert.Error(t, err)
	})

	t.Run("client error", func(t *testing.T) {
		client := newMockClient(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("fail")
		})
		provider := naver.NewProvider(oauth2.ProviderSetting{
			Client:       client,
			ClientID:     "id",
			ClientSecret: "secret",
			RedirectURL:  "http://localhost",
		})
		_, err := provider.GetToken(context.Background(), "code")
		assert.Error(t, err)
	})
}

func TestNaverProvider_GetAuthURL(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		provider := naver.NewProvider(oauth2.ProviderSetting{
			ClientID:    "test-client",
			RedirectURL: "http://localhost/callback",
		})

		urlStr, err := provider.GetAuthURL(context.Background(), "xyz")
		assert.NoError(t, err)

		u, err := url.Parse(urlStr)
		assert.NoError(t, err)
		query := u.Query()

		assert.Equal(t, "test-client", query.Get("client_id"))
		assert.Equal(t, "code", query.Get("response_type"))
		assert.Equal(t, "http://localhost/callback", query.Get("redirect_uri"))
		assert.Equal(t, "xyz", query.Get("state"))
	})

	t.Run("missing redirect URL", func(t *testing.T) {
		provider := naver.NewProvider(oauth2.ProviderSetting{})
		_, err := provider.GetAuthURL(context.Background(), "abc")
		assert.Error(t, err)
	})
}

type userInfoResponse struct {
	Resultcode string `json:"resultcode"`
	Response   struct {
		ID           string `json:"id"`
		Email        string `json:"email"`
		Name         string `json:"name"`
		ProfileImage string `json:"profile_image"`
	} `json:"response"`
}

type tokenInfoResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    string `json:"expires_in"`
}
