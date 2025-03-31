package kakao_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/dings-things/oauth2"
	"github.com/dings-things/oauth2/kakao"
	"github.com/stretchr/testify/assert"
)

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newMockClient(fn roundTripperFunc) *http.Client {
	return &http.Client{Transport: fn}
}

func TestKakaoProvider_GetUserInfo(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockResp := userInfoResponse{
			ID: 1001,
			AccountInfo: accountInfo{
				Email: "kakao@example.com",
				Profile: profileInfo{
					Nickname:        "kakao-user",
					ProfileImageURL: "https://pic.example.com",
				},
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

		provider := kakao.WithKakaoProvider(oauth2.ProviderSetting{
			Client: client,
		})

		info, err := provider.GetUserInfo("token")
		assert.NoError(t, err)
		assert.Equal(t, "1001", info.GetID())
		assert.Equal(t, "kakao@example.com", info.GetEmail())
		assert.Equal(t, "kakao-user", info.GetName())
	})

	t.Run("network error", func(t *testing.T) {
		client := newMockClient(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("network down")
		})

		provider := kakao.WithKakaoProvider(oauth2.ProviderSetting{
			Client: client,
		})
		_, err := provider.GetUserInfo("token")
		assert.Error(t, err)
	})
}

func TestKakaoProvider_GetAccessToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockResp := tokenInfoResponse{
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			ExpiresIn:    7200,
		}
		mockBody, _ := json.Marshal(mockResp)
		client := newMockClient(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(mockBody)),
			}, nil
		})

		provider := kakao.WithKakaoProvider(oauth2.ProviderSetting{
			Client:       client,
			ClientID:     "client-id",
			ClientSecret: "secret",
			RedirectURL:  "http://localhost",
		})

		token, err := provider.GetAccessToken("code")
		assert.NoError(t, err)
		assert.Equal(t, "access-token", token.GetAccessToken())
		assert.Equal(t, "refresh-token", token.GetRefreshToken())
		assert.Equal(t, 7200, token.GetExpiry())
	})

	t.Run("empty code", func(t *testing.T) {
		provider := kakao.WithKakaoProvider(oauth2.ProviderSetting{
			Client: &http.Client{},
		})
		_, err := provider.GetAccessToken("")
		assert.Error(t, err)
	})

	t.Run("client error", func(t *testing.T) {
		client := newMockClient(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("fail")
		})
		provider := kakao.WithKakaoProvider(oauth2.ProviderSetting{
			Client:       client,
			ClientID:     "id",
			ClientSecret: "secret",
			RedirectURL:  "http://localhost",
		})
		_, err := provider.GetAccessToken("code")
		assert.Error(t, err)
	})
}

func TestKakaoProvider_GetAuthURL(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		provider := kakao.WithKakaoProvider(oauth2.ProviderSetting{
			ClientID:    "kakao-client",
			RedirectURL: "http://localhost/callback",
		})

		authURL, err := provider.GetAuthURL("xyz")
		assert.NoError(t, err)

		u, err := url.Parse(authURL)
		assert.NoError(t, err)
		q := u.Query()

		assert.Equal(t, "kakao-client", q.Get("client_id"))
		assert.Equal(t, "http://localhost/callback", q.Get("redirect_uri"))
		assert.Equal(t, "code", q.Get("response_type"))
		assert.Equal(t, "xyz", q.Get("state"))
	})

	t.Run("missing redirect URL", func(t *testing.T) {
		provider := kakao.WithKakaoProvider(oauth2.ProviderSetting{})
		_, err := provider.GetAuthURL("test")
		assert.Error(t, err)
	})
}

type userInfoResponse struct {
	ID          int         `json:"id"`
	AccountInfo accountInfo `json:"kakao_account"`
}

type accountInfo struct {
	Email   string      `json:"email"`
	Profile profileInfo `json:"profile"`
}

type profileInfo struct {
	Nickname        string `json:"nickname"`
	ProfileImageURL string `json:"profile_image_url"`
}

type tokenInfoResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}
