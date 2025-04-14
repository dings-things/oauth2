package kakao

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/dings-things/oauth2"
)

const (
	// ProviderType is the identifier for the Kakao login provider
	//   - REFS : https://developers.kakao.com/docs/latest/ko/kakaologin/rest-api
	ProviderType oauth2.ProviderType = "kakao"

	// UserInfoURL is the endpoint to retrieve user profile info
	UserInfoURL = "https://kapi.kakao.com/v2/user/me"

	// AuthURL is the endpoint to start the authorization code flow
	AuthURL = "https://kauth.kakao.com/oauth/authorize"

	// TokenURL is the endpoint to exchange authorization code for access token
	TokenURL = "https://kauth.kakao.com/oauth/token"
)

type (
	// provider stores Kakao-specific OAuth2 credentials and config
	provider struct {
		client       *http.Client
		clientID     string
		clientSecret string
		redirectURL  string
	}

	// userInfo holds the response structure returned from Kakao user info API
	userInfo struct {
		ID          int `json:"id"`
		AccountInfo struct {
			Email   string `json:"email"`
			Profile struct {
				NickName        string `json:"nickname"`
				ProfileImageURL string `json:"profile_image_url"`
			} `json:"profile"`
			Gender string `json:"gender"`
			Name   string `json:"name"`
		} `json:"kakao_account"`
	}

	// tokenInfo holds token response returned from Kakao token endpoint
	tokenInfo struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
)

// NewProvider initializes the Kakao OAuth2 provider with given settings
func NewProvider(setting oauth2.ProviderSetting) oauth2.Provider {
	return &provider{
		client:       setting.Client,
		clientID:     setting.ClientID,
		clientSecret: setting.ClientSecret,
		redirectURL:  setting.RedirectURL,
	}
}

// GetAuthURL generates the URL to redirect the user for Kakao OAuth2 login
func (k *provider) GetAuthURL(ctx context.Context, state string) (string, error) {
	if k.redirectURL == "" {
		return "", oauth2.WrapProviderError(ProviderType, oauth2.ErrRedirectURLNotSet, "")
	}

	query := url.Values{}
	query.Set("client_id", k.clientID)
	query.Set("redirect_uri", k.redirectURL)
	query.Set("response_type", "code")
	query.Set("state", state)

	return AuthURL + "?" + query.Encode(), nil
}

// GetToken exchanges the authorization code for an access token from Kakao
func (k *provider) GetToken(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	var tokenInfo tokenInfo

	if code == "" {
		return tokenInfo, oauth2.WrapProviderError(ProviderType, oauth2.ErrEmptyAuthCode, "")
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", k.clientID)
	form.Set("redirect_uri", k.redirectURL)
	form.Set("code", code)
	form.Set("client_secret", k.clientSecret)

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		TokenURL,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return tokenInfo, oauth2.WrapProviderError(
			ProviderType,
			oauth2.ErrTokenRequestFailed,
			err.Error(),
		)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := k.client.Do(req)
	if err != nil {
		return tokenInfo, oauth2.WrapProviderError(
			ProviderType,
			oauth2.ErrTokenRequestFailed,
			err.Error(),
		)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return tokenInfo, oauth2.WrapProviderError(
			ProviderType,
			oauth2.ErrTokenRequestFailed,
			err.Error(),
		)
	}

	if resp.StatusCode != http.StatusOK {
		return tokenInfo, oauth2.WrapProviderError(
			ProviderType,
			oauth2.ErrTokenRequestFailed,
			string(body),
		)
	}

	if err := json.Unmarshal(body, &tokenInfo); err != nil {
		return tokenInfo, oauth2.WrapProviderError(
			ProviderType,
			oauth2.ErrTokenRequestFailed,
			err.Error(),
		)
	}

	return tokenInfo, nil
}

// GetUserInfo retrieves the Kakao user's profile using the access token
func (k *provider) GetUserInfo(ctx context.Context, accessToken string) (oauth2.UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, UserInfoURL, nil)
	if err != nil {
		return nil, oauth2.WrapProviderError(
			ProviderType,
			oauth2.ErrUserInfoRequestFailed,
			err.Error(),
		)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := k.client.Do(req)
	if err != nil {
		return nil, oauth2.WrapProviderError(
			ProviderType,
			oauth2.ErrUserInfoRequestFailed,
			err.Error(),
		)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, oauth2.WrapProviderError(
			ProviderType,
			oauth2.ErrUserInfoRequestFailed,
			err.Error(),
		)
	}

	var userInfo userInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, oauth2.WrapProviderError(
			ProviderType,
			oauth2.ErrUserInfoRequestFailed,
			err.Error(),
		)
	}

	return &userInfo, nil
}

// RefreshToken exchanges a refresh token for a new access token from Kakao
func (k *provider) RefreshToken(
	ctx context.Context,
	refreshToken string,
) (oauth2.TokenInfo, error) {
	var tokenInfo tokenInfo

	if refreshToken == "" {
		return tokenInfo, oauth2.WrapProviderError(ProviderType, oauth2.ErrEmptyRefreshToken, "")
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", k.clientID)
	form.Set("refresh_token", refreshToken)
	form.Set("client_secret", k.clientSecret)

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		TokenURL,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return tokenInfo, oauth2.WrapProviderError(
			ProviderType,
			oauth2.ErrTokenRequestFailed,
			err.Error(),
		)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := k.client.Do(req)
	if err != nil {
		return tokenInfo, oauth2.WrapProviderError(
			ProviderType,
			oauth2.ErrTokenRequestFailed,
			err.Error(),
		)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return tokenInfo, oauth2.WrapProviderError(
			ProviderType,
			oauth2.ErrTokenRequestFailed,
			err.Error(),
		)
	}

	if resp.StatusCode != http.StatusOK {
		return tokenInfo, oauth2.WrapProviderError(
			ProviderType,
			oauth2.ErrTokenRequestFailed,
			string(body),
		)
	}

	if err := json.Unmarshal(body, &tokenInfo); err != nil {
		return tokenInfo, oauth2.WrapProviderError(
			ProviderType,
			oauth2.ErrTokenRequestFailed,
			err.Error(),
		)
	}

	return tokenInfo, nil
}

// GetProvider returns the provider type ("kakao")
func (k provider) GetProvider() oauth2.ProviderType { return ProviderType }

// GetID returns the user ID as string
func (k userInfo) GetID() string { return strconv.Itoa(k.ID) }

// GetEmail returns the user's email address
func (k userInfo) GetEmail() string { return k.AccountInfo.Email }

// GetName returns the user's nickname
func (k userInfo) GetName() string {
	if k.AccountInfo.Name == "" {
		return k.AccountInfo.Profile.NickName
	}
	return k.AccountInfo.Name
}

// GetGender returns the user's gender
func (k userInfo) GetGender() string { return k.AccountInfo.Gender }

// GetProfileImage returns the user's profile image URL
func (k userInfo) GetProfileImage() string { return k.AccountInfo.Profile.ProfileImageURL }

// GetAccessToken returns the OAuth2 access token
func (k tokenInfo) GetAccessToken() string { return k.AccessToken }

// GetRefreshToken returns the refresh token
func (k tokenInfo) GetRefreshToken() string { return k.RefreshToken }

// GetExpiry returns the access token's expiration time in seconds
func (k tokenInfo) GetExpiry() int { return k.ExpiresIn }
