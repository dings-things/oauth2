package naver

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
	// ProviderType represents the Naver OAuth2 provider
	//   - REFS : https://developers.naver.com/docs/login/devguide/devguide.md
	ProviderType oauth2.ProviderType = "naver"

	// UserInfoURL is the endpoint for retrieving user information
	UserInfoURL = "https://openapi.naver.com/v1/nid/me"

	// AuthURL is the endpoint for initiating the authorization flow
	AuthURL = "https://nid.naver.com/oauth2.0/authorize"

	// TokenURL is the endpoint to exchange an authorization code for an access token
	TokenURL = "https://nid.naver.com/oauth2.0/token"
)

type (
	// provider defines the Naver OAuth2 provider settings
	provider struct {
		client       *http.Client
		clientID     string
		clientSecret string
		redirectURL  string
	}

	// userInfo represents the response structure from Naver's user info API
	userInfo struct {
		Resultcode string `json:"resultcode"`
		Response   struct {
			ID           string `json:"id"`
			Email        string `json:"email"`
			Name         string `json:"name"`
			ProfileImage string `json:"profile_image"`
			Gender       string `json:"gender"`
		} `json:"response"`
	}

	// tokenInfo represents the response structure for access token requests
	tokenInfo struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    string `json:"expires_in"`
	}
)

// NewProvider initializes and returns a new Naver OAuth2 provider
func NewProvider(setting oauth2.ProviderSetting) oauth2.Provider {
	return &provider{
		client:       setting.Client,
		clientID:     setting.ClientID,
		clientSecret: setting.ClientSecret,
		redirectURL:  setting.RedirectURL,
	}
}

// GetAuthURL generates the authorization URL to redirect the user to Naver's login screen
func (n *provider) GetAuthURL(ctx context.Context, state string) (string, error) {
	if n.redirectURL == "" {
		return "", oauth2.WrapProviderError(ProviderType, oauth2.ErrRedirectURLNotSet, "")
	}

	query := url.Values{}
	query.Set("response_type", "code")
	query.Set("client_id", n.clientID)
	query.Set("redirect_uri", n.redirectURL)
	query.Set("state", state)

	return AuthURL + "?" + query.Encode(), nil
}

// GetToken exchanges the authorization code for an access token from Naver
func (n *provider) GetToken(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	var tokenInfo tokenInfo

	if code == "" {
		return tokenInfo, oauth2.WrapProviderError(ProviderType, oauth2.ErrEmptyAuthCode, "")
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", n.clientID)
	form.Set("client_secret", n.clientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", n.redirectURL)

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

	resp, err := n.client.Do(req)
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

// GetUserInfo retrieves user information from Naver using the access token
func (n *provider) GetUserInfo(ctx context.Context, accessToken string) (oauth2.UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, UserInfoURL, nil)
	if err != nil {
		return nil, oauth2.WrapProviderError(
			ProviderType,
			oauth2.ErrUserInfoRequestFailed,
			err.Error(),
		)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := n.client.Do(req)
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

// RefreshToken exchanges a refresh token for a new access token from Naver
func (n *provider) RefreshToken(
	ctx context.Context,
	refreshToken string,
) (oauth2.TokenInfo, error) {
	var tokenInfo tokenInfo

	if refreshToken == "" {
		return tokenInfo, oauth2.WrapProviderError(ProviderType, oauth2.ErrEmptyRefreshToken, "")
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", n.clientID)
	form.Set("client_secret", n.clientSecret)
	form.Set("refresh_token", refreshToken)

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

	resp, err := n.client.Do(req)
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

// GetProvider returns the provider type ("naver")
func (n provider) GetProvider() oauth2.ProviderType { return ProviderType }

// GetID returns the user's ID
func (n userInfo) GetID() string { return n.Response.ID }

// GetEmail returns the user's email
func (n userInfo) GetEmail() string { return n.Response.Email }

// GetName returns the user's name
func (n userInfo) GetName() string { return n.Response.Name }

// GetGender returns the user's gender
func (n userInfo) GetGender() string { return n.Response.Gender }

// GetProfileImage returns the user's profile image URL
func (n userInfo) GetProfileImage() string { return n.Response.ProfileImage }

// GetAccessToken returns the access token string
func (n tokenInfo) GetAccessToken() string { return n.AccessToken }

// GetRefreshToken returns the refresh token string
func (n tokenInfo) GetRefreshToken() string { return n.RefreshToken }

// GetExpiry returns the expiry time in seconds (converted from string)
func (n tokenInfo) GetExpiry() int {
	sec, _ := strconv.Atoi(n.ExpiresIn)
	return sec
}
