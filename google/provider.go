package google

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/dings-things/oauth2"
)

const (
	// ProviderType is the identifier for the Google OAuth2 provider
	//   - REFS : https://developers.google.com/identity/protocols/oauth2?hl=ko
	ProviderType oauth2.ProviderType = "google"

	// UserInfoURL is the endpoint to retrieve user profile information
	UserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"

	// AuthURL is the endpoint to start the OAuth2 authorization flow
	AuthURL = "https://accounts.google.com/o/oauth2/v2/auth"

	// TokenURL is the endpoint to exchange the authorization code for an access token
	TokenURL = "https://oauth2.googleapis.com/token"
)

type (
	// provider holds the configuration for Google's OAuth2 implementation
	provider struct {
		client       *http.Client
		clientID     string
		clientSecret string
		redirectURL  string
	}

	// userInfo represents the user information returned from Google
	userInfo struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
		Locale  string `json:"locale"`
	}

	// tokenInfo represents the token information returned from Google
	tokenInfo struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}
)

// WithGoogleProvider initializes and returns a new Google OAuth2 provider
func WithGoogleProvider(setting oauth2.ProviderSetting) oauth2.Provider {
	return &provider{
		client:       setting.Client,
		clientID:     setting.ClientID,
		clientSecret: setting.ClientSecret,
		redirectURL:  setting.RedirectURL,
	}
}

// GetUserInfo retrieves the user profile information from Google using the access token
func (g *provider) GetUserInfo(accessToken string) (oauth2.UserInfo, error) {
	req, err := http.NewRequest(http.MethodGet, UserInfoURL, nil)
	if err != nil {
		return nil, oauth2.WrapProviderError(ProviderType, oauth2.ErrUserInfoRequestFailed, err.Error())
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	response, err := g.client.Do(req)
	if err != nil {
		return nil, oauth2.WrapProviderError(ProviderType, oauth2.ErrUserInfoRequestFailed, err.Error())
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, oauth2.WrapProviderError(ProviderType, oauth2.ErrUserInfoRequestFailed, err.Error())
	}

	var userInfo *userInfo
	if unmarshalErr := json.Unmarshal(body, &userInfo); unmarshalErr != nil {
		return nil, oauth2.WrapProviderError(ProviderType, oauth2.ErrUserInfoRequestFailed, unmarshalErr.Error())
	}

	return userInfo, nil
}

// GetAuthURL constructs the Google OAuth2 authorization URL
func (g *provider) GetAuthURL(state string) (string, error) {
	if g.redirectURL == "" {
		return "", oauth2.WrapProviderError(ProviderType, oauth2.ErrRedirectURLNotSet, "")
	}

	scopes := []string{
		"openid",
		"email",
		"profile",
	}

	query := url.Values{}
	query.Set("client_id", g.clientID)
	query.Set("redirect_uri", g.redirectURL)
	query.Set("response_type", "code")
	query.Set("scope", strings.Join(scopes, " "))
	query.Set("state", state)
	query.Set("access_type", "offline")
	query.Set("prompt", "consent")

	return AuthURL + "?" + query.Encode(), nil
}

// GetAccessToken exchanges the authorization code for an access token from Google
func (g *provider) GetAccessToken(code string) (oauth2.TokenInfo, error) {
	var tokenInfo tokenInfo
	if code == "" {
		return tokenInfo, oauth2.WrapProviderError(ProviderType, oauth2.ErrEmptyAuthCode, "")
	}

	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", g.clientID)
	form.Set("client_secret", g.clientSecret)
	form.Set("redirect_uri", g.redirectURL)
	form.Set("grant_type", "authorization_code")

	req, err := http.NewRequest(http.MethodPost, TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenInfo, oauth2.WrapProviderError(ProviderType, oauth2.ErrTokenRequestFailed, err.Error())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := g.client.Do(req)
	if err != nil {
		return tokenInfo, oauth2.WrapProviderError(ProviderType, oauth2.ErrTokenRequestFailed, err.Error())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return tokenInfo, oauth2.WrapProviderError(ProviderType, oauth2.ErrTokenRequestFailed, err.Error())
	}

	if resp.StatusCode != http.StatusOK {
		return tokenInfo, oauth2.WrapProviderError(ProviderType, oauth2.ErrTokenRequestFailed, string(body))
	}

	if err := json.Unmarshal(body, &tokenInfo); err != nil {
		return tokenInfo, oauth2.WrapProviderError(ProviderType, oauth2.ErrTokenRequestFailed, err.Error())
	}

	return tokenInfo, nil
}

// GetProvider returns the provider type ("google")
func (g provider) GetProvider() oauth2.ProviderType { return ProviderType }

// GetID returns the user's Google ID
func (g userInfo) GetID() string { return g.ID }

// GetEmail returns the user's email address
func (g userInfo) GetEmail() string { return g.Email }

// GetName returns the user's full name
func (g userInfo) GetName() string { return g.Name }

// GetAccessToken returns the OAuth2 access token
func (g tokenInfo) GetAccessToken() string { return g.AccessToken }

// GetRefreshToken returns the OAuth2 refresh token
func (g tokenInfo) GetRefreshToken() string { return g.RefreshToken }

// GetExpiry returns the token expiration time in seconds
func (g tokenInfo) GetExpiry() int { return g.ExpiresIn }
