package oauth2

import (
	"encoding/json"
	"io"
	"net/http"
)

const (
	// googleProvider : google login provider
	googleProvider ProviderType = "google"
	// googleUserInfoURL : google user info url
	googleUserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
)

type (
	// googleOAuth2 : Google OAuth2 provider setting
	googleOAuth2 struct {
		clientID     string
		clientSecret string
	}

	// googleUserInfo : Google User Info
	googleUserInfo struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
		Locale  string `json:"locale"`
	}
)

// WithGoogleOAuth2 : Google OAuth2 provider setting
func WithGoogleOAuth2(setting ProviderSetting) Provider {
	return googleOAuth2{
		clientID:     setting.clientID,
		clientSecret: setting.clientSecret,
	}
}

// GetUserInfo : Get user info from Google
func (g googleOAuth2) GetUserInfo(
	client *http.Client,
	accessToken string,
) (UserInfo, error) {
	req, err := http.NewRequest(http.MethodGet, googleUserInfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)

	var userInfo *googleUserInfo
	if unmarshalErr := json.Unmarshal(body, &userInfo); unmarshalErr != nil {
		return nil, unmarshalErr
	}

	return userInfo, nil
}

/*
Fulfill UserInfo interface
*/

// GetProvider : Get provider
func (g googleOAuth2) GetProvider() ProviderType {
	return googleProvider
}

// GetID : Get user id
func (g googleUserInfo) GetID() string {
	return g.ID
}

// GetEmail : Get user email
func (g googleUserInfo) GetEmail() string {
	return g.Email
}

// GetName : Get user name
func (g googleUserInfo) GetName() string {
	return g.Name
}
