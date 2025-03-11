package oauth2

import (
	"encoding/json"
	"io"
	"net/http"
)

const (
	// naverProvider : naver login provider
	naverProvider ProviderType = "naver"
	// naverUserInfoURL : naver user info url
	naverUserInfoURL = "https://openapi.naver.com/v1/nid/me"
)

type (
	// naverOAuth2 : Naver OAuth2 provider setting
	naverOAuth2 struct {
		clientID     string
		clientSecret string
	}

	// naverUserInfo : Naver User Info
	naverUserInfo struct {
		Resultcode string `json:"resultcode"`
		Response   struct {
			ID           string `json:"id"`
			Email        string `json:"email"`
			Name         string `json:"name"`
			ProfileImage string `json:"profile_image"`
		} `json:"response"`
	}
)

// WithNaverOAuth2 : Naver OAuth2 provider setting
func WithNaverOAuth2(setting ProviderSetting) Provider {
	return naverOAuth2{
		clientID:     setting.clientID,
		clientSecret: setting.clientSecret,
	}
}

// GetUserInfo : Get user info from Naver
func (n naverOAuth2) GetUserInfo(
	client *http.Client,
	accessToken string,
) (UserInfo, error) {
	req, err := http.NewRequest(http.MethodGet, naverUserInfoURL, nil)
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

	var userInfo *naverUserInfo
	if unmarshalErr := json.Unmarshal(body, &userInfo); unmarshalErr != nil {
		return nil, unmarshalErr
	}

	return userInfo, nil
}

/*
Fulfill UserInfo interface
*/

// GetProvider : Get provider
func (n naverOAuth2) GetProvider() ProviderType {
	return naverProvider
}

// GetID : Get user id
func (n naverUserInfo) GetID() string {
	return n.Response.ID
}

// GetEmail : Get user email
func (n naverUserInfo) GetEmail() string {
	return n.Response.Email
}

// GetName : Get user name
func (n naverUserInfo) GetName() string {
	return n.Response.Name
}
