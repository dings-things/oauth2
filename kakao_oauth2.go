package oauth2

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
)

const (
	// KakaoProvider : kakao login provider
	KakaoProvider ProviderType = "kakao"
	// kakaoUserInfoURL : kakao user info url
	kakaoUserInfoURL = "https://kapi.kakao.com/v2/user/me"
)

type (
	// kakaoOAuth2 : Kakao OAuth2 provider setting
	kakaoOAuth2 struct {
		clientID     string
		clientSecret string
	}

	// kakaoUserInfo : Kakao User Info
	kakaoUserInfo struct {
		ID          int `json:"id"`
		AccountInfo struct {
			Email           string `json:"email"`
			Nickname        string `json:"nickname"`
			ProfileImageURL string `json:"profile_image_url"`
		} `json:"kakao_account"`
	}
)

// WithKakaoOAuth2 : Kakao OAuth2 provider setting
func WithKakaoOAuth2(setting ProviderSetting) Provider {
	return kakaoOAuth2{
		clientID:     setting.clientID,
		clientSecret: setting.clientSecret,
	}
}

// GetUserInfo : Get user info from Kakao
func (k kakaoOAuth2) GetUserInfo(
	client *http.Client,
	accessToken string,
) (UserInfo, error) {
	req, err := http.NewRequest(http.MethodGet, kakaoUserInfoURL, nil)
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

	var userInfo *kakaoUserInfo
	if unmarshalErr := json.Unmarshal(body, &userInfo); unmarshalErr != nil {
		return nil, unmarshalErr
	}

	return userInfo, nil
}

/*
Fulfill UserInfo interface
*/

// GetProvider : Get provider
func (k kakaoOAuth2) GetProvider() ProviderType {
	return KakaoProvider
}

// GetID : Get ID from Kakao User Info
func (k kakaoUserInfo) GetID() string {
	return strconv.Itoa(k.ID)
}

// GetEmail : Get Email from Kakao User Info
func (k kakaoUserInfo) GetEmail() string {
	return k.AccountInfo.Email
}

// GetName : Get Name from Kakao User Info
func (k kakaoUserInfo) GetName() string {
	return k.AccountInfo.Nickname
}
