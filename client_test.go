package oauth2_test

import (
	"errors"
	"testing"

	"github.com/dings-things/oauth2"
	"github.com/stretchr/testify/assert"
)

type mockProvider struct {
	oauth2.Provider
	returnUserInfo oauth2.UserInfo
	returnToken    oauth2.TokenInfo
	errUserInfo    error
	errToken       error
	authURL        string
	authErr        error
	typ            oauth2.ProviderType
}

func (m *mockProvider) GetUserInfo(token string) (oauth2.UserInfo, error) {
	return m.returnUserInfo, m.errUserInfo
}

func (m *mockProvider) GetAccessToken(code string) (oauth2.TokenInfo, error) {
	return m.returnToken, m.errToken
}

func (m *mockProvider) GetAuthURL(state string) (string, error) {
	return m.authURL, m.authErr
}

func (m *mockProvider) GetProvider() oauth2.ProviderType {
	return m.typ
}

type dummyUser struct{}

func (d dummyUser) GetID() string           { return "id" }
func (d dummyUser) GetEmail() string        { return "email" }
func (d dummyUser) GetName() string         { return "name" }
func (d dummyUser) GetGender() string       { return "gender" }
func (d dummyUser) GetProfileImage() string { return "image" }

type dummyToken struct{}

func (d dummyToken) GetAccessToken() string  { return "access-token" }
func (d dummyToken) GetRefreshToken() string { return "refresh-token" }
func (d dummyToken) GetExpiry() int          { return 3600 }

func TestOAuth2Client_RequestUserInfo(t *testing.T) {
	client := oauth2.NewClient(&mockProvider{
		typ:            "google",
		returnUserInfo: dummyUser{},
		errUserInfo:    nil,
	})

	user, err := client.RequestUserInfo("google", "token")
	assert.NoError(t, err)
	assert.Equal(t, "id", user.GetID())

	_, err = client.RequestUserInfo("kakao", "token")
	assert.ErrorIs(t, err, oauth2.ErrProviderNotSet)
}

func TestOAuth2Client_RequestAccessToken(t *testing.T) {
	client := oauth2.NewClient(&mockProvider{
		typ:         "kakao",
		returnToken: dummyToken{},
		errToken:    nil,
	})

	token, err := client.RequestAccessToken("kakao", "code")
	assert.NoError(t, err)
	assert.Equal(t, "access-token", token)

	_, err = client.RequestAccessToken("naver", "code")
	assert.ErrorIs(t, err, oauth2.ErrProviderNotSet)
}

func TestOAuth2Client_RequestAuthURL(t *testing.T) {
	client := oauth2.NewClient(&mockProvider{
		typ:     "naver",
		authURL: "http://naver.com/auth",
		authErr: nil,
	})

	url := client.RequestAuthURL("naver", "state")
	assert.Equal(t, "http://naver.com/auth", url)

	emptyURL := client.RequestAuthURL("google", "state")
	assert.Empty(t, emptyURL)

	clientWithError := oauth2.NewClient(&mockProvider{
		typ:     "google",
		authErr: errors.New("url error"),
	})
	assert.Empty(t, clientWithError.RequestAuthURL("google", "state"))
}
