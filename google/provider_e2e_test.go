//go:build e2e
// +build e2e

package google_test

import (
	"log"
	"os"
	"testing"

	"github.com/dings-things/oauth2"
	"github.com/dings-things/oauth2/google"
)

var (
	clientID     = os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	redirectURL  = os.Getenv("GOOGLE_REDIRECT_URL")
	code         = os.Getenv("GOOGLE_AUTH_CODE")    // Manually obtained code
	accessToken  = os.Getenv("GOOGLE_ACCESS_TOKEN") // Access token (optional if you already have one)
)

// skipInCI skips the test if it's running in a CI environment.
func skipInCI(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("Skipping OAuth2 flow in CI environment")
	}
}

// newProvider initializes the Google provider with env config.
func newProvider() oauth2.Provider {
	return google.WithGoogleProvider(oauth2.ProviderSetting{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Client:       nil,
	})
}

// TestGetAuthURL prints the Google OAuth2 login URL for manual testing.
func TestGetAuthURL(t *testing.T) {
	skipInCI(t)

	provider := newProvider()
	state := "test-state"

	url, err := provider.GetAuthURL(state)
	if err != nil {
		t.Fatalf("failed to get auth URL: %v", err)
	}

	log.Println("Visit the following URL in your browser to authenticate:")
	log.Println(url)
}

// TestGetAccessToken exchanges an authorization code for an access token.
func TestGetAccessToken(t *testing.T) {
	skipInCI(t)

	if code == "" {
		t.Skip("GOOGLE_AUTH_CODE is not set")
	}

	provider := newProvider()

	token, err := provider.GetAccessToken(code)
	if err != nil {
		t.Fatalf("failed to exchange code for token: %v", err)
	}

	log.Println("Access Token:", token.GetAccessToken())
	log.Println("Refresh Token:", token.GetRefreshToken())
	log.Println("Expires In:", token.GetExpiry())
}

// TestGetUserInfo fetches the user's profile info using the access token.
func TestGetUserInfo(t *testing.T) {
	skipInCI(t)

	if accessToken == "" {
		t.Skip("GOOGLE_ACCESS_TOKEN is not set")
	}

	provider := newProvider()

	user, err := provider.GetUserInfo(accessToken)
	if err != nil {
		t.Fatalf("failed to get user info: %v", err)
	}

	log.Println("User ID:", user.GetID())
	log.Println("Email:", user.GetEmail())
	log.Println("Name:", user.GetName())
}
