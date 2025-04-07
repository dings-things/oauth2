package oauth2

import (
	"fmt"
)

var (
	ErrProviderNotSet        = fmt.Errorf("provider not set")
	ErrRedirectURLNotSet     = fmt.Errorf("redirect URL is not set for provider")
	ErrEmptyAuthCode         = fmt.Errorf("authorization code is empty")
	ErrTokenRequestFailed    = fmt.Errorf("failed to get access token")
	ErrUserInfoRequestFailed = fmt.Errorf("failed to get user info")
	ErrEmptyRefreshToken     = fmt.Errorf("refresh token is empty")
)

func WrapProviderError(provider ProviderType, base error, context string) error {
	return fmt.Errorf("%s provider: %w: %s", provider, base, context)
}
