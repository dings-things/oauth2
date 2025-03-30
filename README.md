# OAuth2 Module for Go

This module provides a unified and extensible OAuth2 client implementation in Go, supporting multiple providers such as Google, Kakao, and Naver. It allows you to easily fetch user information from different OAuth2 providers with a simple interface.

---

## Features

- **Unified API**: Fetch user information from various OAuth2 providers using a single interface.
- **Customizable**: Support for adding new providers via a functional option pattern.
- **Standardized User Information**: Provides a common `UserInfo` interface, making it easy to integrate with different OAuth providers.
- **Flexible Configuration**: Supports dynamic registration of providers with client credentials.
- **Access Token Retrieval**: Easily retrieve access tokens using authorization codes.
- **Authorization URL Generation**: Generate provider-specific auth URLs to redirect users securely.
- **Error Wrapping**: Provides wrapped errors with context (e.g., which provider, what kind of error).
- **Testability**: Designed to allow mocking via custom `http.RoundTripper` or injecting custom `http.Client` for unit testing.

---

## Installation

To install the package, use:

```sh
 go get github.com/dings-things/oauth2
```

---

## Why Use This OAuth2 Module?

OAuth2 is the industry-standard protocol for authentication and authorization. This module abstracts the complexity of integrating multiple providers while offering:

1. **Security**: Ensures proper token handling and provider communication.
2. **Simplicity**: Reduces boilerplate code and standardizes user authentication across providers.
3. **Scalability**: Easily extendable to support new OAuth2 providers.

---

## Usage

### Creating an OAuth2 Client

```go
client := &http.Client{}

oauthClient := oauth2.NewClient(client,
	oauth2.WithGoogleProvider(oauth2.ProviderSetting{
		Client: client,
		ClientID: "your-google-client-id",
		ClientSecret: "your-google-client-secret",
		RedirectURL: "http://localhost/google/callback",
	}),
	oauth2.WithKakaoProvider(oauth2.ProviderSetting{
		Client: client,
		ClientID: "your-kakao-client-id",
		ClientSecret: "your-kakao-client-secret",
		RedirectURL: "http://localhost/kakao/callback",
	}),
	oauth2.WithNaverProvider(oauth2.ProviderSetting{
		Client: client,
		ClientID: "your-naver-client-id",
		ClientSecret: "your-naver-client-secret",
		RedirectURL: "http://localhost/naver/callback",
	}),
)
```

---

### Fetching Authorization URL from a Provider

```go
state := "secure-random-state"
authURL := oauthClient.RequestAuthURL(oauth2.ProviderType("google"), state)
fmt.Println("Redirect user to:", authURL)
```

---

### Exchanging Authorization Code for Access Token

```go
code := "code-from-callback"
token, err := oauthClient.RequestAccessToken(oauth2.ProviderType("google"), code)
if err != nil {
	log.Fatal("failed to exchange code for token:", err)
}
fmt.Println("Access Token:", token)
```

---

### Fetching User Information from an OAuth2 Provider

```go
accessToken := "your-access-token"
userInfo, err := oauthClient.RequestUserInfo(oauth2.ProviderType("google"), accessToken)
if err != nil {
	fmt.Println("Error fetching user info:", err)
	return
}

fmt.Println("User ID:", userInfo.GetID())
fmt.Println("User Email:", userInfo.GetEmail())
fmt.Println("User Name:", userInfo.GetName())
```

---

## Testing

This module is designed with testability in mind:

- Providers use `http.Client` which allows custom `Transport` injection for mocking.
- Each provider can be tested in isolation.
- The `oauth2.Client` can be tested with mocked providers or by injecting round-tripper logic.

---

## License

This project is licensed under the MIT License.
