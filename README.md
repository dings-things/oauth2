# OAuth2 Module for Go

This module provides a unified and extensible OAuth2 client implementation in Go, supporting multiple providers such as Google, Kakao, and Naver. It allows you to easily fetch user information from different OAuth2 providers with a simple interface.

---

## Features

- **Unified API**: Fetch user information from various OAuth2 providers using a single interface.
- **Customizable**: Support for adding new providers via a functional option pattern.
- **Standardized User Information**: Provides a common `UserInfo` interface, making it easy to integrate with different OAuth providers.
- **Flexible Configuration**: Supports dynamic registration of providers with client credentials.

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
package main

import (
	"fmt"
	"net/http"
	"github.com/yourrepo/oauth2"
)

func main() {
	client := &http.Client{}

oauthClient := oauth2.NewClient(client,
		oauth2.WithGoogleOAuth2(oauth2.ProviderSetting{clientID: "your-google-client-id", clientSecret: "your-google-client-secret"}),
		oauth2.WithKakaoOAuth2(oauth2.ProviderSetting{clientID: "your-kakao-client-id", clientSecret: "your-kakao-client-secret"}),
		oauth2.WithNaverOAuth2(oauth2.ProviderSetting{clientID: "your-naver-client-id", clientSecret: "your-naver-client-secret"}),
	)
}
```

---

### Fetching User Information from an OAuth2 Provider

#### Example: Fetching Google User Info

```go
accessToken := "your-access-token"
userInfo, err := oauthClient.GetUserInfo(oauth2.GoogleOAuthProvider, accessToken)
if err != nil {
	fmt.Println("Error fetching user info:", err)
	return
}

fmt.Println("User ID:", userInfo.GetID())
fmt.Println("User Email:", userInfo.GetEmail())
fmt.Println("User Name:", userInfo.GetName())
```

#### Example: Fetching Kakao User Info

```go
accessToken := "your-access-token"
userInfo, err := oauthClient.GetUserInfo(oauth2.KakaoOAuthProvider, accessToken)
if err != nil {
	fmt.Println("Error fetching Kakao user info:", err)
	return
}

fmt.Println("Kakao User ID:", userInfo.GetID())
fmt.Println("Kakao User Email:", userInfo.GetEmail())
fmt.Println("Kakao User Name:", userInfo.GetName())
```

#### Example: Fetching Naver User Info

```go
accessToken := "your-access-token"
userInfo, err := oauthClient.GetUserInfo(oauth2.NaverOAuthProvider, accessToken)
if err != nil {
	fmt.Println("Error fetching Naver user info:", err)
	return
}

fmt.Println("Naver User ID:", userInfo.GetID())
fmt.Println("Naver User Email:", userInfo.GetEmail())
fmt.Println("Naver User Name:", userInfo.GetName())
```

---

## License

This project is licensed under the MIT License.