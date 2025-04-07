package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/dings-things/oauth2"
	"github.com/dings-things/oauth2/google"
	"github.com/dings-things/oauth2/kakao"
	"github.com/dings-things/oauth2/naver"
)

type userProfileView struct {
	Name    string
	Email   string
	Gender  string
	Picture string
}

var (
	client oauth2.Client
	tmpl   *template.Template
)

func main() {
	path, _ := filepath.Abs("templates/*.html")
	tmpl = template.Must(template.ParseGlob(path))

	httpClient := http.DefaultClient
	client = oauth2.NewClient(
		google.WithGoogleProvider(oauth2.ProviderSetting{
			Client:       httpClient,
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
		}),
		naver.WithNaverProvider(oauth2.ProviderSetting{
			Client:       httpClient,
			ClientID:     os.Getenv("NAVER_CLIENT_ID"),
			ClientSecret: os.Getenv("NAVER_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("NAVER_REDIRECT_URL"),
		}),
		kakao.WithKakaoProvider(oauth2.ProviderSetting{
			Client:       httpClient,
			ClientID:     os.Getenv("KAKAO_CLIENT_ID"),
			ClientSecret: os.Getenv("KAKAO_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("KAKAO_REDIRECT_URL"),
		}),
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleHome)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/callback", handleCallback)

	log.Println("✅ Server started at: http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", loggingMiddleware(mux)))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	if err := tmpl.ExecuteTemplate(w, "home.html", nil); err != nil {
		http.Error(w, "failed to render home page", http.StatusInternalServerError)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	provider := oauth2.ProviderType(r.URL.Query().Get("provider"))
	if provider == "" {
		http.Error(w, "provider query param is required", http.StatusBadRequest)
		return
	}

	state := generateRandomState()
	setOAuthStateCookie(w, state)

	authURL := client.RequestAuthURL(provider, state)
	if authURL == "" {
		http.Error(w, "failed to generate auth URL", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	provider := oauth2.ProviderType(r.URL.Query().Get("provider"))
	if provider == "" {
		http.Error(w, "provider query param is required", http.StatusBadRequest)
		return
	}

	queryState := r.URL.Query().Get("state")
	if queryState == "" {
		http.Error(w, "state query param is required", http.StatusBadRequest)
		return
	}

	cookieState, err := getOAuthStateCookie(r)
	if err != nil || queryState != cookieState {
		http.Error(w, "state mismatch (possible CSRF)", http.StatusForbidden)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "code query param is required", http.StatusBadRequest)
		return
	}

	accessToken, err := client.RequestToken(provider, code)
	if err != nil {
		http.Error(w, "failed to get access token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("[OAuth] AccessToken received: %s", accessToken)

	user, err := client.RequestUserInfo(provider, accessToken.GetAccessToken())
	if err != nil {
		http.Error(w, "failed to get user info: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf(
		"[OAuth] User info: ID=%s, Name=%s, Email=%s, Gender=%s",
		user.GetID(),
		user.GetName(),
		user.GetEmail(),
		user.GetGender(),
	)

	view := userProfileView{
		Name:    user.GetName(),
		Email:   user.GetEmail(),
		Gender:  user.GetGender(),
		Picture: user.GetProfileImage(),
	}

	if err := tmpl.ExecuteTemplate(w, "profile.html", view); err != nil {
		http.Error(w, "failed to render profile", http.StatusInternalServerError)
	}
}

func setOAuthStateCookie(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})
}

func getOAuthStateCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie("oauth_state")
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

func generateRandomState() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "fallback-state"
	}
	return hex.EncodeToString(b)
}

// ─────────────────────────────────────
// 🔍 Logging Middleware (Req/Resp)
// ─────────────────────────────────────

type responseCapture struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
}

func (rc *responseCapture) WriteHeader(code int) {
	rc.statusCode = code
	rc.ResponseWriter.WriteHeader(code)
}

func (rc *responseCapture) Write(b []byte) (int, error) {
	rc.body.Write(b)                  // copy response
	return rc.ResponseWriter.Write(b) // write to client
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Read and copy request body
		var reqBody []byte
		if r.Body != nil {
			reqBody, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewBuffer(reqBody)) // restore
		}

		// Wrap response writer
		rc := &responseCapture{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
			body:           new(bytes.Buffer),
		}

		// Serve request
		next.ServeHTTP(rc, r)
		duration := time.Since(start)

		// Logging
		log.Printf("[HTTP] %s %s → %d (%dms)\nRequest Body: %s\nResponse Body: %s\n",
			r.Method,
			r.URL.Path,
			rc.statusCode,
			duration.Milliseconds(),
			string(reqBody),
			rc.body.String(),
		)
	})
}
