package github_oauth_handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"
)

type ctxKeyGithubToken int
const GithubTokenKey ctxKeyGithubToken = 0
var CookieName = "x-github-token"

type Authenticator struct {
	mu           *sync.Mutex
	clientID     string
	clientSecret string
	scope        []string
	callbackURL  *url.URL
//	currentToken *oauth2.Token
}

type AuthenticatorOpts struct {
	Scope []GithubOauthScope
}

type GithubOauthScope string

var AuthScopes = struct {
	Repo          GithubOauthScope
	RepoStatus    GithubOauthScope
	AdminRepoHook GithubOauthScope
}{
	Repo:          "repo",
	RepoStatus:    "repo:status",
	AdminRepoHook: "admin:repo_hook",
}

func (s GithubOauthScope) Valid() bool {
	v := reflect.ValueOf(AuthScopes)

	for i := 0; i< v.NumField(); i++ {
		fmt.Printf("Checking scope: %v, %v\n", v.Field(i).String(), string(s))
		if v.Field(i).String() == string(s) {
			return true
		}
	}
	return false
}

func New(clientID string, clientSecret string, callbackURL *url.URL, opts AuthenticatorOpts) (*Authenticator, error) {
	var scopeStr []string
	for _, scope := range opts.Scope {
		if !scope.Valid() {
			return nil, fmt.Errorf("invalid scope: %v", scope)
		}
		scopeStr = append(scopeStr, string(scope))
	}
	a := &Authenticator{
		mu: &sync.Mutex{},
		clientID:     clientID,
		clientSecret: clientSecret,
		scope:       scopeStr,
		callbackURL:  callbackURL,
		//currentToken: nil,
	}
	return a, nil
}

func (a *Authenticator) LoginURL() string {
	return fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=%s",
		a.clientID, a.callbackURL.String(), strings.Join(a.scope, "%20"))
}

func (a *Authenticator) AuthenticateRequest(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		// always let calls to the callback pass
		if r.URL.Path == a.callbackURL.Path {
			next.ServeHTTP(w, r)
			return
		}

		var token *oauth2.Token

		// try to fetch existing token from cookie
		c, err := r.Cookie(CookieName)
		if err == nil {
			tokenStr, err := base64.StdEncoding.DecodeString(c.Value)
			if err == nil {
				err = json.Unmarshal(tokenStr, &token)
				if err != nil {
					token = nil
				}
			}
		}

		if token != nil && token.Valid() {
			// if token is found & valid, use it
			ctx := context.WithValue(r.Context(), GithubTokenKey, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		} else {
			// otherwise, send user to Github for login & authorisation
			http.Redirect(w, r, a.LoginURL(), http.StatusSeeOther)
		}
	}

	return http.HandlerFunc(fn)
}

func (a *Authenticator) CallbackHandler(redirectAfterLogin *url.URL) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println("Entering callback handler")
		a.mu.Lock()
		defer a.mu.Unlock()
		code := r.URL.Query().Get("code")
		token, err := a.GetAccessToken(code)
		if err != nil {
			http.Error(w, "error retrieving access token", http.StatusInternalServerError)
			return
		}
		//a.currentToken = token
		log.Printf("redirecting to after login url: %s", redirectAfterLogin.String())
		data, err := json.Marshal(token)
		if err != nil {
			http.Error(w, "error encoding token", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:       CookieName,
			Value:      base64.StdEncoding.EncodeToString(data),
			Path:       "/",
			Secure:     false,
			HttpOnly:   false,
		})

		http.Redirect(w, r, redirectAfterLogin.String(), http.StatusSeeOther)
		log.Println("callback handler finished")
	}
}

func (a *Authenticator) GetAccessToken(code string) (*oauth2.Token, error) {

	requestBodyMap := map[string]string{"client_id": a.clientID, "client_secret": a.clientSecret, "code": code}
	requestJSON, _ := json.Marshal(requestBodyMap)
	log.Println("fetching access token from github")
	req, reqerr := http.NewRequest("POST", "https://github.com/login/oauth/access_token", bytes.NewBuffer(requestJSON))
	if reqerr != nil {
		return nil, reqerr
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, resperr := http.DefaultClient.Do(req)
	if resperr != nil {
		return nil, resperr
	}

	respbody, _ := ioutil.ReadAll(resp.Body)

	// Represents the response received from Github
	type githubAccessTokenResponse struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}

	var ghresp githubAccessTokenResponse
	_ = json.Unmarshal(respbody, &ghresp)
	log.Println("received access token from github")
	log.Printf("token type: %s, token: %s, expires_in: %v", ghresp.TokenType, ghresp.AccessToken, ghresp.ExpiresIn)

	var expiry time.Time
	if ghresp.ExpiresIn > 0 {
		expiry = time.Now().Add(time.Duration(ghresp.ExpiresIn) * time.Second)
	}
	token := &oauth2.Token{
		AccessToken:  ghresp.AccessToken,
		TokenType:    ghresp.TokenType,
		RefreshToken: ghresp.RefreshToken,
		Expiry:       expiry,
	}
	return token, nil
}

func (a *Authenticator) RefreshToken(currentToken *oauth2.Token) (*oauth2.Token, error) {
	requestBodyMap := map[string]string{"client_id": a.clientID, "client_secret": a.clientSecret,
		"refresh_token": currentToken.RefreshToken, "grant_type": "refresh_token"}
	requestJSON, _ := json.Marshal(requestBodyMap)

	req, reqerr := http.NewRequest("POST", "https://github.com/login/oauth/access_token", bytes.NewBuffer(requestJSON))
	if reqerr != nil {
		return nil, reqerr
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, resperr := http.DefaultClient.Do(req)
	if resperr != nil {
		return nil, resperr
	}

	respbody, _ := ioutil.ReadAll(resp.Body)

	// Represents the response received from Github
	type githubAccessTokenResponse struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}

	var ghresp githubAccessTokenResponse
	_ = json.Unmarshal(respbody, &ghresp)

	newToken := &oauth2.Token{
		AccessToken:  ghresp.AccessToken,
		TokenType:    ghresp.TokenType,
		RefreshToken: ghresp.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(ghresp.ExpiresIn) * time.Second),
	}
	return newToken, nil
}

