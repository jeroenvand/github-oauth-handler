package github_oauth_handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/go-github/v35/github"
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

type ctxKeyGithubUser int

const GithubUserKey ctxKeyGithubToken = 0

var CookieName = "x-github-token"

type Identity struct {
	Username string
	Token    *oauth2.Token
}
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

	for i := 0; i < v.NumField(); i++ {
		fmt.Printf("Checking scope: %v, %v\n", v.Field(i).String(), string(s))
		if v.Field(i).String() == string(s) {
			return true
		}
	}
	return false
}

func GetTokenFromContext(ctx context.Context) (*oauth2.Token, bool) {
	v := ctx.Value(GithubTokenKey)
	if v != nil {
		if tkn, ok := v.(*oauth2.Token); ok {
			return tkn, ok
		}
	}
	return nil, false
}

func (a *Authenticator) GetTokenFromContext(ctx context.Context) (*oauth2.Token, bool) {
	return GetTokenFromContext(ctx)
}

func (a *Authenticator) GetUsernameFromContext(ctx context.Context) (string, bool) {
	v := ctx.Value(GithubUserKey)
	if v != nil {
		if username, ok := v.(string); ok {
			return username, ok
		}
	}
	return "", false
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
		mu:           &sync.Mutex{},
		clientID:     clientID,
		clientSecret: clientSecret,
		scope:        scopeStr,
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

		var identity *Identity

		// try to fetch existing token from cookie
		c, err := r.Cookie(CookieName)
		if err == nil {
			data, err := base64.StdEncoding.DecodeString(c.Value)
			if err == nil {
				err = json.Unmarshal(data, &identity)
				if err != nil {
					identity = nil
				}
			}
		}

		if identity.Token != nil && identity.Token.Valid() {
			// if token is found & valid, use it
			ctx := context.WithValue(r.Context(), GithubTokenKey, identity.Token)
			ctx = context.WithValue(ctx, GithubUserKey, identity.Username)
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
		user, err := a.GetUserData(r.Context(), token)
		if err != nil {
			http.Error(w, "error retrieving user data", http.StatusInternalServerError)
			return
		}
		//a.currentToken = token
		log.Printf("redirecting to after login url: %s", redirectAfterLogin.String())
		data, err := json.Marshal(Identity{
			Username: user.GetLogin(),
			Token:    token,
		})
		if err != nil {
			http.Error(w, "error encoding token", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     CookieName,
			Value:    base64.StdEncoding.EncodeToString(data),
			Path:     "/",
			Secure:   false,
			HttpOnly: false,
		})

		http.Redirect(w, r, redirectAfterLogin.String(), http.StatusSeeOther)
		log.Println("callback handler finished")
	}
}

func (a *Authenticator) GetGithubClientFromRequest(r *http.Request) (*github.Client, error) {
	ctx := r.Context()
	token, ok := GetTokenFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("missing github token")
	}
	return a.makeGithubClient(ctx, token), nil
}

func (a *Authenticator) makeGithubClient(ctx context.Context, token *oauth2.Token) *github.Client {
	ts := oauth2.StaticTokenSource(token)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)
	return client
}
func (a *Authenticator) GetUserData(ctx context.Context, token *oauth2.Token) (*github.User, error) {
	client := a.makeGithubClient(ctx, token)
	user, _, err := client.Users.Get(ctx, "")
	if err != nil {
		return nil, err
	}
	return user, nil
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
