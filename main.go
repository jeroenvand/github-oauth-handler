package github_oauth_handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"
)

type Authenticator struct {
	mu           *sync.Mutex
	clientID     string
	clientSecret string
	scope        []string
	callbackURL  *url.URL
	currentToken *oauth2.Token
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
		currentToken: nil,
	}
	return a, nil
}

func (a *Authenticator) Token() (*oauth2.Token, error) {
	a.mu.Lock()
	defer a.mu.Lock()
	if a.currentToken == nil {
		// no token, must login first
		return nil, fmt.Errorf("not authenticated")
	}
	if time.Now().After(a.currentToken.Expiry) {
		// token expired, try to refresh token
		newToken, err := a.refreshToken()
		if err != nil {
			return nil, err
		}
		a.currentToken = newToken
	}
	return &oauth2.Token{
		AccessToken:  a.currentToken.AccessToken,
		TokenType:    a.currentToken.TokenType,
		RefreshToken: a.currentToken.RefreshToken,
		Expiry:       a.currentToken.Expiry,
	}, nil
}

func (a *Authenticator) LoginURL() string {
	return fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=%s",
		a.clientID, a.callbackURL.String(), strings.Join(a.scope, "%20"))
}

func (a *Authenticator) CallbackHandler(redirectAfterLogin *url.URL) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Lock()
		code := r.URL.Query().Get("code")
		token, err := a.getAccessToken(code)
		if err != nil {
			http.Error(w, "error retrieving access token", http.StatusInternalServerError)
		}
		a.currentToken = token
		http.Redirect(w, r, redirectAfterLogin.String(), http.StatusSeeOther)
	}
}

func (a *Authenticator) getAccessToken(code string) (*oauth2.Token, error) {

	requestBodyMap := map[string]string{"client_id": a.clientID, "client_secret": a.clientSecret, "code": code}
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

	token := &oauth2.Token{
		AccessToken:  ghresp.AccessToken,
		TokenType:    ghresp.TokenType,
		RefreshToken: ghresp.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(ghresp.ExpiresIn) * time.Second),
	}
	return token, nil
}

func (a *Authenticator) refreshToken() (*oauth2.Token, error) {
	if a.currentToken == nil {
		return nil, fmt.Errorf("not authenticated")
	}
	requestBodyMap := map[string]string{"client_id": a.clientID, "client_secret": a.clientSecret,
		"refresh_token": a.currentToken.RefreshToken, "grant_type": "refresh_token"}
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

	token := &oauth2.Token{
		AccessToken:  ghresp.AccessToken,
		TokenType:    ghresp.TokenType,
		RefreshToken: ghresp.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(ghresp.ExpiresIn) * time.Second),
	}
	return token, nil
}

// reflectStructField checks if an interface is either a struct or a pointer to a struct
// and has the defined member field, if error is nil, the given
// FieldName exists and is accessible with reflect.
func reflectStructField(Iface interface{}, FieldName string) error {
	ValueIface := reflect.ValueOf(Iface)

	// Check if the passed interface is a pointer
	if ValueIface.Type().Kind() != reflect.Ptr {
		// Create a new type of Iface's Type, so we have a pointer to work with
		ValueIface = reflect.New(reflect.TypeOf(Iface))
	}

	// 'dereference' with Elem() and get the field by name
	Field := ValueIface.Elem().FieldByName(FieldName)
	if !Field.IsValid() {
		return fmt.Errorf("Interface `%s` does not have the field `%s`", ValueIface.Type(), FieldName)
	}
	return nil
}
