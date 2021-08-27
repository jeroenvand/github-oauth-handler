# Github Oauth Handler

Simple package for handling Github oauth flow.

Usage:
 - create a github oauth app
 - in your application, create a new Authenticator, providing the clientId and clientSecret from the app
 - hook-up the Authenticator to a http mux and make sure the url/path matches what you have passed to the Authenticator as well as with the Github oauth config
 - in your application, call .Token() to get a token. If you get an error/nil token, call .LoginURL() and redirect user there to login
 - after successful login, you can use the Authenticator in combination with https://pkg.go.dev/golang.org/x/oauth2. You can pass the Authenticator to NewClient as a TokenSource.
