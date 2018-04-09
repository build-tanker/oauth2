package oauth2

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/build-tanker/archer"
	"github.com/tidwall/gjson"
)

// More details here - https://developers.google.com/identity/protocols/OAuth2WebServer#protectauthcode
// And here https://developers.google.com/identity/protocols/OAuth2UserAgent#validate-access-token

const (
	scopeUserInfoEmail   = "https://www.googleapis.com/auth/userinfo.email"
	scopeUserInfoProfile = "https://www.googleapis.com/auth/userinfo.profile"

	accessTypeOnline  = "online"
	accessTypeOffline = "offline"

	promptConsent       = "consent"
	promptSelectAccount = "select_account"

	authTokenURL      = "https://accounts.google.com/o/oauth2/v2/auth?scope=%s&access_type=%s&include_granted_scopes=%s&state=%s&redirect_uri=%s&response_type=code&login_hint=%s&prompt=%s&client_id=%s"
	getTokenURL       = "https://www.googleapis.com/oauth2/v4/token"
	verifyTokenURL    = "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=%s"
	refreshTokenURL   = "https://www.googleapis.com/oauth2/v4/token"
	revokeTokenURL    = "https://accounts.google.com/o/oauth2/revoke?token=%s"
	profileDetailsURL = "https://www.googleapis.com/plus/v1/people/me?access_token=%s"
)

// OAuth2 interface to deal with OAuth2
type OAuth2 interface {
	GetAuthURL(scope, accessType, state, includeGrantedScopes, loginHint, prompt string) (string, error)
	GetToken(code string) ([]byte, error)
	VerifyToken(accessToken string) (string, error)
	RefreshToken(refreshToken string) (string, error)
	RevokeToken(accessToken string) error
	GetProfileDetails(accessToken string) (ProfileDetails, error)
	GetAndVerifyToken(code string) (VerifyDetails, error)
}

type oAuth2 struct {
	a            archer.Archer
	clientID     string
	clientSecret string
	redirectURL  string
	scope        string
}

// ProfileDetails stores the details fetched from the profile call
type ProfileDetails struct {
	Email  string
	Name   string
	Image  string
	ID     string
	Gender string
}

// VerifyDetails stores the details for verifing an account
type VerifyDetails struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int64
	RefreshToken string
	IDToken      string
	UserID       string
}

// NewOAuth2 - get a new client for OAuth2
func NewOAuth2(clientID, clientSecret, redirectURL string) (OAuth2, error) {

	if clientID == "" {
		return oAuth2{}, errors.New("oauth2: Please enter your clientID for Google OAuth")
	}

	if clientSecret == "" {
		return oAuth2{}, errors.New("oauth2: Please enter your clientSecret for Google OAuth")
	}

	if redirectURL == "" {
		return oAuth2{}, errors.New("oauth2: Please enter a redirect URL for Google Auth")
	}

	a := archer.NewArcher(2 * time.Second)
	return oAuth2{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		a:            a,
	}, nil
}

func (o oAuth2) GetAuthURL(scope, accessType, state, includeGrantedScopes, loginHint, prompt string) (string, error) {

	if scope == "" {
		scope = fmt.Sprintf("%s %s", scopeUserInfoEmail, scopeUserInfoProfile)
	}
	o.scope = scope

	if includeGrantedScopes != "true" {
		includeGrantedScopes = "true"
	}

	if accessType != accessTypeOnline {
		accessType = accessTypeOffline
	}

	if prompt == "" {
		prompt = fmt.Sprintf("%s %s", promptConsent, promptSelectAccount)
	}

	return fmt.Sprintf(authTokenURL, url.PathEscape(scope), url.PathEscape(accessType), url.PathEscape(includeGrantedScopes), url.PathEscape(state), url.PathEscape(o.redirectURL), url.PathEscape(loginHint), url.PathEscape(prompt), url.PathEscape(o.clientID)), nil
}

func (o oAuth2) GetToken(code string) ([]byte, error) {
	v := url.Values{}
	v.Set("code", code)
	v.Set("client_id", o.clientID)
	v.Set("client_secret", o.clientSecret)
	v.Set("redirect_uri", o.redirectURL)
	v.Set("grant_type", "authorization_code")
	s := v.Encode()

	body, err := o.a.Post(getTokenURL, strings.NewReader(s))
	if err != nil {
		return []byte{}, err
	}

	return body, nil
}

func (o oAuth2) VerifyToken(accessToken string) (string, error) {
	tokenURL := fmt.Sprintf(verifyTokenURL, accessToken)
	body, err := o.a.Get(tokenURL)
	if err != nil {
		return "", err
	}

	if len(body) == 0 {
		return "", errors.New("Could not find details for that access token")
	}

	aud := gjson.GetBytes(body, "aud")
	scope := gjson.GetBytes(body, "scope")
	userID := gjson.GetBytes(body, "userid")

	if aud.String() != o.clientID {
		return "", errors.New("Aud and clientID do not match")
	}

	if scope.String() != o.scope {
		// TODO : Match the scope to original
		// return "", errors.New("Scope does not match original scope")
	}

	return userID.String(), nil
}

func (o oAuth2) RefreshToken(refreshToken string) (string, error) {
	v := url.Values{}
	v.Set("refresh_token", refreshToken)
	v.Set("client_id", o.clientID)
	v.Set("client_secret", o.clientSecret)
	v.Set("grant_type", "refresh_token")
	s := v.Encode()

	body, err := o.a.Post(refreshTokenURL, strings.NewReader(s))
	if err != nil {
		return "", err
	}

	accessToken := gjson.GetBytes(body, "access_token")

	return accessToken.String(), nil
}

func (o oAuth2) RevokeToken(accessToken string) error {
	revokeURL := fmt.Sprintf(revokeTokenURL, accessToken)
	_, err := o.a.Get(revokeURL)
	if err != nil {
		return err
	}

	return nil
}

func (o oAuth2) GetProfileDetails(accessToken string) (ProfileDetails, error) {
	profileURL := fmt.Sprintf(profileDetailsURL, accessToken)
	bytes, err := o.a.Get(profileURL)
	if err != nil {
		return ProfileDetails{}, err
	}

	// Check for errors
	errorMessage := gjson.GetBytes(bytes, "error.message").String()
	if errorMessage != "" {
		return ProfileDetails{}, errors.New(errorMessage)
	}

	return ProfileDetails{
		Email:  gjson.GetBytes(bytes, "emails.0.value").String(),
		Name:   gjson.GetBytes(bytes, "displayName").String(),
		Image:  gjson.GetBytes(bytes, "image.url").String(),
		ID:     gjson.GetBytes(bytes, "id").String(),
		Gender: gjson.GetBytes(bytes, "gender").String(),
	}, nil
}

func (o oAuth2) GetAndVerifyToken(code string) (VerifyDetails, error) {
	bytes, err := o.GetToken(code)
	if err != nil {
		return VerifyDetails{}, err
	}

	accessToken := gjson.GetBytes(bytes, "access_token")
	userID, err := o.VerifyToken(accessToken.String())
	if err != nil {
		return VerifyDetails{}, err
	}

	return VerifyDetails{
		AccessToken:  accessToken.String(),
		TokenType:    gjson.GetBytes(bytes, "token_type").String(),
		ExpiresIn:    gjson.GetBytes(bytes, "expires_in").Int(),
		RefreshToken: gjson.GetBytes(bytes, "refresh_token").String(),
		IDToken:      gjson.GetBytes(bytes, "id_token").String(),
		UserID:       userID,
	}, nil
}
