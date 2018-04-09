package oauth2

import (
	"fmt"
	"io"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

type MockArcher struct{}

var state string

func (m MockArcher) Get(url string) ([]byte, error) {
	switch state {
	case "fakeProfileDetails":
		return []byte(`{"kind": "plus#person", "etag": "", "gender": "male", "emails": [{"value": "boogabooga@gmail.com", "type": "account"}], "urls": [{"value": "http://sudhanshuraheja.com", "type": "otherProfile", "label": "Gyaan Sutra"}, {"value": "http://vxtindia.com", "type": "other", "label": "Vercingetorix Technologies"} ], "objectType": "person", "id": "102967380278879533510", "displayName": "Sudhanshu Raheja", "name": {"familyName": "Raheja", "givenName": "Sudhanshu"}, "aboutMe": "Founder of Vercingetorix Technologies Pvt Ltd", "url": "https://plus.google.com/102967380278879533510", "image": {"url": "https://lh5.googleusercontent.com/-RjZVXVkQ_Z4/AAAAAAAAAAI/AAAAAAAABDY/-osXKni-BSY/photo.jpg?sz=50", "isDefault": false }, "organizations": [{"name": "Army Institute of Technology", "title": "Electronics & Telecommunications", "type": "school", "startDate": "2000", "endDate": "2004", "primary": false }, {"name": "Vercingetorix Technologies Pvt Ltd", "type": "work", "startDate": "2007", "primary": true } ], "placesLived": [{"value": "Pune, India", "primary": true }, {"value": "Delhi, India"}, {"value": "Sydney, Australia"} ], "isPlusUser": true, "language": "en_GB", "verified": false }`), nil
	case "fakeRevokeToken":
		return []byte(`{ "success": "true" }`), nil
	case "fakeTokenActualResponse":
		return []byte(`{ "aud": "fakeClientID", "scope": "", "userid": "fakeUserId" }`), nil
	case "fakeGetAndVerifyToken":
		return []byte(`{ "aud": "fakeClientID", "scope":"", "userid":"fakeUserId" }`), nil
	default:
		return []byte{}, nil
	}
}
func (m MockArcher) Post(url string, body io.Reader) ([]byte, error) {
	switch state {
	case "fakeRefreshToken":
		return []byte(`{ "access_token":"fakeRefreshedAccessToken", "expires_in":3920, "token_type":"Bearer" }`), nil
	case "fakeGetAndVerifyToken":
		return []byte(`{ "access_token":"fakeAccessToken", "token_type": "fakeTokenType", "expiresIn": "fakeExpiresIn", "refresh_token": "fakeRefreshToken", "id_token": "fakeIdToken" }`), nil
	default:
		bytes, err := ioutil.ReadAll(body)
		if err != nil {
			return nil, err
		}
		output := fmt.Sprintf("%s %s", url, string(bytes))
		return []byte(output), nil
	}
}
func (m MockArcher) Put(url string) ([]byte, error) {
	return []byte{}, nil
}
func (m MockArcher) Delete(url string) ([]byte, error) {
	return []byte{}, nil
}
func (m MockArcher) Upload(url string, file string) ([]byte, error) {
	return []byte{}, nil
}

func newOAuth2(clientID, clientSecret, redirectURL string) (OAuth2, error) {
	a := MockArcher{}
	return oAuth2{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		a:            a,
	}, nil
}

func TestGetAuthURL(t *testing.T) {
	oa, err := NewOAuth2("", "fakeClientSecret", "fakeRedirectURL")
	assert.Equal(t, "oauth2: Please enter your clientID for Google OAuth", err.Error())

	oa, err = NewOAuth2("fakeClientID", "fakeClientSecret", "")
	assert.Equal(t, "oauth2: Please enter a redirect URL for Google Auth", err.Error())

	oa, err = NewOAuth2("fakeClientID", "fakeClientSecret", "fakeRedirectURL")
	assert.Nil(t, err)

	// Get URL
	url, err := oa.GetAuthURL("fakeScope", "fakeAccessType", "fakeState", "fakeIncludeGrantedScopes", "fakeLoginHint", "fakePrompt")
	assert.Nil(t, err)
	assert.Equal(t, "https://accounts.google.com/o/oauth2/v2/auth?scope=fakeScope&access_type=offline&include_granted_scopes=true&state=fakeState&redirect_uri=fakeRedirectURL&response_type=code&login_hint=fakeLoginHint&prompt=fakePrompt&client_id=fakeClientID", url)

	// Try with no scope
	url, err = oa.GetAuthURL("", "fakeAccessType", "fakeState", "fakeIncludeGrantedScopes", "fakeLoginHint", "fakePrompt")
	assert.Nil(t, err)
	assert.Equal(t, "https://accounts.google.com/o/oauth2/v2/auth?scope=https:%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email%20https:%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.profile&access_type=offline&include_granted_scopes=true&state=fakeState&redirect_uri=fakeRedirectURL&response_type=code&login_hint=fakeLoginHint&prompt=fakePrompt&client_id=fakeClientID", url)

	// Try with no include_granted_scopes
	url, err = oa.GetAuthURL("fakeScope", "fakeAccessType", "fakeState", "", "fakeLoginHint", "fakePrompt")
	assert.Nil(t, err)
	assert.Equal(t, "https://accounts.google.com/o/oauth2/v2/auth?scope=fakeScope&access_type=offline&include_granted_scopes=true&state=fakeState&redirect_uri=fakeRedirectURL&response_type=code&login_hint=fakeLoginHint&prompt=fakePrompt&client_id=fakeClientID", url)

	// Try with online accessType
	url, err = oa.GetAuthURL("fakeScope", "online", "fakeState", "fakeIncludeGrantedScopes", "fakeLoginHint", "fakePrompt")
	assert.Nil(t, err)
	assert.Equal(t, "https://accounts.google.com/o/oauth2/v2/auth?scope=fakeScope&access_type=online&include_granted_scopes=true&state=fakeState&redirect_uri=fakeRedirectURL&response_type=code&login_hint=fakeLoginHint&prompt=fakePrompt&client_id=fakeClientID", url)

	// Try with empty accessType
	url, err = oa.GetAuthURL("fakeScope", "", "fakeState", "fakeIncludeGrantedScopes", "fakeLoginHint", "fakePrompt")
	assert.Nil(t, err)
	assert.Equal(t, "https://accounts.google.com/o/oauth2/v2/auth?scope=fakeScope&access_type=offline&include_granted_scopes=true&state=fakeState&redirect_uri=fakeRedirectURL&response_type=code&login_hint=fakeLoginHint&prompt=fakePrompt&client_id=fakeClientID", url)

	// Try with empty prompt
	url, err = oa.GetAuthURL("fakeScope", "fakeAccessType", "fakeState", "fakeIncludeGrantedScopes", "fakeLoginHint", "")
	assert.Nil(t, err)
	assert.Equal(t, "https://accounts.google.com/o/oauth2/v2/auth?scope=fakeScope&access_type=offline&include_granted_scopes=true&state=fakeState&redirect_uri=fakeRedirectURL&response_type=code&login_hint=fakeLoginHint&prompt=consent%20select_account&client_id=fakeClientID", url)
}

func TestGetToken(t *testing.T) {
	oa, err := newOAuth2("fakeClientID", "fakeClientSecret", "fakeRedirectURL")
	assert.Nil(t, err)

	bytes, err := oa.GetToken("abc")
	assert.Nil(t, err)
	assert.Equal(t, "https://www.googleapis.com/oauth2/v4/token client_id=fakeClientID&client_secret=fakeClientSecret&code=abc&grant_type=authorization_code&redirect_uri=fakeRedirectURL", string(bytes))
}

func TestVerifyToken(t *testing.T) {
	oa, err := newOAuth2("fakeClientID", "fakeClientSecret", "fakeRedirectURL")
	assert.Nil(t, err)

	_, err = oa.VerifyToken("fakeToken")
	assert.Equal(t, "Could not find details for that access token", err.Error())

	state = "fakeTokenActualResponse"

	userid, err := oa.VerifyToken("fakeToken")
	assert.Nil(t, err)
	assert.Equal(t, "fakeUserId", userid)
}

func TestRefreshToken(t *testing.T) {
	oa, err := newOAuth2("fakeClientID", "fakeClientSecret", "fakeRedirectURL")
	assert.Nil(t, err)

	state = "fakeRefreshToken"

	accessToken, err := oa.RefreshToken("fakeRefreshToken")
	assert.Nil(t, err)
	assert.Equal(t, "fakeRefreshedAccessToken", accessToken)
}

func TestRevokeToken(t *testing.T) {
	oa, err := newOAuth2("fakeClientID", "fakeClientSecret", "fakeRedirectURL")
	assert.Nil(t, err)

	state = "fakeRevokeToken"

	err = oa.RevokeToken("fakeAccessToken")
	assert.Nil(t, err)
}

func TestProfileDetails(t *testing.T) {
	oa, err := newOAuth2("fakeClientID", "fakeClientSecret", "fakeRedirectURL")
	assert.Nil(t, err)

	state = "fakeProfileDetails"

	profileDetails, err := oa.GetProfileDetails("fakeAccessToken")
	assert.Nil(t, err)
	assert.Equal(t, "boogabooga@gmail.com", profileDetails.Email)
	assert.Equal(t, "Sudhanshu Raheja", profileDetails.Name)
	assert.Equal(t, "https://lh5.googleusercontent.com/-RjZVXVkQ_Z4/AAAAAAAAAAI/AAAAAAAABDY/-osXKni-BSY/photo.jpg?sz=50", profileDetails.Image)
	assert.Equal(t, "102967380278879533510", profileDetails.ID)
	assert.Equal(t, "male", profileDetails.Gender)

}

func TestGetAndVerifyToken(t *testing.T) {
	oa, err := newOAuth2("fakeClientID", "fakeClientSecret", "fakeRedirectURL")
	assert.Nil(t, err)

	state = "fakeGetAndVerifyToken"

	verifyDetails, err := oa.GetAndVerifyToken("fakeCode")
	assert.Nil(t, err)
	assert.Equal(t, "fakeAccessToken", verifyDetails.AccessToken)
	assert.Equal(t, "fakeTokenType", verifyDetails.TokenType)
	assert.Equal(t, int64(0), verifyDetails.ExpiresIn)
	assert.Equal(t, "fakeRefreshToken", verifyDetails.RefreshToken)
	assert.Equal(t, "fakeIdToken", verifyDetails.IDToken)
	assert.Equal(t, "fakeUserId", verifyDetails.UserID)
}
