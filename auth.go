package jwtAuth

import (
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Errors
var (
	ErrNoToken      = errors.New("Token was not supplied")
	ErrInvalidToken = errors.New("Invalid Token - Access Denied.")
)

type ErrValidation struct {
	ValidateError *jwt.ValidationError
}

func (e ErrValidation) Error() string {
	return fmt.Sprintf("Validation Error: %s", e.ValidateError.Error())
}

var (
	HeaderKey string = "AuthToken" // Default Header name
)

// you need to overwrite this to supply your key.
// you can make also make custom checks on the claim.
// claim[exp] is verified internaly by the jwt-go package
var VerifyFunc jwt.Keyfunc

// VerifyHeader checks for the exsistence of a Token in the Request Header
// it Verifies the Token using the user supplied VerifyFunc
// func signature is chosen to work with go-tigertonic.If()
func VerifyHeader(r *http.Request) (http.Header, error) {
	tokString := r.Header.Get(HeaderKey)
	if tokString == "" {
		return nil, ErrNoToken
	}

	token, err := jwt.Parse(tokString, VerifyFunc)

	switch err.(type) {

	case nil: // no error
		if !token.Valid { // may still be invalid
			return nil, ErrInvalidToken
		}

		return nil, nil

	case *jwt.ValidationError: // something was wrong during the validation
		return nil, ErrValidation{err.(*jwt.ValidationError)}

	default: // something else went wrong
		return nil, err
	}

}

// MakeToken creates a new RS256 signed token.
// it sets the claims map and usses validDur to sepcify when it is expireing from time.Now()
func MakeToken(signKey []byte, claims map[string]interface{}, validDur time.Duration) (string, error) {
	t := jwt.New(jwt.GetSigningMethod("RS256"))

	for key, value := range claims {
		t.Claims[key] = value
	}

	// see http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4.1.4
	t.Claims["exp"] = time.Now().Add(validDur).Unix()

	tokenString, err := t.SignedString(signKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
