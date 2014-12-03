package jwtAuth

import (
	"errors"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	ErrInvalidToken     = errors.New("jwtAuth: Invalid Token")
	ErrVerifyFuncNotSet = errors.New("jwtAuth: You did not set VerifyFunc.")
)

var HeaderKey = "Authorization" // Default Header name

// you need to overwrite this to supply your key.
// you can make also make custom checks on the claim.
// claim[exp] is verified internaly by the jwt-go package
var VerifyFunc = func(tok *jwt.Token) (interface{}, error) {
	return nil, ErrVerifyFuncNotSet
}

// VerifyHeader checks for the exsistence of a Token in the Request Header
// it Verifies the Token using the user supplied VerifyFunc
// func signature is chosen to work with go-tigertonic.If()
func VerifyHeader(r *http.Request) (http.Header, error) {
	token, err := jwt.ParseFromRequest(r, VerifyFunc)
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	return nil, nil
}

// MakeToken creates a new RS256 signed token.
// it sets the claims map and usses validDur to sepcify when it is expireing from time.Now()
func MakeToken(signKey interface{}, claims map[string]interface{}, validDur time.Duration) (string, error) {
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

	return "Bearer " + tokenString, nil
}
