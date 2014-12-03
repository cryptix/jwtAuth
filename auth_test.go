package jwtAuth

import (
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func TestVerifyNoToken(t *testing.T) {
	a := assert.New(t)
	req, err := http.NewRequest("GET", "/", nil)
	a.Nil(err)

	_, err = VerifyHeader(req)
	a.Equal(jwt.ErrNoTokenInRequest, err)
}

func TestVerifyInvalidToken(t *testing.T) {
	a := assert.New(t)
	req, err := http.NewRequest("GET", "/", nil)
	a.Nil(err)
	req.Header.Set(HeaderKey, "Bearer abc")

	_, err = VerifyHeader(req)
	a.EqualError(err, "token contains an invalid number of segments")
}

func TestVerifyFuncNotSet(t *testing.T) {
	a := assert.New(t)
	req, err := http.NewRequest("GET", "/", nil)
	a.Nil(err)
	req.Header.Set(HeaderKey, "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg")

	_, err = VerifyHeader(req)
	a.EqualError(err, ErrVerifyFuncNotSet.Error())
}

func TestVerifyValidToken(t *testing.T) {

	a := assert.New(t)
	req, err := http.NewRequest("GET", "/", nil)
	a.Nil(err)
	req.Header.Set(HeaderKey, "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.wjRzalnqwKCB4zrZ8K8s7vUZ06SCG55AWHJFMt-qTlMNAx36SNOEwhtkXKQRDzzrPj7ddI_qFXbBzr98oKo1MagoJHRv1oBwRjGZZs5O3z816LYFvMwIA0N0VOf94d34Hd8LcUoUZ_6Alpys5s3yzTdN6o4cLWKMx44QxlyQvLY")

	VerifyFunc = func(tok *jwt.Token) (interface{}, error) {
		keyBytes, err := ioutil.ReadFile("key.pub")
		a.Nil(err, "Error:  %q", err)

		key, err := jwt.ParseRSAPublicKeyFromPEM(keyBytes)
		a.Nil(err, "Error:  %q", err)

		return key, nil
	}

	_, err = VerifyHeader(req)
	a.Nil(err, "Error:  %q", err)
}
