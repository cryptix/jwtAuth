package jwtAuth

import (
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"net/http"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestVerifyHeader(t *testing.T) {
	Convey("No Token returns an error", t, func() {
		req, _ := http.NewRequest("GET", "/", nil)

		header, err := VerifyHeader(req)
		So(header, ShouldBeNil)
		So(err, ShouldEqual, ErrNoToken)
	})

	Convey("Invalid Token returns an error", t, func() {
		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set(HeaderKey, "abc")

		header, err := VerifyHeader(req)
		So(header, ShouldBeNil)
		So(err.Error(), ShouldEqual, "Validation Error: Token contains an invalid number of segments")
	})

	Convey("VerifyFunc needs to be set", t, func() {
		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set(HeaderKey, "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg")

		header, err := VerifyHeader(req)
		So(header, ShouldBeNil)
		So(err.Error(), ShouldEqual, "Validation Error: "+ErrVerifyFuncNotSet.Error())
	})

	Convey("Valid Token returns no error", t, func() {
		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set(HeaderKey, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoiaGkifQ.x3m_ha9OONqv25ER7Fazl7Inywq7Vv3977KqHTr3qwJe02_KSOKCDEcA2Lexevy0IcJTpoKMtzSWAWeR12veQbe8GIcFBIvwWoxKGuXHeIZYPZiKFhmQehOK6FmBRc1cjvQjct-BfcTTYp7x3Mlw-k99uHL93JKR6CNraZUN_oM")

		VerifyFunc = func(tok *jwt.Token) ([]byte, error) {
			verifyKey, err := ioutil.ReadFile("key.pub")
			if err != nil {
				t.Fatal(err)
			}

			return verifyKey, nil
		}

		header, err := VerifyHeader(req)
		So(header, ShouldBeNil)
		So(err, ShouldBeNil)
	})
}
