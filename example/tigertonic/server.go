package main

import (
	crRand "crypto/rand"
	"io/ioutil"
	"log"
	"math/big"
	maRand "math/rand"
	"net/http"
	"net/url"
	"os"

	"github.com/cryptix/jwtAuth"
	"github.com/dgrijalva/jwt-go"
	"github.com/rcrowley/go-metrics"
	"github.com/rcrowley/go-tigertonic"
)

var (
	goodSauce bool
	mux       *tigertonic.TrieServeMux
)

func main() {

	goodSauce = true

	verifyKeyBytes, err := ioutil.ReadFile("key.pub")
	if err != nil {
		log.Fatal("Error reading private key")
		return
	}

	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyKeyBytes)
	if err != nil {
		log.Fatal("Error reading private key")
		return
	}

	jwtAuth.VerifyFunc = func(t *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	}

	// Register endpoints defined in top-level functions below with example
	// uses of Timed go-metrics wrapper.
	mux = tigertonic.NewTrieServeMux()

	mux.Handle("POST", "/toggleSauce", tigertonic.If(jwtAuth.VerifyHeader, toggleSauceHandler{}))
	mux.Handle("GET", "/sauce", tigertonic.Marshaled(sauceHandler))

	// Example use of go-metrics.
	go metrics.Log(
		metrics.DefaultRegistry,
		60e9,
		log.New(os.Stderr, "metrics ", log.Lmicroseconds),
	)

	server := tigertonic.NewServer(":3000",
		// Example use of go-metrics to track HTTP status codes.
		tigertonic.CountedByStatus(
			tigertonic.Logged(mux, nil),
			"http",
			nil,
		),
	)

	err = server.ListenAndServe()
	if nil != err {
		log.Println(err)
	}

}

// POST /toggleSauce
type toggleSauceHandler struct {
}

func (t toggleSauceHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	goodSauce = !goodSauce
	rw.WriteHeader(http.StatusOK)
}

// GET /sauce
type SauceResp struct{ A, B int64 }

type myReader int

func (r myReader) Read(b []byte) (n int, err error) {
	return crRand.Read(b)
}

func sauceHandler(u *url.URL, h http.Header, req interface{}) (int, http.Header, *SauceResp, error) {
	var a, b int64
	var r myReader
	if goodSauce {
		aBig, _ := crRand.Int(r, big.NewInt(9223372036854775807))
		bBig, _ := crRand.Int(r, big.NewInt(9223372036854775807))
		a = aBig.Int64()
		b = bBig.Int64()
	} else {
		a = maRand.Int63()
		b = maRand.Int63()
	}
	return http.StatusOK, nil, &SauceResp{a, b}, nil
}
