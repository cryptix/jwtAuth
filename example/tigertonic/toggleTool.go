package main

import (
	"github.com/cryptix/jwtAuth"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

func main() {
	signKey, err := ioutil.ReadFile("key")
	check(err)

	claims := make(map[string]interface{})
	claims["lul"] = 23

	tok, err := jwtAuth.MakeToken(signKey, claims, time.Minute*1)
	check(err)

	req, err := http.NewRequest("POST", "http://localhost:3000/toggleSauce", nil)
	check(err)
	req.Header.Set(jwtAuth.HeaderKey, tok)

	resp, err := http.DefaultClient.Do(req)
	check(err)

	log.Println(resp)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
