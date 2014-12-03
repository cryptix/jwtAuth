package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/codegangsta/cli"
	"github.com/cryptix/go/logging"
	"github.com/cryptix/jwtAuth"
)

func toggleCmd(ctx *cli.Context) {
	signKey, err := ioutil.ReadFile("key.priv")
	logging.CheckFatal(err)

	claims := make(map[string]interface{})
	claims["lul"] = 23

	tok, err := jwtAuth.MakeToken(signKey, claims, time.Minute*1)
	logging.CheckFatal(err)

	req, err := http.NewRequest("POST", "http://localhost:3000/toggleSauce", nil)
	logging.CheckFatal(err)
	req.Header.Set(jwtAuth.HeaderKey, tok)

	resp, err := http.DefaultClient.Do(req)
	logging.CheckFatal(err)

	log.Println(resp)
}
