jwtAuth
=======
[![GoDoc](https://godoc.org/github.com/cryptix/jwtAuth?status.svg)](https://godoc.org/github.com/cryptix/jwtAuth)
[![Build Status](https://travis-ci.org/cryptix/jwtAuth.png?branch=master)](https://travis-ci.org/cryptix/jwtAuth)

Some simple Handlers and Helpers to use [jwt-go](https://github.com/dgrijalva/jwt-go) for go http stuff.

Currently only `RS256` is supported. If you have need/ideas for key schemes to use `HS256`, contact me or open a PR.



## Working
* `MakeToken` for creating signed tokens
* `VerifyHeader` to check if a key is valid

## TODO
* Make simple Handler to resign a token (extend its valdity)
* Tests MakeToken


## How to get Keys
```
openssl genrsa -out app.rsa <keysize> # i'd suggest 4096
openssl rsa -in app.rsa -pubout > app.rsa.pub
```
