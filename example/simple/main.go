package main

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/codegangsta/negroni"
	"github.com/cryptix/jwtAuth"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

// location of the files used for signing and verification
const (
	privKeyPath = "keys/app.rsa"     // openssl genrsa -out app.rsa keysize
	pubKeyPath  = "keys/app.rsa.pub" // openssl rsa -in app.rsa -pubout > app.rsa.pub
)

// keys are held in global variables
// i havn't seen a memory corruption/info leakage in go yet
// but maybe it's a better idea, just to store the public key in ram?
// and load the signKey on every signing request? depends on  your usage i guess
var (
	signKey   *rsa.PrivateKey
	verifyKey *rsa.PublicKey
)

// read the key files before starting http handlers
func init() {
	var err error
	signKeyBytes, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		log.Fatal(err)
		return
	}

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signKeyBytes)
	if err != nil {
		log.Fatal(err)
		return
	}

	verifyKeyBytes, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		log.Fatal(err)
		return
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyKeyBytes)
	if err != nil {
		log.Fatal(err)
		return
	}
}

type User struct {
	Name, Pass string
	Level      int
}

var users map[int]User

func myVerify(t *jwt.Token) (interface{}, error) {
	return verifyKey, nil
}

func main() {

	jwtAuth.VerifyFunc = myVerify

	users = make(map[int]User, 2)
	users[23] = User{"Hackbarth", "AllTheVexes", 9001}
	users[42] = User{"cryptix", "yolo", 1}

	r := mux.NewRouter()
	r.HandleFunc("/", mainHandler)

	r.HandleFunc("/auth", authHandler).Methods("POST")

	r.HandleFunc("/restricted", restrictedHandler)

	n := negroni.Classic()
	n.UseHandler(r)

	var addr string
	port := os.Getenv("PORT")
	if port != "" {
		addr = fmt.Sprintf(":%s", port)
	} else {
		addr = ":3000"
	}

	n.Run(addr)
}

func mainHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "welcome!")
}

func authHandler(w http.ResponseWriter, req *http.Request) {

	user := req.FormValue("user")
	pass := req.FormValue("pass")

	// lookup user
	var found int
	for id, u := range users {
		if u.Name == user && u.Pass == pass {
			found = id
		}
	}

	if found == 0 {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "Wrong info")
		return
	}

	claims := make(map[string]interface{})
	claims["Id"] = found // leak some id...
	claims["CustomUserInfo"] = struct {
		Level int
		Kind  string
	}{users[found].Level, "superhuman"}

	// set our claims
	tok, err := jwtAuth.MakeToken(signKey, claims, time.Minute*5)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Sorry, error while Signing Token!")
		log.Printf("Token Signing error: %v\n", err)
		return
	}

	w.Header().Set(jwtAuth.HeaderKey, tok)
	fmt.Fprintf(w, "welcome!")
}

func restrictedHandler(w http.ResponseWriter, req *http.Request) {
	// check if Authorize passed
	_, err := jwtAuth.VerifyHeader(req)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "Error: Could not validate request Token.")
		log.Printf("jwtAuth.VerifyHeader() Error - %s\n", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "ohai!")
}
