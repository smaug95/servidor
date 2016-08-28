package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
  "log"
	"net/http"
	"os"
	"strings"
)

func basicAuthentication(reqHandler http.HandlerFunc, checkAuthorization bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if config.AuthEnabled {
			username, password, ok := r.BasicAuth()
			if !ok {
				renderUnauthenticated(w, "Authentication failed - Provide Basic Authentication - username:password")
				log.Println("Authentication failure – no basic authentication credentials found")
				return
			}
			if !validate(username, password) {
				renderUnauthenticated(w, "Authentication failed - incorrect username or password")
				log.Println("Authentication failure – wrong credentials for user ", username)
				return
			}
			if checkAuthorization && !authorize(username, r) {
				renderUnauthorized(w, "You are not authorized to access this resource")
				log.Println("Authorization failure by user " + username)
				return
			}
		}
		reqHandler(w, r)
	}
}

func validate(username, password string) bool {
	file, err := os.Open(config.PasswdFilePath)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		params := strings.Split(scanner.Text(), ":")
		if username == params[0] && matchPassword(password, params[1]) {
			return true
		}
	}
	return false
}

func matchPassword(savedPwd string, sentPwd string) bool {
	hash := sha1.New()
	hash.Write([]byte(savedPwd))
	pwdCheck := strings.Replace(base64.URLEncoding.EncodeToString(hash.Sum(nil)), "-", "+", -1)
	pwdCheck = strings.Replace(pwdCheck, "_", "/", -1)

	return (pwdCheck == strings.Split(sentPwd, "{SHA}")[1])
}

func authorize(authenticatedUser string, r *http.Request) bool {
  repoUser, _, _ := GetParamValues(r)
  return repoUser == "repos" || authenticatedUser == repoUser
}

func renderUnauthenticated(w http.ResponseWriter, error string) {
	w.Header().Set("WWW-Authenticate", "Basic realm=\"\"")
	w.WriteHeader(http.StatusUnauthorized)
	errJSON := Error{Message: error}
	WriteIndentedJSON(w, errJSON, "", "  ")
}

func renderUnauthorized(w http.ResponseWriter, error string) {
	w.WriteHeader(http.StatusForbidden)
	errJSON := Error{Message: error}
	WriteIndentedJSON(w, errJSON, "", "  ")
}
