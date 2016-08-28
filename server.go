package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

func GitServer() {
	host := fmt.Sprintf("%s:%s", config.Hostname, config.Port)
	log.Println("Starting git http server at", host)

	r := mux.NewRouter()
	attachHandler(r)

	if config.SSLEnabled {
		if err := http.ListenAndServeTLS(host, "server.pem", "server.key", r); err != nil {
			log.Fatal(err)
		}
	} else {
		if err := http.ListenAndServe(host, r); err != nil {
			log.Fatal(err)
		}
	}
}

func attachHandler(r *mux.Router) {
	//git methods Handler
	r.HandleFunc(`/{user-name}/{repo-name:([a-zA-Z0-9\-\.\_]+)}/info/refs`, basicAuthentication(serviceHandler, true)).Methods("GET")
	r.HandleFunc(`/{user-name}/{repo-name:([a-zA-Z0-9\-\.\_]+)}/git-upload-pack`, basicAuthentication(uploadPackHandler, true)).Methods("POST")
	r.HandleFunc(`/{user-name}/{repo-name:([a-zA-Z0-9\-\.\_]+)}/git-receive-pack`, basicAuthentication(receivePackHandler, true)).Methods("POST")

	//APIs handlers
	r.HandleFunc("/", rootHandler).Methods("GET")
	r.HandleFunc(GetRepoCreateURL(), basicAuthentication(repoCreateHandler, false)).Methods("POST")
	r.HandleFunc(GetReposURL(), repoIndexHandler).Methods("GET")
	r.HandleFunc(GetRepoURL(), repoShowHandler).Methods("GET")
	r.HandleFunc(GetBranchesURL(), branchIndexHandler).Methods("GET")
	r.HandleFunc(GetBranchURL(), branchShowHandler).Methods("GET")
}
