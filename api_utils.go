package main

import (
	"encoding/json"
	"io"
)

func GetRepoCreateUrl() string {
	return "/api/repos/create"
}

func GetReposUrl() string {
	return "/api/{user-name}/repos"
}

func GetRepoUrl() string {
	return "/api/{user-name}/repos/{repo-name}"
}

func GetBranchesUrl() string {
	return "/api/{user-name}/repos/{repo-name}/branches"
}

func GetBranchUrl() string {
	return "/api/{user-name}/repos/{repo-name}/branches/{branch-name}"
}

func GetProtocol(ssl bool) string {
	if ssl {
		return "https://"
	}
	return "http://"
}

func WriteIndentedJson(w io.Writer, v interface{}, prefix, indent string) {
	resp, _ := json.MarshalIndent(v, prefix, indent)
	w.Write(resp)
	w.Write([]byte("\n"))
}