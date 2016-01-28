package client

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestCreateSession(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"token": "TestToken"}`
		fmt.Fprintln(w, response)
	}))
	defer testServer.Close()

	transport := &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			return url.Parse(testServer.URL)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{Transport: transport}

	jsonStr, err := json.Marshal(`{"username": "testU", "password": "testP"}`)
	if err != nil {
		t.FailNow()
	}

	client := Client{}

	body, err := client.postWithArgs(httpClient, testServer.URL, jsonStr)
	if err != nil {
		t.FailNow()
	}

	var session createSession
	json.Unmarshal(body, &session)
	if session.Token != "TestToken" {
		t.FailNow()
	}
}
