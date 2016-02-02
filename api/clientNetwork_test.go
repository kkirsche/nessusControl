package nessusAPI

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPostWithArgs(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		unmarshalledJSON := `{"token": "TestToken"}`
		fmt.Fprintln(w, unmarshalledJSON)
	}))
	defer testServer.Close()

	jsonStr, err := json.Marshal(`{"username": "test", "password": "test"}`)
	if err != nil {
		t.FailNow()
	}

	client := Client{}

	// Ignore bad HTTPS certificate
	transportSettings := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{Transport: transportSettings}

	statusCode, body, err := client.postWithJSON(httpClient, testServer.URL, jsonStr)
	if err != nil || statusCode != 200 {
		t.FailNow()
	}

	var session CreateSessionResponse
	json.Unmarshal(body, &session)
	if session.Token != "TestToken" {
		t.FailNow()
	}
}

func TestPutWithArgs(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		unmarshalledJSON := `{"token": "TestToken"}`
		fmt.Fprintln(w, unmarshalledJSON)
	}))
	defer testServer.Close()

	jsonStr, err := json.Marshal(`{"username": "test", "password": "test"}`)
	if err != nil {
		t.FailNow()
	}

	client := Client{}

	// Ignore bad HTTPS certificate
	transportSettings := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{Transport: transportSettings}

	statusCode, body, err := client.putWithJSON(httpClient, testServer.URL, jsonStr)
	if err != nil || statusCode != 200 {
		t.FailNow()
	}

	var session CreateSessionResponse
	json.Unmarshal(body, &session)
	if session.Token != "TestToken" {
		t.FailNow()
	}
}

func TestPut(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		unmarshalledJSON := `{"example": "test"}`
		fmt.Fprintln(w, unmarshalledJSON)
	}))
	defer testServer.Close()

	client := Client{}

	// Ignore bad HTTPS certificate
	transportSettings := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{Transport: transportSettings}

	statusCode, _, err := client.put(httpClient, testServer.URL)
	if err != nil || statusCode != 200 {
		t.FailNow()
	}
}

func TestDelete(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "")
	}))
	defer testServer.Close()

	client := Client{}

	// Ignore bad HTTPS certificate
	transportSettings := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{Transport: transportSettings}

	statusCode, _, err := client.delete(httpClient, testServer.URL)
	if err != nil || statusCode != 200 {
		t.FailNow()
	}
}

func TestGet(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		unmarshalledJSON := `{"example": "test"}`
		fmt.Fprintln(w, unmarshalledJSON)
	}))
	defer testServer.Close()

	client := Client{}

	// Ignore bad HTTPS certificate
	transportSettings := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{Transport: transportSettings}

	statusCode, _, err := client.get(httpClient, testServer.URL)
	if err != nil || statusCode != 200 {
		t.FailNow()
	}
}
