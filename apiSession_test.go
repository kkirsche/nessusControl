package client

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateSession(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"token": "TestToken"}`
		fmt.Fprintln(w, response)
	}))
	defer testServer.Close()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{Transport: transport}

	port := strings.Split(testServer.URL, ":")[2]

	client := &Client{
		username: "testU",
		password: "testP",
		ip:       "127.0.0.1",
		port:     port,
	}

	client, err := client.CreateSession(httpClient)
	if err != nil {
		t.FailNow()
	}

	if client.token != "TestToken" {
		t.FailNow()
	}
}

func TestEditSession(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"lockout":false,"connectors":null,"whatsnew":true,"container_id":0,"groups":null,"whatsnew_version":"","lastlogin":1454101652,"permissions":128,"type":"local","name":"Test User","email":"test.user@gmail.com","username":"test","id":2}`
		fmt.Fprintln(w, response)
	}))
	defer testServer.Close()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{Transport: transport}

	port := strings.Split(testServer.URL, ":")[2]

	client := &Client{
		username: "kkirsche",
		password: "{j3TEd6CR2KNZMgy>6H(E]ug7BmrJTy=P8Y]44jCRrBYw{Bhjz",
		ip:       "127.0.0.1",
		port:     port,
	}

	client, err := client.CreateSession(httpClient)
	if err != nil {
		t.FailNow()
	}

	session, err := client.EditSession(httpClient, `{"name":"Kevin Kirsche","email":"Kev.Kirsche@gmail.com"}`)
	if err != nil || session.Username != "test" {
		t.FailNow()
	}
}

func TestDeleteSession(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "")
	}))
	defer testServer.Close()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	port := strings.Split(testServer.URL, ":")[2]

	client := &Client{
		username: "testU",
		password: "testP",
		ip:       "127.0.0.1",
		port:     port,
	}

	httpClient := &http.Client{Transport: transport}
	client, err := client.CreateSession(httpClient)
	if err != nil {
		t.FailNow()
	}

	resp, err := client.DestroySession(httpClient)
	if err != nil || resp != true {
		t.FailNow()
	}
}
