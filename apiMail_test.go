package nessus

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChangeMailSettings(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"token":"Example"}` // JSON for the CreateSession method. This method actually returns nothing.
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

	successfullyChanged, err := client.ChangeMailSettings(httpClient, `{"smtp_host":"smtp.company.com","smtp_port":"25","smtp_from":"test.user@company.com","smtp_enc":"Use TLS if available","smtp_www_host":"localhost:8834","smtp_auth":"NONE","smtp_user":"","smtp_pass":""}`)
	if err != nil || successfullyChanged != true {
		t.FailNow()
	}
}

func TestViewMailSettings(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"smtp_from":"test.user@example.company.com","smtp_www_host":"localhost:8834","smtp_user":"","smtp_host":"smtp.company.com","smtp_pass":"","smtp_auth":"NONE","smtp_test":null,"smtp_enc":"Use TLS if available","smtp_port":"25"}`
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

	mailSettings, err := client.ViewMailSettings(httpClient)
	if err != nil || mailSettings.SMTPPort != "25" {
		t.FailNow()
	}
}
