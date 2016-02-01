package nessus

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListScans(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"folders":[{"unread_count":null,"custom":0,"default_tag":0,"type":"trash","name":"Trash","id":23},{"unread_count":null,"custom":0,"default_tag":1,"type":"main","name":"My Scans","id":24}],"scans":[{"folder_id":24,"type":null,"read":true,"last_modification_date":0,"creation_date":0,"status":"empty","uuid":null,"shared":false,"user_permissions":128,"owner":"testU","timezone":null,"rrules":null,"starttime":null,"enabled":false,"control":true,"name":"test","id":36}],"timestamp":1454368895}`
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

	scanList, err := client.ListScans(httpClient)
	if err != nil || scanList.Scans[0].Name != "test" {
		t.FailNow()
	}
}

func TestPauseScan(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"token": "ExampleToken"}` // This is for CreateSession, this method alone returns nothing
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

	scanPaused, err := client.PauseScan(httpClient, 36)
	if err != nil || scanPaused != true {
		t.FailNow()
	}
}
