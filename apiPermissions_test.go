package nessus

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChangePermissions(t *testing.T) {
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

	successfullyChanged, err := client.ChangePermissions(httpClient, "policy", 37, `{"acls": [{"type": "user", "permissions": 0, "name": "testU", "id": 1, "owner": 1}]}`)
	if err != nil || successfullyChanged != true {
		t.FailNow()
	}
}

func TestListPermissions(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"acls":[{"permissions":0,"owner":null,"display_name":null,"name":null,"id":null,"type":"default"},{"permissions":128,"owner":1,"display_name":"testU","name":"testU","id":3,"type":"user"}]}`
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

	permissions, err := client.ListPermissions(httpClient, "policy", 37)
	if err != nil || permissions.Acls[1].Permissions != 128 {
		fmt.Println(err)
		t.FailNow()
	}
}
