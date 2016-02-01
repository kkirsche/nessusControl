package nessus

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListPolicies(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"policies":[{"no_target":"false","template_uuid":"exampleuuid", "description":"This is an example Policy for GoNessus","name":"Example Policy","owner":"kkirsche","visibility":"shared","shared":1,"user_permissions":32,"last_modification_date":1454334708,"creation_date":1454334708,"owner_id":2,"id":25}]}`
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

	policies, err := client.ListPolicy(httpClient)
	if err != nil || policies.Policies[0].Name != "Example Policy" {
		t.FailNow()
	}
}
