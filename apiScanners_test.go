package nessus

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListScanners(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"scanners":[{"challenge":"testChallenge","license":{"drm":"licenseDRM","activation_code":"TestActivationCode","update_url":"https://plugins.nessus.org/v2/nessus.php","type":"home","expiration_date":1599665140,"mode":3,"scanners_used":0,"agents_used":0,"update_password":"Nope","name":"Nessus Home"},"num_scans":null,"aws_availability_zone":null,"aws_update_interval":null,"needs_restart":null,"last_connect":null,"loadavg":null,"num_tcp_sessions":null,"num_hosts":null,"num_sessions":null,"registration_code":"TestRegistrationCode","expiration_time":1684,"expiration":1599665140,"loaded_plugin_set":"201601280615","platform":"DARWIN","ui_build":"44","ui_version":"6.5.4","engine_build":"M20044","engine_version":"6.5.4","status":"on","scan_count":0,"linked":1,"key":"testKey","type":"local","name":"Local Scanner","uuid":"00000000-0000-0000-0000-00000000000000000000000000000","token":null,"owner_name":"system","owner":"nessus_ms_agent","shared":1,"user_permissions":64,"timestamp":1441984838,"last_modification_date":1441984838,"creation_date":1441984838,"owner_id":1,"id":1}]}`
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

	scanners, err := client.ListScanners(httpClient)
	if err != nil || scanners.Scanners[0].Challenge != "testChallenge" {
		t.FailNow()
	}
}
