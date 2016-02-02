package nessusCreator

import (
	"crypto/tls"
	"fmt"
	"github.com/kkirsche/nessusControl/api"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateScanJSON(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"scan":{"container_id":0,"uuid":"template-9f6a69d0-709e-22b1-f696-e1de009f6a8faf787b8b14d3a111","name":"Example Scan","description":null,"policy_id":40,"scanner_id":1,"emails":null,"sms":null,"enabled":true,"use_dashboard":false,"dashboard_file":null,"scan_time_window":null,"custom_targets":"localhost","starttime":null,"rrules":null,"timezone":null,"notification_filters":null,"shared":0,"user_permissions":128,"default_permisssions":0,"owner":"testU","owner_id":3,"last_modification_date":1454379756,"creation_date":1454379756,"type":"public","id":41}}`
		fmt.Fprintln(w, response)
	}))
	defer testServer.Close()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{Transport: transport}

	port := strings.Split(testServer.URL, ":")[2]

	client := nessusAPI.NewUsernameClient("127.0.0.1", port, "testU", "testP", false)

	client, err := client.CreateSession(httpClient)
	if err != nil {
		t.FailNow()
	}

	creator := NewCreator("/some/place", client, false)
	createScanCh := make(chan nessusAPI.CreateScan)

	go func(createScanCh chan nessusAPI.CreateScan) {
		for i := 0; i < 5; i++ {
			createScanCh <- nessusAPI.CreateScan{
				UUID: "TestUUID",
				Settings: nessusAPI.CreateScanSettings{
					Name:        "Request 1",
					Description: "Request 2",
					FolderID:    "1",
					ScannerID:   "2",
					PolicyID:    "3",
					TextTargets: "123.12.45.0/24",
					Launch:      "ONETIME",
					Enabled:     false,
					LaunchNow:   false,
				},
			}
		}
		close(createScanCh)
	}(createScanCh)

	createScanResponseCh := creator.createScan(createScanCh, true)
	for createdScanResponse := range createScanResponseCh {
		if createdScanResponse.Scan.UUID != "template-9f6a69d0-709e-22b1-f696-e1de009f6a8faf787b8b14d3a111" {
			t.FailNow()
		}
	}
}

func TestBuildCreateScanJSON(t *testing.T) {
	creator := Creator{}
	requestScanCh := make(chan RequestedScan)

	go func(requestScanCh chan RequestedScan) {
		for i := 0; i < 5; i++ {
			requestScanCh <- RequestedScan{
				RequestID: "123",
				Method:    "atomic",
				TargetIPs: []string{
					"192.168.2.0/24",
					"192.168.3.0/24",
					"192.168.4.0/24",
				},
			}
		}

		close(requestScanCh)
	}(requestScanCh)

	createScanCh := creator.buildCreateScanJSON(requestScanCh)
	for createScanJSON := range createScanCh {
		if createScanJSON.UUID != "ab4bacd2-05f6-425c-9d79-3ba3940ad1c24e51e1f403febe40" ||
			createScanJSON.Settings.Name != "Scan Request #123, Method: atomic" ||
			createScanJSON.Settings.Description != "Scan Request #123, Method: atomic" ||
			createScanJSON.Settings.FolderID != "65" ||
			createScanJSON.Settings.ScannerID != "1" ||
			createScanJSON.Settings.PolicyID != "54" ||
			createScanJSON.Settings.TextTargets != "192.168.2.0/24 192.168.3.0/24 192.168.4.0/24" ||
			createScanJSON.Settings.FileTargets != "" ||
			createScanJSON.Settings.Launch != "ONETIME" ||
			createScanJSON.Settings.Enabled != false ||
			createScanJSON.Settings.LaunchNow != false ||
			createScanJSON.Settings.Emails != "" {
			t.FailNow()
		}
	}
}

func TestScanMethodToPolicyID(t *testing.T) {
	creator := Creator{}
	policyID := creator.scanMethodToPolicyID("allportswithping")
	if policyID != "52" {
		t.FailNow()
	}

	policyID = creator.scanMethodToPolicyID("allportsnoping")
	if policyID != "53" {
		t.FailNow()
	}

	policyID = creator.scanMethodToPolicyID("atomic")
	if policyID != "54" {
		t.FailNow()
	}

	policyID = creator.scanMethodToPolicyID("pci")
	if policyID != "55" {
		t.FailNow()
	}

	policyID = creator.scanMethodToPolicyID("other")
	if policyID != "19" {
		t.FailNow()
	}
}
