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

func TestLaunchScan(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"scan_uuid": "3390954f-63b5-1604-78b9-94237d20c69fd45c9012e5d18f69"}`
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

	creator := NewCreator("/some/place", client, httpClient, nil, false)
	createdScanCh := make(chan ScanData)

	go func(createdScanCh chan ScanData) {
		for i := 0; i < 5; i++ {
			scanSetting := struct {
				CreationDate           int    `json:"creation_date"`
				CustomTargets          string `json:"custom_targets"`
				DefaultPermisssions    int    `json:"default_permisssions"`
				Description            string `json:"description"`
				Emails                 string `json:"emails"`
				Enabled                bool   `json:"enabled"`
				ID                     int    `json:"id"`
				LastModificationDate   int    `json:"last_modification_date"`
				Name                   string `json:"name"`
				NotificationFilterType string `json:"notification_filter_type"`
				NotificationFilters    string `json:"notification_filters"`
				Owner                  string `json:"owner"`
				OwnerID                int    `json:"owner_id"`
				PolicyID               int    `json:"policy_id"`
				Rrules                 string `json:"rrules"`
				ScannerID              int    `json:"scanner_id"`
				Shared                 int    `json:"shared"`
				Starttime              string `json:"starttime"`
				TagID                  int    `json:"tag_id"`
				Timezone               string `json:"timezone"`
				Type                   string `json:"type"`
				UseDashboard           bool   `json:"use_dashboard"`
				UserPermissions        int    `json:"user_permissions"`
				UUID                   string `json:"uuid"`
			}{ID: 1}
			createdScanCh <- ScanData{CreatedScan: nessusAPI.CreateScanResponse{
				Scan: scanSetting,
			},
			}
		}
		close(createdScanCh)
	}(createdScanCh)

	launchedScanCh := creator.launchScan(createdScanCh)
	for launchedScanData := range launchedScanCh {
		if launchedScanData.LaunchedScan.ScanUUID != "3390954f-63b5-1604-78b9-94237d20c69fd45c9012e5d18f69" {
			t.FailNow()
		}
	}
}

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

	creator := NewCreator("/some/place", client, httpClient, nil, false)
	createScanCh := make(chan ScanData)

	go func(createScanCh chan ScanData) {
		for i := 0; i < 5; i++ {
			createScanCh <- ScanData{
				CreateScanJSON: nessusAPI.CreateScan{
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
				},
			}
		}
		close(createScanCh)
	}(createScanCh)

	createScanResponseCh := creator.createScan(createScanCh)
	for createdScanResponseData := range createScanResponseCh {
		if createdScanResponseData.CreatedScan.Scan.UUID != "template-9f6a69d0-709e-22b1-f696-e1de009f6a8faf787b8b14d3a111" ||
			createdScanResponseData.CreatedScan.Scan.Name != "Example Scan" {
			t.FailNow()
		}
	}
}

func TestBuildCreateScanJSON(t *testing.T) {
	creator := Creator{}
	requestScanCh := make(chan ScanData)

	go func(requestScanCh chan ScanData) {
		for i := 0; i < 5; i++ {
			requestScanCh <- ScanData{
				RequestedScan: RequestedScan{
					RequestID: "123",
					Method:    "atomic",
					TargetIPs: []string{
						"192.168.2.0/24",
						"192.168.3.0/24",
						"192.168.4.0/24",
					},
				},
			}
		}

		close(requestScanCh)
	}(requestScanCh)

	createScanCh := creator.buildCreateScanJSON(requestScanCh)
	for createScanJSONData := range createScanCh {
		if createScanJSONData.CreateScanJSON.UUID != "ab4bacd2-05f6-425c-9d79-3ba3940ad1c24e51e1f403febe40" ||
			createScanJSONData.CreateScanJSON.Settings.Name != "Scan Request #123, Method: atomic" ||
			createScanJSONData.CreateScanJSON.Settings.Description != "Scan Request #123, Method: atomic" ||
			createScanJSONData.CreateScanJSON.Settings.FolderID != "65" ||
			createScanJSONData.CreateScanJSON.Settings.ScannerID != "1" ||
			createScanJSONData.CreateScanJSON.Settings.PolicyID != "54" ||
			createScanJSONData.CreateScanJSON.Settings.TextTargets != "192.168.2.0/24 192.168.3.0/24 192.168.4.0/24" ||
			createScanJSONData.CreateScanJSON.Settings.FileTargets != "" ||
			createScanJSONData.CreateScanJSON.Settings.Launch != "ONETIME" ||
			createScanJSONData.CreateScanJSON.Settings.Enabled != false ||
			createScanJSONData.CreateScanJSON.Settings.LaunchNow != false ||
			createScanJSONData.CreateScanJSON.Settings.Emails != "" {
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
