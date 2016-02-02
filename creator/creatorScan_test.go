package nessusCreator

import (
	"testing"
)

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
