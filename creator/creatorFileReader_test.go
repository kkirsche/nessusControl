package nessusCreator

import (
	"os"
	"testing"
)

func TestProcessRequestedScanDirectory(t *testing.T) {
	pwd, err := os.Getwd()
	if err != nil {
		t.FailNow()
	}

	creator := Creator{}

	requestedScanCh, err := creator.processRequestedScanDirectory(pwd+"/test/fixtures", false)
	if err != nil {
		t.FailNow()
	}

	for requestedScanData := range requestedScanCh {
		if requestedScanData.RequestedScan.RequestID != "123" ||
			requestedScanData.RequestedScan.Method != "atomic" ||
			requestedScanData.RequestedScan.TargetIPs[0] != "192.168.2.0/24" {
			t.FailNow()
		}
	}
}

func TestProcessRequestedScanFile(t *testing.T) {
	pwd, err := os.Getwd()
	if err != nil {
		t.FailNow()
	}

	creator := Creator{}

	requestedScan, err := creator.processRequestedScanFile(pwd + "/test/fixtures/desiredScan.json")
	if err != nil || requestedScan.RequestID != "123" ||
		requestedScan.Method != "atomic" ||
		requestedScan.TargetIPs[0] != "192.168.2.0/24" {
		t.FailNow()
	}

	requestedScan, err = creator.processRequestedScanFile(pwd + "/test/fixtures/desiredScan.xml")
	if err != nil || requestedScan.RequestID != "123" ||
		requestedScan.Method != "atomic" ||
		requestedScan.TargetIPs[0] != "192.168.2.0/24" {
		t.FailNow()
	}

	requestedScan, err = creator.processRequestedScanFile(pwd + "/test/fixtures/desiredScan.txt")
	if err != nil || requestedScan.RequestID != "123" ||
		requestedScan.Method != "atomic" ||
		requestedScan.TargetIPs[0] != "192.168.2.0/24" {
		t.FailNow()
	}
}

func TestInvalidProcessRequestedScanFile(t *testing.T) {
	pwd, err := os.Getwd()
	if err != nil {
		t.FailNow()
	}

	creator := Creator{}

	_, err = creator.processRequestedScanFile(pwd + "/test/fixtures/desiredScan.whoKnowsWhat")
	if err.Error() != "Requested scan file format is not supported." {
		t.FailNow()
	}
}

func TestReadJSON(t *testing.T) {
	pwd, err := os.Getwd()
	if err != nil {
		t.FailNow()
	}

	creator := Creator{}

	requestedScan, err := creator.readJSON(pwd + "/test/fixtures/desiredScan.json")
	if err != nil || requestedScan.RequestID != "123" ||
		requestedScan.Method != "atomic" ||
		requestedScan.TargetIPs[0] != "192.168.2.0/24" {
		t.FailNow()
	}
}

func TestReadXML(t *testing.T) {
	pwd, err := os.Getwd()
	if err != nil {
		t.FailNow()
	}

	creator := Creator{}

	requestedScan, err := creator.readXML(pwd + "/test/fixtures/desiredScan.xml")
	if err != nil || requestedScan.RequestID != "123" ||
		requestedScan.Method != "atomic" ||
		requestedScan.TargetIPs[0] != "192.168.2.0/24" {
		t.FailNow()
	}
}

func TestReadTextFile(t *testing.T) {
	pwd, err := os.Getwd()
	if err != nil {
		t.FailNow()
	}

	creator := Creator{}

	requestedScan, err := creator.readText(pwd + "/test/fixtures/desiredScan.txt")
	if err != nil || requestedScan.RequestID != "123" ||
		requestedScan.Method != "atomic" ||
		requestedScan.TargetIPs[0] != "192.168.2.0/24" {
		t.FailNow()
	}
}
