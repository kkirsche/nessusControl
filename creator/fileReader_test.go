package nessusCreator

import (
	"os"
	"testing"
)

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
