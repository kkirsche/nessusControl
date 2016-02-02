package nessusCreator

import (
	"os"
	"testing"
)

func TestFilenameFromPath(t *testing.T) {
	pwd, err := os.Getwd()
	if err != nil {
		t.FailNow()
	}

	creator := Creator{}

	filename := creator.filenameFromPath(pwd + "/test/fixtures/desiredScan.json")
	if filename != "desiredScan.json" {
		t.FailNow()
	}
}
