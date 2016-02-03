package nessusCreator

import (
	"crypto/tls"
	"github.com/kkirsche/nessusControl/api"
	"github.com/kkirsche/nessusControl/database"
	"net/http"
	"os"
	"testing"
)

func TestIngestPipeline(t *testing.T) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := &http.Client{Transport: transport}
	debugEnabled := false
	moveFilesDuringPipeline := false
	apiClient := nessusAPI.NewAccessTokenClient("127.0.0.1", "8834", "testU", "testP", debugEnabled)

	pwd, err := os.Getwd()
	if err != nil {
		t.FailNow()
	}

	testDB, err := nessusDatabase.ConnectToSQLite(pwd + "/test/fixtures/testDatabase.db")
	if err != nil {
		t.FailNow()
	}

	creator := NewCreator(pwd+"/test/fixtures", apiClient, httpClient, testDB, debugEnabled)
	err = creator.IngestPipeline(moveFilesDuringPipeline)
	if err != nil {
		t.FailNow()
	}
}
