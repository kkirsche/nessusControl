package nessusCreator

import (
	"crypto/tls"
	"github.com/kkirsche/nessusControl/api"
	"net/http"
	"os"
	"testing"
)

// IngestPipeline is used to run the creator's ingest pipeline
func TestIngestPipeline(t *testing.T) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := &http.Client{Transport: transport}
	debug := false
	apiClient := nessusAPI.NewAccessTokenClient("127.0.0.1", "8834", "testU", "testP", debug)

	pwd, err := os.Getwd()
	if err != nil {
		t.FailNow()
	}

	creator := NewCreator(pwd+"/test/fixtures", apiClient, httpClient, debug)
	err = creator.IngestPipeline(false)
	if err != nil {
		t.FailNow()
	}
}
