package nessusCreator

import (
	"github.com/kkirsche/nessusControl/api"
	"net/http"
	"testing"
)

func TestNewCreator(t *testing.T) {
	debug := false
	client := nessusAPI.NewUsernameClient("localhost", "8834", "testU", "testP", debug)
	httpClient := &http.Client{}
	creator := NewCreator("/test/path", client, httpClient, nil, debug)

	if creator.debug != false ||
		creator.apiClient != client ||
		creator.fileLocations.baseDirectory != "/test/path" ||
		creator.fileLocations.archiveDirectory != "/test/path/targets/archive" ||
		creator.fileLocations.incomingDirectory != "/test/path/targets/incoming" {
		t.FailNow()
	}
}
