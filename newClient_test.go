package nessus

import (
	"testing"
)

func TestNewUsernameClient(t *testing.T) {
	client := NewUsernameClient("localhost", "1234", "testUsername", "testPassword", false)
	if client.ip != "localhost" ||
		client.port != "1234" ||
		client.username != "testUsername" ||
		client.password != "testPassword" {
		t.FailNow()
	}
}

func TestNewAccessKeyClient(t *testing.T) {
	client := NewAccessTokenClient("localhost", "1234", "testAccessKey", "testSecretKey", false)
	if client.ip != "localhost" ||
		client.port != "1234" ||
		client.accessKey != "testAccessKey" ||
		client.secretKey != "testSecretKey" {
		t.FailNow()
	}
}
