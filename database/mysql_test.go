package nessusDatabase

import "testing"

func TestConnectToMySQLDatabase(t *testing.T) {
	tlsInfo := &TLSCertificates{}
	db, err := ConnectToMySQLDatabase("travis", "", "test", "127.0.0.1", tlsInfo, false)
	if err != nil {
		t.FailNow()
	}
	defer db.Close()
}
