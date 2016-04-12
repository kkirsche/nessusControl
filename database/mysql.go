// Package nessusDatabase is used to connect to databases for state and result storage.
//
// This package is a supporting package for nessusCreator and nessusResults which
// handle the file to launched scan pipeline and the result retriever / processing
// functionality.
package nessusDatabase

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io/ioutil"

	"github.com/go-sql-driver/mysql"
)

// ConnectToMySQLDatabase generates a secure or insecure TCP MySQL database connection on port 3306
func ConnectToMySQLDatabase(username, password, database, server string, tlsInfo *TLSCertificates, secure bool) (*sql.DB, error) {
	if secure {
		// Create a cert pool
		rootCertPool := x509.NewCertPool()
		// Load the Certificate Authority cert
		pem, err := ioutil.ReadFile(tlsInfo.BasePath + tlsInfo.CACertRelativePath)
		if err != nil {
			return nil, fmt.Errorf("Failed to open ca cert: %s", err.Error())
		}

		// Append the CA cert to the cert pool
		ok := rootCertPool.AppendCertsFromPEM(pem)
		if !ok {
			return nil, fmt.Errorf("Failed to append Certs from PEM.")
		}

		// Load the Client Certificate and Key
		clientCert := make([]tls.Certificate, 0, 1)
		certs, err := tls.LoadX509KeyPair(tlsInfo.BasePath+tlsInfo.ClientCertRelativePath,
			tlsInfo.BasePath+tlsInfo.ClientKeyRelativePath)
		if err != nil {
			return nil, fmt.Errorf("Failed to load x509 client cert and key: %s", err.Error())
		}
		clientCert = append(clientCert, certs)

		// Register the TLS configuration with MySQL
		mysql.RegisterTLSConfig("custom", &tls.Config{
			RootCAs:      rootCertPool,
			Certificates: clientCert,
		})

		// Open the connection
		db, err := sql.Open("mysql", username+":"+password+"@tcp("+server+":3306)/"+database+"?tls=skip-verify")
		if err != nil {
			return nil, fmt.Errorf("Couldn't connect to database: %s", err.Error())
		}

		return db, nil
	}

	url := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s", username, password, server, database)
	db, err := sql.Open("mysql", url)
	if err != nil {
		return nil, fmt.Errorf("Couldn't connect to database: %s", err.Error())
	}
	return db, nil
}
