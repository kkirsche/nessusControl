package nessusDatabase

// TLSCertificates contains information about where TLS information for a MySQL
// connection are stored
type TLSCertificates struct {
	BasePath               string
	CACertRelativePath     string
	ClientCertRelativePath string
	ClientKeyRelativePath  string
}
