package nessusProcessor

// Nessus6ResultRow represents a single row of an exported CSV results file from
// Tenable's Nessus 6.
type Nessus6ResultRow struct {
	// Nessus default inclusions
	PluginID     int
	CVE          string
	CVSS         int
	Risk         string
	Host         string
	Protocol     string
	Port         int
	Name         string
	Synopsis     string
	Description  string
	Solution     string
	SeeAlso      string
	PluginOutput string

	// Additional (Optional) Criteria. Usually only necessary in larger companies
	ExternallyAccessible bool
	FalsePositive        bool
	PolicyViolation      bool
	ProtocolNumber       int
	OrganizationID       int
	RegionID             int
	Severity             int
}

// Nessus6Scanner represents the information about the Nessus scanner
type Nessus6Scanner struct {
	IP             string
	RegionID       int
	OrganizationID int
}
