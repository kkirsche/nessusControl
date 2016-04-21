package nessusProcessor

import (
	"fmt"
	"html"

	"github.com/kkirsche/nessusControl/database"
)

const (
	scanDBDatabaseName = "nessus"

	// TLS Key and Certificate location(s)
	tlsCACertRelativePath     = "/certs/cacert.pem"
	tlsClientCertRelativePath = "/certs/client-cert.pem"
	tlsClientKeyRelativePath  = "/certs/client-key.pem"
)

// ResultRowProcessorPipeline is used to process a single result row from the
// Nessus CSV Result file
func ResultRowProcessorPipeline(scannerIP string,
	result *Nessus6ResultRow,
	riskToSeverity *RiskRewriteValuesCriteria,
	riskrewritePlugins []RiskRewritePluginsCriteria,
	policyViolationsCriteria []PolicyViolationMatchCriteria,
	falsePositiveCriteria []FalsePositiveMatchCriteria) error {

	tlsInfo := &nessusDatabase.TLSCertificates{
		BasePath:               tlsBasePath,
		CACertRelativePath:     tlsCACertRelativePath,
		ClientCertRelativePath: tlsClientCertRelativePath,
		ClientKeyRelativePath:  tlsClientKeyRelativePath,
	}

	db, err := nessusDatabase.ConnectToMySQLDatabase(scanDBUser, scanDBPass, scanDBDatabaseName, scanDBServer, tlsInfo, true)
	if err != nil {
		return err
	}

	scanner, err := RetrieveScannerOrganizationAndRegionID(scannerIP, db)
	if err != nil {
		return err
	}

	result.OrganizationID = scanner.OrganizationID

	protoNumber := LookupProtocolNumberByProtocolString(result.Protocol)
	if protoNumber == -1 {
		return fmt.Errorf("This protocol's numeric representation could not be found.")
	}
	result.ProtocolNumber = protoNumber

	severity, err := riskToSeverity.RiskTextToNumber(result.Risk)
	if err != nil {
		return err
	}

	match, severity := IsSeverityDefinedForCriteria(result, riskrewritePlugins)
	if match {
		result.Severity = severity
	}

	result.PolicyViolation = IsPolicyViolation(result, policyViolationsCriteria)
	result.FalsePositive, err = IsFalsePositive(result, falsePositiveCriteria, db)
	if err != nil {
		return err
	}

	result.PCIDSSAddress, err = IsOrgIDHostPairPCIDSSAddress(result, db)
	if err != nil {
		return err
	}

	if result.PCIDSSAddress && result.FalsePositive {
		err := UpdateDBWithScannerDetectedException(result, db)
		if err != nil {
			return err
		}
	}

	// EscapeString escapes special characters like "<" to become "&lt;".
	// It escapes only five such characters: <, >, &, ' and "
	result.Description = html.EscapeString(result.Description)

	return nil
}
