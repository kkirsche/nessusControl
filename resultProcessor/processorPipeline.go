package nessusProcessor

import (
	"html"

	"github.com/kkirsche/nessusControl/database"
)


// ResultProcessorPipeline is used to process
func ResultProcessorPipeline(result *Nessus6ResultRow,
	riskToSeverity *RiskRewriteValuesCriteria,
	riskrewritePlugins []RiskRewritePluginsCriteria,
	policyViolationsCriteria []PolicyViolationMatchCriteria,
	falsePositiveCriteria []FalsePositiveMatchCriteria) error {

	tlsInfo := &nessusDatabase.TLSCertificates{
		BasePath:               "",
		CACertRelativePath:     "",
		ClientCertRelativePath: "",
		ClientKeyRelativePath:  "",
	}

	db, err := nessusDatabase.ConnectToMySQLDatabase(scanDBUser, scanDBPass, scanDBDatabaseName, scanDBServer, tlsInfo, true)
	if err != nil {
		return err
	}
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

	// EscapeString escapes special characters like "<" to become "&lt;".
	// It escapes only five such characters: <, >, &, ' and "
	result.Description = html.EscapeString(result.Description)

	return nil
}
