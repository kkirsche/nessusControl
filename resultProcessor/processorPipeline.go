package nessusProcessor

import "html"

// ResultProcessorPipeline is used to process
func ResultProcessorPipeline(result *Nessus6ResultRow,
	riskToSeverity *RiskRewriteValuesCriteria,
	riskrewritePlugins []RiskRewritePluginsCriteria,
	policyViolationsCriteria []PolicyViolationMatchCriteria,
	falsePositiveCriteria []FalsePositiveMatchCriteria) error {
	severity, err := riskToSeverity.RiskTextToNumber(result.Risk)
	if err != nil {
		return err
	}

	match, severity := IsSeverityDefinedForCriteria(result, riskrewritePlugins)
	if match {
		result.Severity = severity
	}

	result.PolicyViolation = IsPolicyViolation(result, policyViolationsCriteria)
	result.FalsePositive = IsFalsePositive(result, falsePositiveCriteria)

	// EscapeString escapes special characters like "<" to become "&lt;".
	// It escapes only five such characters: <, >, &, ' and "
	result.Description = html.EscapeString(result.Description)

	return nil
}
