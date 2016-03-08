// Package nessusResultProcessor is used to process Nessus CSV result files
// with custom logic for use within a company or enterprise.
package nessusResultProcessor

// IsPluginPolicyViolation checks whether a plugin is a violation of policy, as
// defined by your configuration file.
func IsPluginPolicyViolation(pluginID string, positivePolicyViolationIDs,
	negativePolicyViolationIDs []string) bool {
	violation := false

	for _, negativeViolationID := range negativePolicyViolationIDs {
		if pluginID == negativeViolationID {
			return violation
		}
	}

	for _, positiveViolationID := range positivePolicyViolationIDs {
		if pluginID == positiveViolationID {
			violation = true
		}
	}
	return violation
}
