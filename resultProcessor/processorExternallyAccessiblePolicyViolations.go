// Package nessusResultProcessor is used to process Nessus CSV result files
// with custom logic for use within a company or enterprise.
package nessusResultProcessor

// IsPluginExternallyAccessiblePolicyViolation checks whether a plugin is a violation of policy
// when located within a demilitarized zone (DMZ) within, as defined by your
// configuration file.
func IsPluginExternallyAccessiblePolicyViolation(pluginID string, isInDMZ bool,
	positivePolicyViolationIDs, negativePolicyViolationIDs []string) bool {
	violation := false

	if isInDMZ {
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
	}
	return violation
}
