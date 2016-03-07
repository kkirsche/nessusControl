// Package nessusResultProcessor is used to process Nessus CSV result files
// with custom logic for use within a company or enterprise.
package nessusResultProcessor

// IsPluginDMZPolicyViolation checks whether a plugin is a violation of policy
// when located within a demilitarized zone (DMZ) within, as defined by your
// configuration file.
func IsPluginDMZPolicyViolation(pluginID string, positivePolicyViolationIDs []string,
	isInDMZ bool) bool {
	violation := false
	if isInDMZ {
		for _, positiveViolationID := range positivePolicyViolationIDs {
			if pluginID == positiveViolationID {
				violation = true
			}
		}
	}
	return violation
}
