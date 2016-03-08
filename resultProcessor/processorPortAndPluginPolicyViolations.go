// Package nessusResultProcessor is used to process Nessus CSV result files
// with custom logic for use within a company or enterprise.
package nessusResultProcessor

import (
	"strings"
)

// IsPluginWithPortPolicyViolation checks whether a plugin, when detected with
// a specific port,is a violation of policy,as defined by your configuration file.
func IsPluginWithPortPolicyViolation(pluginID, port string,
	positivePolicyViolationPortAndIDs, negativePolicyViolationPortAndIDs []string) bool {
	violation := false

	for _, negativeViolationPortAndID := range negativePolicyViolationPortAndIDs {
		stringArray := strings.Split(negativeViolationPortAndID, "|^|")
		violationPluginID := stringArray[0]
		violationPortNumber := stringArray[1]
		if violationPluginID == pluginID && violationPortNumber == port {
			return violation
		}
	}

	for _, positiveViolationPortAndID := range positivePolicyViolationPortAndIDs {
		stringArray := strings.Split(positiveViolationPortAndID, "|^|")
		violationPluginID := stringArray[0]
		violationPortNumber := stringArray[1]
		if violationPluginID == pluginID && violationPortNumber == port {
			violation = true
		}
	}
	return violation
}
