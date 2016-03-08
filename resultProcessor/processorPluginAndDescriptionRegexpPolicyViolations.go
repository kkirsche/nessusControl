// Package nessusResultProcessor is used to process Nessus CSV result files
// with custom logic for use within a company or enterprise.
package nessusResultProcessor

import (
	"regexp"
	"strings"
)

// IsPluginWithDescripRegexpPolicyViolation checks whether a plugin, when detected with
// a a regular expression within it's description, is a violation of policy, as
// defined by your configuration file.
func IsPluginWithDescripRegexpPolicyViolation(pluginID, description string,
	positivePolicyViolationRegexpAndID, negativePolicyViolationRegexpAndID []string) bool {
	violation := false

	for _, negativeViolationRegexpAndID := range negativePolicyViolationRegexpAndID {
		stringArray := strings.Split(negativeViolationRegexpAndID, "|^|")
		violationPluginID := stringArray[0]
		violationRegexpStr := stringArray[1]
		violationRegexp := regexp.MustCompile(violationRegexpStr)
		if violationPluginID == pluginID && violationRegexp.MatchString(description) {
			return violation
		}
	}

	for _, positiveViolationRegexpAndID := range positivePolicyViolationRegexpAndID {
		stringArray := strings.Split(positiveViolationRegexpAndID, "|^|")
		violationPluginID := stringArray[0]
		violationRegexpStr := stringArray[1]
		violationRegexp := regexp.MustCompile(violationRegexpStr)
		if violationPluginID == pluginID && violationRegexp.MatchString(description) {
			violation = true
		}
	}
	return violation
}
