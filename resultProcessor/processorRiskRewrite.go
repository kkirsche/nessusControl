package nessusProcessor

import "fmt"

// RiskTextToNumber converts a textual severity into a numeric severity
func (r *RiskRewriteValuesCriteria) RiskTextToNumber(risk string) (int, error) {
	switch risk {
	case "High":
		return r.High, nil
	case "Medium":
		return r.Medium, nil
	case "Low":
		return r.Low, nil
	case "No Risk":
		return r.NoRisk, nil
	default:
		return 0, fmt.Errorf("Received unknown severity string. Expected: 'High', 'Medium', 'Low', or 'No Risk'. Received: " + risk)
	}
}

// CheckForUserDefinedPluginRisk checks if any of the user-provided criteria
// match the provided result row. If it does, this sets the new severity
func CheckForUserDefinedPluginRisk(result *Nessus6ResultRow, pluginCriteria []RiskRewritePluginsCriteria) {
	for _, criteria := range pluginCriteria {
		ok, severity := criteria.ValidateCriteriaForPluginID(result.PluginID, result.ExternallyAccessible)
		if ok {
			result.Severity = severity
		}
	}
}

// ValidateCriteriaForPluginID converts checks if user supplied criteria matches. If
// it does, we return the new user-defined severity for this plugin.
func (s *RiskRewritePluginsCriteria) ValidateCriteriaForPluginID(pluginID int, externallyAccessible bool) (bool, int) {
	if pluginID == s.PluginID && externallyAccessible == s.ExternallyAccessible {
		return true, s.Severity
	}

	return false, 0
}
