package nessusProcessor

import "fmt"

// SeverityTextToNumber converts a textual severity into a numeric severity
func (s *SeverityRewriteValuesCriteria) SeverityTextToNumber(severity string) (int, error) {
	switch severity {
	case "High":
		return s.High, nil
	case "Medium":
		return s.Medium, nil
	case "Low":
		return s.Low, nil
	case "No Risk":
		return s.NoRisk, nil
	default:
		return 0, fmt.Errorf("Received unknown severity string. Expected: 'High', 'Medium', 'Low', or 'No Risk'. Received: " + severity)
	}
}
