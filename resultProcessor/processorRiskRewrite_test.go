package nessusProcessor

import "testing"

func TestHighSeverityTextToNumber(t *testing.T) {
	s := &RiskRewriteValuesCriteria{
		High: 10,
	}

	severity, err := s.RiskTextToNumber("High")
	if err != nil || severity != 10 {
		t.FailNow()
	}
}

func TestMediumSeverityTextToNumber(t *testing.T) {
	s := &RiskRewriteValuesCriteria{
		Medium: 5,
	}

	severity, err := s.RiskTextToNumber("Medium")
	if err != nil || severity != 5 {
		t.FailNow()
	}
}

func TestLowSeverityTextToNumber(t *testing.T) {
	s := &RiskRewriteValuesCriteria{
		Low: 1,
	}

	severity, err := s.RiskTextToNumber("Low")
	if err != nil || severity != 1 {
		t.FailNow()
	}
}

func TestNoRiskSeverityTextToNumber(t *testing.T) {
	s := &RiskRewriteValuesCriteria{
		NoRisk: 0,
	}

	severity, err := s.RiskTextToNumber("No Risk")
	if err != nil || severity != 0 {
		t.FailNow()
	}
}

func TestErrorSeverityTextToNumber(t *testing.T) {
	s := &RiskRewriteValuesCriteria{}

	severity, err := s.RiskTextToNumber("Hax0r News")
	if err.Error() != "Received unknown severity string. Expected: 'High', 'Medium', 'Low', or 'No Risk'. Received: Hax0r News" ||
		severity != 0 {
		t.FailNow()
	}
}

func TestMatchingValidateCriteriaForPluginID(t *testing.T) {
	r := RiskRewritePluginsCriteria{
		PluginID:             123,
		ExternallyAccessible: true,
		Severity:             21,
	}

	ok, severity := r.ValidateCriteriaForPluginID(123, true)

	if !ok || severity != 21 {
		t.FailNow()
	}
}

func TestNonMatchingValidateCriteriaForPluginID(t *testing.T) {
	r := RiskRewritePluginsCriteria{
		PluginID:             123,
		ExternallyAccessible: true,
		Severity:             21,
	}

	ok, severity := r.ValidateCriteriaForPluginID(321, true)

	if ok || severity != 0 {
		t.FailNow()
	}
}

func TestMatchingIsSeverityDefinedForCriteria(t *testing.T) {
	r1 := RiskRewritePluginsCriteria{
		PluginID:             123,
		ExternallyAccessible: true,
		Severity:             21,
	}

	r2 := RiskRewritePluginsCriteria{
		PluginID:             456,
		ExternallyAccessible: false,
		Severity:             42,
	}

	r := []RiskRewritePluginsCriteria{r1, r2}

	n := &Nessus6ResultRow{
		PluginID:             456,
		ExternallyAccessible: false,
	}

	match, severity := IsSeverityDefinedForCriteria(n, r)

	if match {
		n.Severity = severity
	}

	if n.Severity != 42 {
		t.FailNow()
	}
}

func TestNonMatchingIsSeverityDefinedForCriteria(t *testing.T) {
	r1 := RiskRewritePluginsCriteria{
		PluginID:             123,
		ExternallyAccessible: true,
		Severity:             21,
	}

	r2 := RiskRewritePluginsCriteria{
		PluginID:             456,
		ExternallyAccessible: false,
		Severity:             42,
	}

	r := []RiskRewritePluginsCriteria{r1, r2}

	n := &Nessus6ResultRow{
		PluginID: 890,
	}

	match, severity := IsSeverityDefinedForCriteria(n, r)

	if match {
		n.Severity = severity
	}

	if n.Severity != 0 {
		t.FailNow()
	}
}
