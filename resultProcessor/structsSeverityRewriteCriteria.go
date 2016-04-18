package nessusProcessor

// SeverityRewriteValuesCriteria holds information used by nessusProcessor to
// convert the text severity to a numeric value
type SeverityRewriteValuesCriteria struct {
	High   int
	Medium int
	Low    int
	NoRisk int
}

// SeverityRewritePluginsCriteria holds information used by nessusProcessor to
// convert a specific plugin to be a specific severity
type SeverityRewritePluginsCriteria struct {
	PluginID             int
	ExternallyAccessible bool
	Severity             int
}
