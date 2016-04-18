package nessusProcessor

// RiskRewriteCriteria is a container to hold the Values and Plugins configurations
type RiskRewriteCriteria struct {
	Values  RiskRewriteValuesCriteria
	Plugins []RiskRewritePluginsCriteria
}

// RiskRewriteValuesCriteria holds information used by nessusProcessor to
// convert the text severity to a numeric value
type RiskRewriteValuesCriteria struct {
	High   int
	Medium int
	Low    int
	NoRisk int
}

// RiskRewritePluginsCriteria holds information used by nessusProcessor to
// convert a specific plugin to be a specific severity
type RiskRewritePluginsCriteria struct {
	PluginID             int
	ExternallyAccessible bool
	Severity             int
}
