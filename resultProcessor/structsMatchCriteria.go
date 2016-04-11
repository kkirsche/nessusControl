package nessusProcessor

// MatchCriteria holds what criteria should be checked when checking for a
// policy violation.
type MatchCriteria struct {
	PluginID                     int
	ExternallyAccessible         bool
	Port                         []int
	DescriptionRegexp            []string
	OrganizationID               []int
	RegionID                     []int
	IgnoreViolationsWithCriteria bool
	CountIf                      string
}
