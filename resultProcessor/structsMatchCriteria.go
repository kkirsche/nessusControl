package nessusProcessor

// MatchCriteria holds what criteria should be checked when checking for a
// policy violation.
type MatchCriteria struct {
	PluginID                         int
	ExternallyAccessible             bool
	Ports                            []int
	DescriptionRegexps               []string
	OrganizationIDs                  []int
	RegionIDs                        []int
	IgnoreViolationWithCriteriaMatch bool
	CountIf                          string
}
