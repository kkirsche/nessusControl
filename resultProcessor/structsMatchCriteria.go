package nessusProcessor

// PolicyViolationMatchCriteria holds what criteria should be checked when checking for a
// policy violation.
type PolicyViolationMatchCriteria struct {
	ExternallyAccessible             bool
	IgnoreViolationWithCriteriaMatch bool
	PreviousViolationCheck           bool
	CountIf                          string
	DescriptionRegexp                []string
	NotDescriptionRegexp             []string
	PluginID                         int
	Ports                            []int
	OrganizationIDs                  []int
	RegionIDs                        []int
}
