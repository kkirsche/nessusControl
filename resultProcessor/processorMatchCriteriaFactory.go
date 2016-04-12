package nessusProcessor

// NewMatchCriteria creates a MatchCriteria structure and returns a pointer to
// the new structure.
func NewMatchCriteria(pluginID int, externallyAccessible,
	ignoreViolationWithCriteriaMatch bool, ports, organizationIDs, regionIDs []int,
	descriptionRegularExpressions []string, countIf string) *MatchCriteria {
	return &MatchCriteria{
		PluginID:                         pluginID,
		ExternallyAccessible:             externallyAccessible,
		IgnoreViolationWithCriteriaMatch: ignoreViolationWithCriteriaMatch,
		Ports:              ports,
		OrganizationIDs:    organizationIDs,
		RegionIDs:          regionIDs,
		DescriptionRegexps: descriptionRegularExpressions,
		CountIf:            countIf,
	}
}
