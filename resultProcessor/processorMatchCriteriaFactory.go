package nessusProcessor

// NewPolicyViolationMatchCriteria creates a PolicyViolationMatchCriteria
// structure and returns a pointer to the new structure.
func NewPolicyViolationMatchCriteria(pluginID int, externallyAccessible,
	ignoreViolationWithCriteriaMatch bool, ports, organizationIDs, regionIDs []int,
	descriptionRegularExpressions []string, countIf string) *PolicyViolationMatchCriteria {
	return &PolicyViolationMatchCriteria{
		PluginID:                         pluginID,
		ExternallyAccessible:             externallyAccessible,
		IgnoreViolationWithCriteriaMatch: ignoreViolationWithCriteriaMatch,
		Ports:             ports,
		OrganizationIDs:   organizationIDs,
		RegionIDs:         regionIDs,
		DescriptionRegexp: descriptionRegularExpressions,
		CountIf:           countIf,
	}
}
