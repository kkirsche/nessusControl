package nessusProcessor

// CheckForViolation checks for matches in the policyViolations section of the
// configuration file. This function checks for matches with the Plugin ID,
// Port, Description Regular Expressions, organization ID, region ID and
// external accessibility.
func (m *MatchCriteria) CheckForViolation(r *Nessus6ResultRow) bool {
	violation := false
	results := []bool{}

	results = append(results, intMatch(r.PluginID, m.PluginID))

	portMatches := intSliceMatch(r.Port, m.Ports)
	results = append(results, checkMatchCriteria(portMatches, m.CountIf))

	descriptionMatches := regexpStringSliceMatch(r.Description, m.DescriptionRegexps)
	results = append(results, checkMatchCriteria(descriptionMatches, m.CountIf))

	organizationIDMatches := intSliceMatch(r.OrganizationID, m.OrganizationIDs)
	results = append(results, checkMatchCriteria(organizationIDMatches, m.CountIf))

	regionIDMatches := intSliceMatch(r.RegionID, m.RegionIDs)
	results = append(results, checkMatchCriteria(regionIDMatches, m.CountIf))

	results = append(results, m.ExternallyAccessible)

	violation = checkMatchCriteria(results, m.CountIf)

	if m.IgnoreViolationWithCriteriaMatch && violation {
		return !violation
	}

	return violation
}
