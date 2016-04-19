package nessusProcessor

// IsPolicyViolation checks for matches in the policyViolations section of the
// configuration file. This function checks for matches with the Plugin ID,
// Port, Description Regular Expressions, organization ID, region ID and
// external accessibility.
func IsPolicyViolation(result *Nessus6ResultRow, policyViolationsCriteria []PolicyViolationMatchCriteria) bool {
	var violations []bool

	for _, violationCriteria := range policyViolationsCriteria {
		violations = append(violations, violationCriteria.IsPolicyViolationMatch(result))
	}

	policyViolation := true
	for _, violation := range violations {
		if !violation {
			policyViolation = violation
		}
	}

	return policyViolation

}

// IsPolicyViolationMatch checks for a match against the policy violation
// criteria in the policyViolations section of the configuration file.
// This function checks for matches with the Plugin ID, Port, Description
// Regular Expressions, organization ID, region ID and external accessibility.
func (p *PolicyViolationMatchCriteria) IsPolicyViolationMatch(r *Nessus6ResultRow) bool {
	violation := false
	results := []bool{}

	results = append(results, intMatch(r.PluginID, p.PluginID))

	portMatches := intSliceMatch(r.Port, p.Ports)
	results = append(results, checkMatchCriteria(portMatches, p.CountIf))

	descriptionMatches := regexpStringSliceMatch(r.Description, p.DescriptionRegexp)
	results = append(results, checkMatchCriteria(descriptionMatches, p.CountIf))

	organizationIDMatches := intSliceMatch(r.OrganizationID, p.OrganizationIDs)
	results = append(results, checkMatchCriteria(organizationIDMatches, p.CountIf))

	regionIDMatches := intSliceMatch(r.RegionID, p.RegionIDs)
	results = append(results, checkMatchCriteria(regionIDMatches, p.CountIf))

	results = append(results, p.ExternallyAccessible)

	violation = checkMatchCriteria(results, p.CountIf)

	if p.IgnoreViolationWithCriteriaMatch && violation {
		return !violation
	}

	return violation
}
