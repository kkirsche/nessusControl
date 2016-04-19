package nessusProcessor

// IsFalsePositive checks for matches in the falsePositive section of the
// configuration file.
func IsFalsePositive(result *Nessus6ResultRow, falsePositiveCriteria []FalsePositiveMatchCriteria) bool {
	var falsePositives []bool

	for _, criteria := range falsePositiveCriteria {
		falsePositives = append(falsePositives, criteria.IsFalsePositiveMatch(result))
	}

	falsePositive := true
	for _, fp := range falsePositives {
		if !fp {
			falsePositive = fp
		}
	}

	return falsePositive

}

// IsFalsePositiveMatch checks for a match against the false positive
// criteria in the falsePositive section of the configuration file.
func (f *FalsePositiveMatchCriteria) IsFalsePositiveMatch(r *Nessus6ResultRow) bool {
	falsePositive := false
	results := []bool{}

	results = append(results, intMatch(r.PluginID, f.PluginID))

	portMatches := intSliceMatch(r.Port, f.Ports)
	results = append(results, checkMatchCriteria(portMatches, "all"))

	results = append(results, stringMatch(r.Protocol, f.Protocol))

	descriptionMatches := regexpStringSliceMatch(r.Description, f.DescriptionRegexp)
	results = append(results, checkMatchCriteria(descriptionMatches, "any"))

	// results = append(results, IsDefined(r))
	//
	// results = append(results, IsSolaris(r))

	falsePositive = checkMatchCriteria(results, "all")

	return falsePositive
}
