package nessusProcessor

import "database/sql"

// IsFalsePositive checks for matches in the falsePositive section of the
// configuration file.
func IsFalsePositive(result *Nessus6ResultRow, falsePositiveCriteria []FalsePositiveMatchCriteria, db *sql.DB) (bool, error) {
	var falsePositives []bool

	for _, criteria := range falsePositiveCriteria {
		// fp1 is short for false positive 1. This is simply numbered to avoid
		// variable shadowing and potential confusion.
		fp1, err := criteria.IsFalsePositiveMatch(result, db)
		if err != nil {
			return false, err
		}
		falsePositives = append(falsePositives, fp1)
	}

	falsePositive := true
	// fp2 is short for false positive 2. This is simply numbered to avoid
	// variable shadowing and potential confusion.
	for _, fp2 := range falsePositives {
		if !fp2 {
			falsePositive = fp2
		}
	}

	return falsePositive, nil

}

// IsFalsePositiveMatch checks for a match against the false positive
// criteria in the falsePositive section of the configuration file.
func (f *FalsePositiveMatchCriteria) IsFalsePositiveMatch(r *Nessus6ResultRow, db *sql.DB) (bool, error) {
	falsePositive := false
	results := []bool{}

	results = append(results, intMatch(r.PluginID, f.PluginID))

	portMatches := intSliceMatch(r.Port, f.Ports)
	results = append(results, checkMatchCriteria(portMatches, "all"))

	results = append(results, stringMatch(r.Protocol, f.Protocol))

	descriptionMatches := regexpStringSliceMatch(r.Description, f.DescriptionRegexp)
	results = append(results, checkMatchCriteria(descriptionMatches, "any"))

	// As we require all criteria to match, we can't aggregate this if we
	// shouldn't test for it as it may return false for many hosts
	if f.IsIPWithinExternalRegion {
		isExternal, err := IsIPWithinExternalOrganization(r, db)
		if err != nil {
			return falsePositive, err
		}

		results = append(results, isExternal)
	}

	// As we require all criteria to match, we can't aggregate this if we
	// shouldn't test for it as it may return false for many hosts
	if f.SQLSolarisCheck {
		isSolaris, err := IsScannedHostSolaris(r, db)
		if err != nil {
			return falsePositive, err
		}
		results = append(results, isSolaris)
	}

	falsePositive = checkMatchCriteria(results, "all")

	return falsePositive, nil
}
