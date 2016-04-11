package nessusProcessor

func checkMatchCriteria(matches []bool, critera string) bool {
	switch critera {
	case "any":
		result := false
		for _, match := range matches {
			if match {
				result = true
			}
		}
		return result
	case "all":
		result := true
		for _, match := range matches {
			if !match {
				result = false
			}
		}
		return result
	default:
		return false
	}
}
