package nessusProcessor

func intMatch(resultInt int, criteriaInts []int) bool {
	var match = false

	for _, criteriaInt := range criteriaInts {
		if resultInt == criteriaInt {
			match = true
		}
	}

	return match
}

func stringMatch(resultString string, criteriaStrings []string) bool {
	var match = false

	for _, criteriaString := range criteriaStrings {
		if resultString == criteriaString {
			match = true
		}
	}

	return match
}
