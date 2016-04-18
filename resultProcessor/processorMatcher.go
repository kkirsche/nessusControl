package nessusProcessor

import "regexp"

func intMatch(a, b int) bool {
	return a == b
}

func intSliceMatch(resultInt int, criteriaInts []int) []bool {
	match := []bool{}

	for _, criteriaInt := range criteriaInts {
		if resultInt == criteriaInt {
			match = append(match, true)
		}
	}

	return match
}

func stringMatch(a, b string) bool {
	return a == b
}

func stringSliceMatch(resultString string, criteriaStrings []string) []bool {
	match := []bool{}

	for _, criteriaString := range criteriaStrings {
		if resultString == criteriaString {
			match = append(match, true)
		}
	}

	return match
}

func regexpStringSliceMatch(resultString string, regexpStrings []string) []bool {
	match := []bool{}

	for _, regexpString := range regexpStrings {
		compiledRegexp := regexp.MustCompile(regexpString)
		if compiledRegexp.FindStringIndex(resultString) != nil {
			match = append(match, true)
		}
	}

	return match
}

func notRegexpStringSliceMatch(resultString string, regexpStrings []string) []bool {
	match := []bool{}

	for _, regexpString := range regexpStrings {
		compiledRegexp := regexp.MustCompile(regexpString)
		if compiledRegexp.FindStringIndex(resultString) == nil {
			match = append(match, true)
		}
	}

	return match
}
