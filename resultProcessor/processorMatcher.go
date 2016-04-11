package nessusProcessor

import (
	"regexp"
)

func intMatch(resultInt int, criteriaInts []int) []bool {
	match := []bool{}

	for _, criteriaInt := range criteriaInts {
		if resultInt == criteriaInt {
			match = append(match, true)
		}
	}

	return match
}

func stringMatch(resultString string, criteriaStrings []string) []bool {
	match := []bool{}

	for _, criteriaString := range criteriaStrings {
		if resultString == criteriaString {
			match = append(match, true)
		}
	}

	return match
}

func regexpStringMatch(resultString string, regexpStrings []string) []bool {
	match := []bool{}

	for _, regexpString := range regexpStrings {
		compiledRegexp := regexp.MustCompile(regexpString)
		if compiledRegexp.FindStringIndex(resultString) != nil {
			match = append(match, true)
		}
	}

	return match
}
