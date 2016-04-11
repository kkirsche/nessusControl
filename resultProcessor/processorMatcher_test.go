package nessusProcessor

import (
	"testing"
)

func TestPositiveIntMatch(t *testing.T) {
	result := 321
	criteria := []int{123, 321}

	matches := intMatch(result, criteria)
	for _, match := range matches {
		if !match {
			t.FailNow()
		}
	}
}

func TestNegativeIntMatch(t *testing.T) {
	result := 555
	criteria := []int{123, 321}

	matches := intMatch(result, criteria)
	for _, match := range matches {
		if match {
			t.FailNow()
		}
	}
}

func TestPositiveStringMatch(t *testing.T) {
	result := "321"
	criteria := []string{"123", "321"}

	matches := stringMatch(result, criteria)
	for _, match := range matches {
		if !match {
			t.FailNow()
		}
	}
}

func TestNegativeStringMatch(t *testing.T) {
	result := "555"
	criteria := []string{"123", "321"}

	matches := stringMatch(result, criteria)
	for _, match := range matches {
		if match {
			t.FailNow()
		}
	}
}

func TestPositiveRegexpMatch(t *testing.T) {
	result := "This could be a match!"
	criteria := []string{"(This|That) could be a (success|match)!", "321"}

	matches := regexpStringMatch(result, criteria)
	for _, match := range matches {
		if !match {
			t.FailNow()
		}
	}
}

func TestNegativeRegexpMatch(t *testing.T) {
	result := "This could be a match!"
	criteria := []string{"abcdef", "zyxw"}

	matches := regexpStringMatch(result, criteria)
	for _, match := range matches {
		if match {
			t.FailNow()
		}
	}
}
