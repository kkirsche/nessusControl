package nessusProcessor

import "testing"

func TestPositiveIntMatch(t *testing.T) {
	a := 1
	b := 1
	if !intMatch(a, b) {
		t.FailNow()
	}
}

func TestNegativeIntMatch(t *testing.T) {
	a := 1
	b := 2
	if intMatch(a, b) {
		t.FailNow()
	}
}

func TestPositiveIntSliceMatch(t *testing.T) {
	result := 321
	criteria := []int{123, 321}

	matches := intSliceMatch(result, criteria)
	for _, match := range matches {
		if !match {
			t.FailNow()
		}
	}
}

func TestNegativeIntSliceMatch(t *testing.T) {
	result := 555
	criteria := []int{123, 321}

	matches := intSliceMatch(result, criteria)
	for _, match := range matches {
		if match {
			t.FailNow()
		}
	}
}

func TestPositiveStringMatch(t *testing.T) {
	a := "1"
	b := "1"
	if !stringMatch(a, b) {
		t.FailNow()
	}
}

func TestNegativeStringMatch(t *testing.T) {
	a := "1"
	b := "2"
	if stringMatch(a, b) {
		t.FailNow()
	}
}

func TestPositiveStringSliceMatch(t *testing.T) {
	result := "321"
	criteria := []string{"123", "321"}

	matches := stringSliceMatch(result, criteria)
	for _, match := range matches {
		if !match {
			t.FailNow()
		}
	}
}

func TestNegativeStringSliceMatch(t *testing.T) {
	result := "555"
	criteria := []string{"123", "321"}

	matches := stringSliceMatch(result, criteria)
	for _, match := range matches {
		if match {
			t.FailNow()
		}
	}
}

func TestPositiveRegexpMatch(t *testing.T) {
	result := "This could be a match!"
	criteria := []string{"(This|That) could be a (success|match)!", "321"}

	matches := regexpStringSliceMatch(result, criteria)
	for _, match := range matches {
		if !match {
			t.FailNow()
		}
	}
}

func TestNegativeRegexpMatch(t *testing.T) {
	result := "This could be a match!"
	criteria := []string{"abcdef", "zyxw"}

	matches := regexpStringSliceMatch(result, criteria)
	for _, match := range matches {
		if match {
			t.FailNow()
		}
	}
}

func TestPositiveNotRegexpMatch(t *testing.T) {
	result := "This could be a match!"
	criteria := []string{"abcdef", "zyxw"}

	matches := notRegexpStringSliceMatch(result, criteria)
	for _, match := range matches {
		if !match {
			t.FailNow()
		}
	}
}

func TestNegativeNotRegexpMatch(t *testing.T) {
	result := "This could be a match!"
	criteria := []string{"(This|That) could be a (success|match)!"}

	matches := notRegexpStringSliceMatch(result, criteria)
	for _, match := range matches {
		if match {
			t.FailNow()
		}
	}
}
