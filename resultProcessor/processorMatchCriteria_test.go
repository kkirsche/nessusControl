package nessusProcessor

import (
	"testing"
)

func TestPositiveAnyMatch(t *testing.T) {
	matches := []bool{false, false, true}
	criteria := "any"

	result := checkMatchCriteria(matches, criteria)
	if !result {
		t.FailNow()
	}
}

func TestNegativeAnyMatch(t *testing.T) {
	matches := []bool{false, false, false}
	criteria := "any"

	result := checkMatchCriteria(matches, criteria)
	if result {
		t.FailNow()
	}
}

func TestPositiveAllMatch(t *testing.T) {
	matches := []bool{true, true, true}
	criteria := "all"

	result := checkMatchCriteria(matches, criteria)
	if !result {
		t.FailNow()
	}
}

func TestNegativeAllMatch(t *testing.T) {
	matches := []bool{true, false, true}
	criteria := "all"

	result := checkMatchCriteria(matches, criteria)
	if result {
		t.FailNow()
	}
}

func TestUnknownMatchCriteria(t *testing.T) {
	matches := []bool{true, false, true}
	criteria := "something"

	result := checkMatchCriteria(matches, criteria)
	if result {
		t.FailNow()
	}
}
