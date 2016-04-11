package nessusProcessor

import (
	"testing"
)

func TestPositiveIntMatch(t *testing.T) {
	result := 321
	criteria := []int{123, 321}

	match := intMatch(result, criteria)
	if !match {
		t.FailNow()
	}
}

func TestNegativeIntMatch(t *testing.T) {
	result := 555
	criteria := []int{123, 321}

	match := intMatch(result, criteria)
	if match {
		t.FailNow()
	}
}

func TestPositiveStringMatch(t *testing.T) {
	result := "321"
	criteria := []string{"123", "321"}

	match := stringMatch(result, criteria)
	if !match {
		t.FailNow()
	}
}

func TestNegativeStringMatch(t *testing.T) {
	result := "555"
	criteria := []string{"123", "321"}

	match := stringMatch(result, criteria)
	if match {
		t.FailNow()
	}
}
