package nessusResultProcessor

import (
	"testing"
)

func TestPositiveIsPluginWithPortPolicyViolation(t *testing.T) {
	positivePolicyViolationIDs := []string{"12345|^|80"}
	negativePolicyViolationIDs := []string{"12345|^|70"}
	isViolation := IsPluginWithPortPolicyViolation("12345", "80",
		positivePolicyViolationIDs, negativePolicyViolationIDs)
	if isViolation == false {
		t.FailNow()
	}
}

func TestNegativePortIsPluginWithPortPolicyViolation(t *testing.T) {
	positivePolicyViolationIDs := []string{"12345|^|70"}
	negativePolicyViolationIDs := []string{"12345|^|70"}
	isViolation := IsPluginWithPortPolicyViolation("12345", "80",
		positivePolicyViolationIDs, negativePolicyViolationIDs)
	if isViolation == true {
		t.FailNow()
	}
}

func TestNegativePluginIDIsPluginWithPortPolicyViolation(t *testing.T) {
	positivePolicyViolationIDs := []string{"54321|^|80"}
	negativePolicyViolationIDs := []string{"12345|^|70"}
	isViolation := IsPluginWithPortPolicyViolation("12345", "80",
		positivePolicyViolationIDs, negativePolicyViolationIDs)
	if isViolation == true {
		t.FailNow()
	}
}

func TestNegativePortAndPluginIsPluginWithPortPolicyViolation(t *testing.T) {
	positivePolicyViolationIDs := []string{"54321|^|70"}
	negativePolicyViolationIDs := []string{"12345|^|70"}
	isViolation := IsPluginWithPortPolicyViolation("12345", "80",
		positivePolicyViolationIDs, negativePolicyViolationIDs)
	if isViolation == true {
		t.FailNow()
	}
}

func TestNegativeExplicitlyFalseIsPluginWithPortPolicyViolation(t *testing.T) {
	positivePolicyViolationIDs := []string{"12345|^|80"}
	negativePolicyViolationIDs := []string{"12345|^|80"}
	isViolation := IsPluginWithPortPolicyViolation("12345", "80",
		positivePolicyViolationIDs, negativePolicyViolationIDs)
	if isViolation == true {
		t.FailNow()
	}
}
