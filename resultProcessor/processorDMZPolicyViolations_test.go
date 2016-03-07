package nessusResultProcessor

import (
	"testing"
)

func TestPositiveIsPluginDMZPolicyViolation(t *testing.T) {
	isInDMZ := true
	positivePolicyViolationIDs := []string{"12345"}
	isViolation := IsPluginDMZPolicyViolation("12345", positivePolicyViolationIDs, isInDMZ)
	if isViolation == false {
		t.FailNow()
	}
}

func TestNegativePluginIDIsPluginDMZPolicyViolation(t *testing.T) {
	isInDMZ := true
	positivePolicyViolationIDs := []string{"12345"}
	isViolation := IsPluginDMZPolicyViolation("54321", positivePolicyViolationIDs, isInDMZ)
	if isViolation == true {
		t.FailNow()
	}
}

func TestNegativeInDMZIsPluginDMZPolicyViolation(t *testing.T) {
	isInDMZ := false
	positivePolicyViolationIDs := []string{"12345"}
	isViolation := IsPluginDMZPolicyViolation("12345", positivePolicyViolationIDs, isInDMZ)
	if isViolation == true {
		t.FailNow()
	}
}
