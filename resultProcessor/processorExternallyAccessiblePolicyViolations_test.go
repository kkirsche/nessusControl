package nessusResultProcessor

import (
	"testing"
)

func TestPositiveIsPluginExternallyAccessiblePolicyViolation(t *testing.T) {
	isInDMZ := true
	positivePolicyViolationIDs := []string{"12345"}
	negativePolicyViolationIDs := []string{}
	isViolation := IsPluginExternallyAccessiblePolicyViolation("12345", isInDMZ,
		positivePolicyViolationIDs, negativePolicyViolationIDs)
	if isViolation == false {
		t.FailNow()
	}
}

func TestNegativePluginIDIsPluginExternallyAccessiblePolicyViolation(t *testing.T) {
	isInDMZ := true
	positivePolicyViolationIDs := []string{"12345"}
	negativePolicyViolationIDs := []string{}
	isViolation := IsPluginExternallyAccessiblePolicyViolation("54321", isInDMZ,
		positivePolicyViolationIDs, negativePolicyViolationIDs)
	if isViolation == true {
		t.FailNow()
	}
}

func TestNegativeInDMZIsPluginExternallyAccessiblePolicyViolation(t *testing.T) {
	isInDMZ := false
	positivePolicyViolationIDs := []string{"12345"}
	negativePolicyViolationIDs := []string{}
	isViolation := IsPluginExternallyAccessiblePolicyViolation("12345", isInDMZ,
		positivePolicyViolationIDs, negativePolicyViolationIDs)
	if isViolation == true {
		t.FailNow()
	}
}

func TestNegativeExplicitIsPluginExternallyAccessiblePolicyViolation(t *testing.T) {
	isInDMZ := true
	positivePolicyViolationIDs := []string{"12345"}
	negativePolicyViolationIDs := []string{"12345"}
	isViolation := IsPluginExternallyAccessiblePolicyViolation("12345", isInDMZ,
		positivePolicyViolationIDs, negativePolicyViolationIDs)
	if isViolation == true {
		t.FailNow()
	}
}
