package nessusResultProcessor

import (
	"testing"
)

func TestPositiveIsPluginPolicyViolation(t *testing.T) {
	positivePluginIDs := []string{"12345"}
	negativePluginIDs := []string{}
	isViolation := IsPluginPolicyViolation("12345", positivePluginIDs, negativePluginIDs)
	if isViolation == false {
		t.FailNow()
	}
}

func TestNegativePluginIDIsPluginPolicyViolation(t *testing.T) {
	positivePluginIDs := []string{}
	negativePluginIDs := []string{"12345"}
	isViolation := IsPluginPolicyViolation("12345", positivePluginIDs, negativePluginIDs)
	if isViolation == true {
		t.FailNow()
	}
}

func TestNegativeNoMatchIsPluginPolicyViolation(t *testing.T) {
	positivePluginIDs := []string{"12345"}
	negativePluginIDs := []string{}
	isViolation := IsPluginPolicyViolation("54321", positivePluginIDs, negativePluginIDs)
	if isViolation == true {
		t.FailNow()
	}
}

func TestNegativeNoMatchEitherIsPluginPolicyViolation(t *testing.T) {
	positivePluginIDs := []string{"12345"}
	negativePluginIDs := []string{"12345"}
	isViolation := IsPluginPolicyViolation("54321", positivePluginIDs, negativePluginIDs)
	if isViolation == true {
		t.FailNow()
	}
}
