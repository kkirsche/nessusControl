// Package nessusResultProcessor is used to process Nessus CSV result files
// with custom logic for use within a company or enterprise.
package nessusResultProcessor

import (
	"testing"
)

func TestPositiveIsPluginWithDescripRegexpPolicyViolation(t *testing.T) {
	description := "Nessus has found that a telnet server is listening on the remote port over ssl which is bad!"
	positivePluginIDs := []string{"10281|^|a telnet server is listening on the remote port over ssl"}
	negativePluginIDs := []string{}
	violation := IsPluginWithDescripRegexpPolicyViolation("10281", description, positivePluginIDs, negativePluginIDs)
	if violation != true {
		t.FailNow()
	}
}

func TestExplicitNegativeIsPluginWithDescripRegexpPolicyViolation(t *testing.T) {
	description := "Nessus has found that a telnet server is listening on the remote port over ssl which is bad!"
	positivePluginIDs := []string{"10281|^|a telnet server is listening on the remote port over ssl"}
	negativePluginIDs := []string{"10281|^|a telnet server is listening on the remote port over ssl"}
	violation := IsPluginWithDescripRegexpPolicyViolation("10281", description, positivePluginIDs, negativePluginIDs)
	if violation != false {
		t.FailNow()
	}
}

func TestNegativePluginIDIsPluginWithDescripRegexpPolicyViolation(t *testing.T) {
	description := "Nessus has found that a telnet server is listening on the remote port over ssl which is bad!"
	positivePluginIDs := []string{"10281|^|a telnet server is listening on the remote port over ssl"}
	negativePluginIDs := []string{}
	violation := IsPluginWithDescripRegexpPolicyViolation("12345", description, positivePluginIDs, negativePluginIDs)
	if violation != false {
		t.FailNow()
	}
}

func TestNegativeDescriptionIsPluginWithDescripRegexpPolicyViolation(t *testing.T) {
	description := "Nessus has found that a telnet instance which listens on the remote port over ssl which is bad!"
	positivePluginIDs := []string{"10281|^|a telnet server is listening on the remote port over ssl"}
	negativePluginIDs := []string{}
	violation := IsPluginWithDescripRegexpPolicyViolation("10281", description, positivePluginIDs, negativePluginIDs)
	if violation != false {
		t.FailNow()
	}
}
