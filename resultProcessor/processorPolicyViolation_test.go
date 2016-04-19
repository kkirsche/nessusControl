package nessusProcessor

import (
	"testing"
)

var (
	nessusPolicyViolationResultRow = &Nessus6ResultRow{
		PluginID:       71783,
		CVE:            "CVE-2013-5211",
		CVSS:           5,
		Risk:           "Medium",
		Host:           "localhost",
		Protocol:       "udp",
		Port:           123,
		Name:           "NTP monlist Command Enabled",
		Synopsis:       "The remote network time service could be used for network reconnaissance or abused in a distributed denial of service attack.",
		Description:    "The version of ntpd on the remote host has the 'monlist' command enabled. This command returns a list of recent hosts that have connected to the service. As such, it can be used for network reconnaissance or, along with a spoofed source IP, a distributed denial of service attack.",
		Solution:       "If using NTP from the Network Time Protocol Project, either upgrade to\nNTP 4.2.7-p26 or later, or add 'disable monitor' to the 'ntp.conf'\nconfiguration file and restart the service. Otherwise, contact the\nvendor.\n\nOtherwise, limit access to the affected service to trusted hosts.",
		SeeAlso:        "https://isc.sans.edu/diary/NTP+reflection+attack/17300\nhttp://bugs.ntp.org/show_bug.cgi?id=1532\nhttp://kb.juniper.net/InfoCenter/index?page=content&id=JSA10613",
		PluginOutput:   "",
		OrganizationID: 1,
		RegionID:       2,
	}

	positiveAnyPolicyViolationMatchCriteria = &PolicyViolationMatchCriteria{
		PluginID:                         71783,
		ExternallyAccessible:             true,
		Ports:                            []int{514, 123},
		DescriptionRegexp:                []string{"(The|This|That) version of ntpd", "This better not match"},
		OrganizationIDs:                  []int{5, 3, 1},
		RegionIDs:                        []int{6, 4, 2},
		IgnoreViolationWithCriteriaMatch: false,
		CountIf: "any",
	}

	positiveAllPolicyViolationMatchCriteria = &PolicyViolationMatchCriteria{
		PluginID:                         71783,
		ExternallyAccessible:             true,
		Ports:                            []int{514, 123},
		DescriptionRegexp:                []string{"(The|This|That) version of ntpd", "This better not match"},
		OrganizationIDs:                  []int{5, 3, 1},
		RegionIDs:                        []int{6, 4, 2},
		IgnoreViolationWithCriteriaMatch: false,
		CountIf: "all",
	}

	positiveIgnoredAnyPolicyViolationMatchCriteria = &PolicyViolationMatchCriteria{
		PluginID:                         71783,
		ExternallyAccessible:             true,
		Ports:                            []int{514, 123},
		DescriptionRegexp:                []string{"(The|This|That) version of ntpd", "This better not match"},
		OrganizationIDs:                  []int{5, 3, 1},
		RegionIDs:                        []int{6, 4, 2},
		IgnoreViolationWithCriteriaMatch: true,
		CountIf: "any",
	}

	negativeAnyPolicyViolationMatchCriteria = &PolicyViolationMatchCriteria{
		PluginID:                         1234,
		ExternallyAccessible:             false,
		Ports:                            []int{1},
		DescriptionRegexp:                []string{"This is a lot of structs?", "This better not match"},
		OrganizationIDs:                  []int{6, 4, 2},
		RegionIDs:                        []int{5, 3, 1},
		IgnoreViolationWithCriteriaMatch: false,
		CountIf: "any",
	}

	negativeAllPolicyViolationMatchCriteria = &PolicyViolationMatchCriteria{
		PluginID:                         1234,
		ExternallyAccessible:             false,
		Ports:                            []int{1},
		DescriptionRegexp:                []string{"This is a lot of structs?", "This better not match"},
		OrganizationIDs:                  []int{6, 4, 2},
		RegionIDs:                        []int{5, 3, 1},
		IgnoreViolationWithCriteriaMatch: false,
		CountIf: "all",
	}

	negativeIgnoredAnyPolicyViolationMatchCriteria = &PolicyViolationMatchCriteria{
		PluginID:                         1234,
		ExternallyAccessible:             false,
		Ports:                            []int{1},
		DescriptionRegexp:                []string{"This is a lot of structs?", "This better not match"},
		OrganizationIDs:                  []int{6, 4, 2},
		RegionIDs:                        []int{5, 3, 1},
		IgnoreViolationWithCriteriaMatch: true,
		CountIf: "any",
	}
)

func TestPositiveAnyPolicyViolationMatchCheckForViolation(t *testing.T) {
	violation := positiveAnyPolicyViolationMatchCriteria.IsPolicyViolationMatch(nessusPolicyViolationResultRow)

	if !violation {
		t.FailNow()
	}
}

func TestNegativeAnyPolicyViolationMatchCheckForViolation(t *testing.T) {
	violation := negativeAnyPolicyViolationMatchCriteria.IsPolicyViolationMatch(nessusPolicyViolationResultRow)

	if violation {
		t.FailNow()
	}
}

func TestPositiveAllPolicyViolationMatchCheckForViolation(t *testing.T) {
	violation := positiveAllPolicyViolationMatchCriteria.IsPolicyViolationMatch(nessusPolicyViolationResultRow)

	if !violation {
		t.FailNow()
	}
}

func TestNegativeAllPolicyViolationMatchCheckForViolation(t *testing.T) {
	violation := negativeAllPolicyViolationMatchCriteria.IsPolicyViolationMatch(nessusPolicyViolationResultRow)

	if violation {
		t.FailNow()
	}
}

func TestPositiveIgnoredAnyPolicyViolationMatchCheckForViolation(t *testing.T) {
	violation := positiveIgnoredAnyPolicyViolationMatchCriteria.IsPolicyViolationMatch(nessusPolicyViolationResultRow)

	if violation {
		t.FailNow()
	}
}

func TestNegativeIgnoredAnyPolicyViolationMatchCheckForViolation(t *testing.T) {
	violation := negativeIgnoredAnyPolicyViolationMatchCriteria.IsPolicyViolationMatch(nessusPolicyViolationResultRow)

	if violation {
		t.FailNow()
	}
}
