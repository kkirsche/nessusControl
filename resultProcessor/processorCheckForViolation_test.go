package nessusProcessor

import (
	"testing"
)

var (
	nessusResultRow = &Nessus6ResultRow{
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

	positiveAnyMatchCriteria = &MatchCriteria{
		PluginID:                         71783,
		ExternallyAccessible:             true,
		Ports:                            []int{514, 123},
		DescriptionRegexps:               []string{"(The|This|That) version of ntpd", "This better not match"},
		OrganizationIDs:                  []int{5, 3, 1},
		RegionIDs:                        []int{6, 4, 2},
		IgnoreViolationWithCriteriaMatch: false,
		CountIf: "any",
	}

	positiveAllMatchCriteria = &MatchCriteria{
		PluginID:                         71783,
		ExternallyAccessible:             true,
		Ports:                            []int{514, 123},
		DescriptionRegexps:               []string{"(The|This|That) version of ntpd", "This better not match"},
		OrganizationIDs:                  []int{5, 3, 1},
		RegionIDs:                        []int{6, 4, 2},
		IgnoreViolationWithCriteriaMatch: false,
		CountIf: "all",
	}

	positiveIgnoredAnyMatchCriteria = &MatchCriteria{
		PluginID:                         71783,
		ExternallyAccessible:             true,
		Ports:                            []int{514, 123},
		DescriptionRegexps:               []string{"(The|This|That) version of ntpd", "This better not match"},
		OrganizationIDs:                  []int{5, 3, 1},
		RegionIDs:                        []int{6, 4, 2},
		IgnoreViolationWithCriteriaMatch: true,
		CountIf: "any",
	}

	negativeAnyMatchCriteria = &MatchCriteria{
		PluginID:                         1234,
		ExternallyAccessible:             false,
		Ports:                            []int{1},
		DescriptionRegexps:               []string{"This is a lot of structs?", "This better not match"},
		OrganizationIDs:                  []int{6, 4, 2},
		RegionIDs:                        []int{5, 3, 1},
		IgnoreViolationWithCriteriaMatch: false,
		CountIf: "any",
	}

	negativeAllMatchCriteria = &MatchCriteria{
		PluginID:                         1234,
		ExternallyAccessible:             false,
		Ports:                            []int{1},
		DescriptionRegexps:               []string{"This is a lot of structs?", "This better not match"},
		OrganizationIDs:                  []int{6, 4, 2},
		RegionIDs:                        []int{5, 3, 1},
		IgnoreViolationWithCriteriaMatch: false,
		CountIf: "all",
	}

	negativeIgnoredAnyMatchCriteria = &MatchCriteria{
		PluginID:                         1234,
		ExternallyAccessible:             false,
		Ports:                            []int{1},
		DescriptionRegexps:               []string{"This is a lot of structs?", "This better not match"},
		OrganizationIDs:                  []int{6, 4, 2},
		RegionIDs:                        []int{5, 3, 1},
		IgnoreViolationWithCriteriaMatch: true,
		CountIf: "any",
	}
)

func TestPositiveAnyMatchCheckForViolation(t *testing.T) {
	violation := positiveAnyMatchCriteria.CheckForViolation(nessusResultRow)

	if !violation {
		t.FailNow()
	}
}

func TestNegativeAnyMatchCheckForViolation(t *testing.T) {
	violation := negativeAnyMatchCriteria.CheckForViolation(nessusResultRow)

	if violation {
		t.FailNow()
	}
}

func TestPositiveAllMatchCheckForViolation(t *testing.T) {
	violation := positiveAllMatchCriteria.CheckForViolation(nessusResultRow)

	if !violation {
		t.FailNow()
	}
}

func TestNegativeAllMatchCheckForViolation(t *testing.T) {
	violation := negativeAllMatchCriteria.CheckForViolation(nessusResultRow)

	if violation {
		t.FailNow()
	}
}

func TestPositiveIgnoredAnyMatchCheckForViolation(t *testing.T) {
	violation := positiveIgnoredAnyMatchCriteria.CheckForViolation(nessusResultRow)

	if violation {
		t.FailNow()
	}
}

func TestNegativeIgnoredAnyMatchCheckForViolation(t *testing.T) {
	violation := negativeIgnoredAnyMatchCriteria.CheckForViolation(nessusResultRow)

	if violation {
		t.FailNow()
	}
}
