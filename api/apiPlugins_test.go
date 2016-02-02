package nessusAPI

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPluginFamilies(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"families":[{"count":11224,"name":"AIX Local Security Checks","id":51},{"count":651,"name":"Amazon Linux Local Security Checks","id":50},{"count":104,"name":"Backdoors","id":2},{"count":2113,"name":"CentOS Local Security Checks","id":49},{"count":3394,"name":"CGI abuses","id":3},{"count":615,"name":"CGI abuses : XSS","id":7},{"count":665,"name":"CISCO","id":24},{"count":422,"name":"Databases","id":23},{"count":3819,"name":"Debian Local Security Checks","id":42},{"count":104,"name":"Default Unix Accounts","id":40},{"count":107,"name":"Denial of Service","id":10},{"count":139,"name":"DNS","id":18},{"count":279,"name":"F5 Networks Local Security Checks","id":48},{"count":8914,"name":"Fedora Local Security Checks","id":47},{"count":164,"name":"Firewalls","id":5},{"count":3063,"name":"FreeBSD Local Security Checks","id":46},{"count":246,"name":"FTP","id":14},{"count":278,"name":"Gain a shell remotely","id":9},{"count":211,"name":"General","id":16},{"count":2153,"name":"Gentoo Local Security Checks","id":45},{"count":1984,"name":"HP-UX Local Security Checks","id":44},{"count":16,"name":"Huawei Local Security Checks","id":43},{"count":134,"name":"Junos Local Security Checks","id":41},{"count":871,"name":"MacOS X Local Security Checks","id":32},{"count":3139,"name":"Mandriva Local Security Checks","id":39},{"count":1126,"name":"Misc.","id":1},{"count":52,"name":"Mobile Devices","id":19},{"count":14,"name":"Netware","id":38},{"count":2176,"name":"Oracle Linux Local Security Checks","id":37},{"count":216,"name":"OracleVM Local Security Checks","id":36},{"count":24,"name":"Palo Alto Local Security Checks","id":35},{"count":76,"name":"Peer-To-Peer File Sharing","id":13},{"count":43,"name":"Policy Compliance","id":22},{"count":3789,"name":"Red Hat Local Security Checks","id":34},{"count":36,"name":"RPC","id":11},{"count":251,"name":"SCADA","id":33},{"count":2001,"name":"Scientific Linux Local Security Checks","id":31},{"count":413,"name":"Service detection","id":8},{"count":75,"name":"Settings","id":15},{"count":819,"name":"Slackware Local Security Checks","id":30},{"count":135,"name":"SMTP problems","id":12},{"count":33,"name":"SNMP","id":27},{"count":3849,"name":"Solaris Local Security Checks","id":26},{"count":8265,"name":"SuSE Local Security Checks","id":21},{"count":3141,"name":"Ubuntu Local Security Checks","id":25},{"count":98,"name":"VMware ESX Local Security Checks","id":20},{"count":935,"name":"Web Servers","id":4},{"count":3361,"name":"Windows","id":6},{"count":1100,"name":"Windows : Microsoft Bulletins","id":29},{"count":28,"name":"Windows : User management","id":28}]}`
		fmt.Fprintln(w, response)
	}))
	defer testServer.Close()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{Transport: transport}

	port := strings.Split(testServer.URL, ":")[2]

	client := &Client{
		username: "testU",
		password: "testP",
		ip:       "127.0.0.1",
		port:     port,
	}

	client, err := client.CreateSession(httpClient)
	if err != nil {
		t.FailNow()
	}

	pluginFamilies, err := client.PluginFamilies(httpClient)
	if err != nil || pluginFamilies.Families[0].Count != 11224 {
		t.FailNow()
	}
}

func TestPluginFamilyDetails(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"name":"AIX Local Security Checks","id":51,"plugins":[{"id":22372,"name":"AIX 5.1 : IY19744"},{"id":22373,"name":"AIX 5.1 : IY20486"}]}`
		fmt.Fprintln(w, response)
	}))
	defer testServer.Close()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{Transport: transport}

	port := strings.Split(testServer.URL, ":")[2]

	client := &Client{
		username: "testU",
		password: "testP",
		ip:       "127.0.0.1",
		port:     port,
	}

	client, err := client.CreateSession(httpClient)
	if err != nil {
		t.FailNow()
	}

	pluginFamilyDetails, err := client.PluginFamilyDetails(httpClient, 51)
	if err != nil || pluginFamilyDetails.Name != "AIX Local Security Checks" {
		t.FailNow()
	}
}

func TestPluginDetails(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"attributes":[{"attribute_value":"joomla_object_injection.nasl","attribute_name":"fname"},{"attribute_value":"Joomla! User-Agent Object Injection RCE","attribute_name":"plugin_name"},{"attribute_value":"$Revision: 1.1 $","attribute_name":"script_version"},{"attribute_value":"2015/12/12","attribute_name":"vuln_publication_date"},{"attribute_value":"cpe:/a:joomla:joomla%21","attribute_name":"cpe"},{"attribute_value":"Upgrade to Joomla! version 3.4.6 or later.","attribute_name":"solution"},{"attribute_value":"High","attribute_name":"risk_factor"},{"attribute_value":"The Joomla! application running on the remote web server is affected\nby a remote code execution vulnerability due to improper sanitization\nof the User-Agent header field when saving session values. A remote\nattacker can exploit this, via a serialized PHP object, to execute\narbitrary PHP code.","attribute_name":"description"},{"attribute_value":"2016/01/29","attribute_name":"plugin_publication_date"},{"attribute_value":"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P","attribute_name":"cvss_vector"},{"attribute_value":"remote","attribute_name":"plugin_type"},{"attribute_value":"The remote web server is running a PHP application that is affected by\na remote code execution vulnerability.","attribute_name":"synopsis"},{"attribute_value":"2015/12/14","attribute_name":"patch_publication_date"},{"attribute_value":"http://www.nessus.org/u?bec8944e","attribute_name":"see_also"},{"attribute_value":"2016/01/29","attribute_name":"plugin_modification_date"},{"attribute_value":"7.5","attribute_name":"cvss_base_score"},{"attribute_value":"CVE-2015-8562","attribute_name":"cve"},{"attribute_value":"79195","attribute_name":"bid"},{"attribute_value":"OSVDB:131679","attribute_name":"xref"},{"attribute_value":"131679","attribute_name":"osvdb"},{"attribute_value":"EDB-ID:38977","attribute_name":"xref"},{"attribute_value":"38977","attribute_name":"edb-id"},{"attribute_value":"EDB-ID:39033","attribute_name":"xref"},{"attribute_value":"39033","attribute_name":"edb-id"},{"attribute_value":"CWE:20","attribute_name":"xref"},{"attribute_value":"20","attribute_name":"cwe"}],"family_name":"CGI abuses","name":"Joomla! User-Agent Object Injection RCE","id":88489}`
		fmt.Fprintln(w, response)
	}))
	defer testServer.Close()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{Transport: transport}

	port := strings.Split(testServer.URL, ":")[2]

	client := &Client{
		username: "testU",
		password: "testP",
		ip:       "127.0.0.1",
		port:     port,
	}

	client, err := client.CreateSession(httpClient)
	if err != nil {
		t.FailNow()
	}

	pluginFamilyDetails, err := client.PluginDetails(httpClient, 88489)
	if err != nil || pluginFamilyDetails.Name != "Joomla! User-Agent Object Injection RCE" {
		t.FailNow()
	}
}
