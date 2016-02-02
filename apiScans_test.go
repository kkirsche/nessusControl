package nessus

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScanDetails(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"comphosts":[],"hosts":[{"totalchecksconsidered":2506,"numchecksconsidered":2506,"scanprogresstotal":2506,"scanprogresscurrent":2506,"host_index":0,"score":22300,"severitycount":{"item":[{"count":100,"severitylevel":0},{"count":0,"severitylevel":1},{"count":2,"severitylevel":2},{"count":2,"severitylevel":3},{"count":2,"severitylevel":4}]},"progress":"2506-2506/76866-76866","critical":2,"high":2,"medium":2,"low":0,"info":100,"severity":106,"host_id":2,"hostname":"localhost"}],"notes":null,"remediations":{"remediations":[{"remediation":"Google Chrome < 48.0.2564.82 Multiple Vulnerabilities (Mac OS X): Upgrade to Google Chrome version 48.0.2564.82 or later.","hosts":1,"value":"7973a2bf857b90cfd8ffdc7968689ac9","vulns":9}],"num_hosts":1,"num_cves":24,"num_impacted_hosts":1,"num_remediated_cves":9},"vulnerabilities":[{"count":1,"plugin_name":"Wireshark Installed (Mac OS X)","vuln_index":127,"severity":0,"plugin_id":84503,"severity_index":0,"plugin_family":"MacOS X Local Security Checks"},{"count":1,"plugin_name":"VNC Software Detection","vuln_index":126,"severity":0,"plugin_id":10342,"severity_index":1,"plugin_family":"Service detection"},{"count":1,"plugin_name":"VNC Server Unencrypted Communication Detection","vuln_index":125,"severity":0,"plugin_id":65792,"severity_index":2,"plugin_family":"Service detection"},{"count":1,"plugin_name":"VNC Server Security Type Detection","vuln_index":124,"severity":0,"plugin_id":19288,"severity_index":3,"plugin_family":"Service detection"},{"count":1,"plugin_name":"VMware OVF Tool Detection (Mac OS X)","vuln_index":123,"severity":0,"plugin_id":77330,"severity_index":4,"plugin_family":"MacOS X Local Security Checks"},{"count":1,"plugin_name":"VMware Fusion Version Detection (Mac OS X)","vuln_index":122,"severity":0,"plugin_id":50828,"severity_index":5,"plugin_family":"MacOS X Local Security Checks"},{"count":1,"plugin_name":"Time of Last System Startup","vuln_index":121,"severity":0,"plugin_id":56468,"severity_index":6,"plugin_family":"General"},{"count":1,"plugin_name":"SSL Cipher Suites Supported","vuln_index":120,"severity":0,"plugin_id":21643,"severity_index":7,"plugin_family":"General"},{"count":1,"plugin_name":"SSL Cipher Block Chaining Cipher Suites Supported","vuln_index":119,"severity":0,"plugin_id":70544,"severity_index":8,"plugin_family":"General"},{"count":1,"plugin_name":"SSL Certificate Information","vuln_index":117,"severity":0,"plugin_id":10863,"severity_index":9,"plugin_family":"General"},{"count":1,"plugin_name":"SSL Certificate commonName Mismatch","vuln_index":116,"severity":0,"plugin_id":45410,"severity_index":10,"plugin_family":"General"},{"count":1,"plugin_name":"SSL / TLS Versions Supported","vuln_index":114,"severity":0,"plugin_id":56984,"severity_index":11,"plugin_family":"General"},{"count":1,"plugin_name":"SSH Server Type and Version Information","vuln_index":113,"severity":0,"plugin_id":10267,"severity_index":12,"plugin_family":"Service detection"},{"count":1,"plugin_name":"SSH Protocol Versions Supported","vuln_index":112,"severity":0,"plugin_id":10881,"severity_index":13,"plugin_family":"General"},{"count":1,"plugin_name":"SSH Algorithms and Languages Supported","vuln_index":111,"severity":0,"plugin_id":70657,"severity_index":14,"plugin_family":"Misc."},{"count":1,"plugin_name":"Software Enumeration (SSH)","vuln_index":110,"severity":0,"plugin_id":22869,"severity_index":15,"plugin_family":"General"},{"count":1,"plugin_name":"Skype for Mac Installed (credentialed check)","vuln_index":109,"severity":0,"plugin_id":53843,"severity_index":16,"plugin_family":"MacOS X Local Security Checks"},{"count":1,"plugin_name":"Service Detection (HELP Request)","vuln_index":108,"severity":0,"plugin_id":11153,"severity_index":17,"plugin_family":"Service detection"},{"count":1,"plugin_name":"Patch Report","vuln_index":106,"severity":0,"plugin_id":66334,"severity_index":18,"plugin_family":"General"},{"count":1,"plugin_name":"OS Identification","vuln_index":105,"severity":0,"plugin_id":11936,"severity_index":19,"plugin_family":"General"},{"count":1,"plugin_name":"Oracle VM VirtualBox Installed (Mac OS X)","vuln_index":104,"severity":0,"plugin_id":84240,"severity_index":20,"plugin_family":"MacOS X Local Security Checks"},{"count":1,"plugin_name":"OpenSSL Detection","vuln_index":103,"severity":0,"plugin_id":50845,"severity_index":21,"plugin_family":"Service detection"},{"count":1,"plugin_name":"Network Time Protocol (NTP) Server Detection","vuln_index":102,"severity":0,"plugin_id":10884,"severity_index":22,"plugin_family":"Service detection"},{"count":1,"plugin_name":"Netstat Connection Information","vuln_index":100,"severity":0,"plugin_id":64582,"severity_index":23,"plugin_family":"General"},{"count":1,"plugin_name":"Netstat Active Connections","vuln_index":99,"severity":0,"plugin_id":58651,"severity_index":24,"plugin_family":"Misc."},{"count":1,"plugin_name":"Nessus Server Detection","vuln_index":98,"severity":0,"plugin_id":10147,"severity_index":25,"plugin_family":"Service detection"},{"count":1,"plugin_name":"Nessus Scan Information","vuln_index":97,"severity":0,"plugin_id":19506,"severity_index":26,"plugin_family":"Settings"},{"count":1,"plugin_name":"MySQL Server Detection","vuln_index":96,"severity":0,"plugin_id":10719,"severity_index":27,"plugin_family":"Databases"},{"count":1,"plugin_name":"Microsoft Silverlight Installed (Mac OS X)","vuln_index":95,"severity":0,"plugin_id":58091,"severity_index":28,"plugin_family":"MacOS X Local Security Checks"},{"count":1,"plugin_name":"Mac OS X DNS Server Enumeration","vuln_index":93,"severity":0,"plugin_id":58180,"severity_index":29,"plugin_family":"MacOS X Local Security Checks"},{"count":1,"plugin_name":"Mac OS X Admin Group User List","vuln_index":92,"severity":0,"plugin_id":60019,"severity_index":30,"plugin_family":"MacOS X Local Security Checks"},{"count":1,"plugin_name":"List Installed Mac OS X Software","vuln_index":91,"severity":0,"plugin_id":83991,"severity_index":31,"plugin_family":"MacOS X Local Security Checks"},{"count":1,"plugin_name":"Kerberos Information Disclosure","vuln_index":90,"severity":0,"plugin_id":43829,"severity_index":32,"plugin_family":"Misc."},{"count":1,"plugin_name":"iTunes Version Detection (Mac OS X)","vuln_index":89,"severity":0,"plugin_id":25997,"severity_index":33,"plugin_family":"MacOS X Local Security Checks"},{"count":1,"plugin_name":"HTTP Server Type and Version","vuln_index":87,"severity":0,"plugin_id":10107,"severity_index":34,"plugin_family":"Web Servers"},{"count":1,"plugin_name":"HSTS Missing From HTTPS Server","vuln_index":86,"severity":0,"plugin_id":84502,"severity_index":35,"plugin_family":"Web Servers"},{"count":1,"plugin_name":"Host Fully Qualified Domain Name (FQDN) Resolution","vuln_index":85,"severity":0,"plugin_id":12053,"severity_index":36,"plugin_family":"General"},{"count":1,"plugin_name":"Google Chrome Installed (Mac OS X)","vuln_index":84,"severity":0,"plugin_id":70890,"severity_index":37,"plugin_family":"MacOS X Local Security Checks"},{"count":1,"plugin_name":"Firewall Rule Enumeration","vuln_index":82,"severity":0,"plugin_id":56310,"severity_index":38,"plugin_family":"Firewalls"},{"count":1,"plugin_name":"Firefox Installed (Mac OS X)","vuln_index":81,"severity":0,"plugin_id":55417,"severity_index":39,"plugin_family":"MacOS X Local Security Checks"},{"count":1,"plugin_name":"Ethernet Card Manufacturer Detection","vuln_index":79,"severity":0,"plugin_id":35716,"severity_index":40,"plugin_family":"Misc."},{"count":1,"plugin_name":"Enumerate MAC Addresses via SSH","vuln_index":78,"severity":0,"plugin_id":33276,"severity_index":41,"plugin_family":"General"},{"count":1,"plugin_name":"Enumerate IPv6 Interfaces via SSH","vuln_index":77,"severity":0,"plugin_id":25202,"severity_index":42,"plugin_family":"General"},{"count":1,"plugin_name":"Enumerate IPv4 Interfaces via SSH","vuln_index":76,"severity":0,"plugin_id":25203,"severity_index":43,"plugin_family":"General"},{"count":1,"plugin_name":"Device Type","vuln_index":75,"severity":0,"plugin_id":54615,"severity_index":44,"plugin_family":"General"},{"count":1,"plugin_name":"Device Hostname","vuln_index":74,"severity":0,"plugin_id":55472,"severity_index":45,"plugin_family":"General"},{"count":1,"plugin_name":"Common Platform Enumeration (CPE)","vuln_index":73,"severity":0,"plugin_id":45590,"severity_index":46,"plugin_family":"General"},{"count":1,"plugin_name":"Backported Security Patch Detection (SSH)","vuln_index":72,"severity":0,"plugin_id":39520,"severity_index":47,"plugin_family":"General"},{"count":1,"plugin_name":"Authenticated Check : OS Name and Installed Package Enumeration","vuln_index":71,"severity":0,"plugin_id":12634,"severity_index":48,"plugin_family":"Settings"},{"count":1,"plugin_name":"Apple Xcode IDE Detection (Mac OS X)","vuln_index":70,"severity":0,"plugin_id":61412,"severity_index":49,"plugin_family":"MacOS X Local Security Checks"},{"count":1,"plugin_name":"Adobe Photoshop for Mac Installed","vuln_index":68,"severity":0,"plugin_id":62220,"severity_index":50,"plugin_family":"MacOS X Local Security Checks"},{"count":1,"plugin_name":"Adobe Flash Player for Mac Installed","vuln_index":67,"severity":0,"plugin_id":53914,"severity_index":51,"plugin_family":"MacOS X Local Security Checks"},{"count":1,"plugin_name":"Adobe AIR for Mac Installed","vuln_index":66,"severity":0,"plugin_id":56960,"severity_index":52,"plugin_family":"MacOS X Local Security Checks"},{"count":1,"plugin_name":"Adobe Acrobat Installed (Mac OS X)","vuln_index":64,"severity":0,"plugin_id":70349,"severity_index":53,"plugin_family":"MacOS X Local Security Checks"},{"count":4,"plugin_name":"HyperText Transfer Protocol (HTTP) Information","vuln_index":88,"severity":0,"plugin_id":24260,"severity_index":54,"plugin_family":"Web Servers"},{"count":6,"plugin_name":"Microsoft Office Installed (Mac OS X)","vuln_index":94,"severity":0,"plugin_id":86383,"severity_index":55,"plugin_family":"MacOS X Local Security Checks"},{"count":7,"plugin_name":"Service Detection","vuln_index":107,"severity":0,"plugin_id":22964,"severity_index":56,"plugin_family":"Service detection"},{"count":29,"plugin_name":"netstat portscanner (SSH)","vuln_index":101,"severity":0,"plugin_id":14272,"severity_index":57,"plugin_family":"Port scanners"},{"count":1,"plugin_name":"SSL Certificate Signed Using Weak Hashing Algorithm","vuln_index":118,"severity":2,"plugin_id":35291,"severity_index":58,"plugin_family":"General"},{"count":1,"plugin_name":"SSL Certificate Cannot Be Trusted","vuln_index":115,"severity":2,"plugin_id":51192,"severity_index":59,"plugin_family":"General"},{"count":1,"plugin_name":"Google Chrome < 48.0.2564.82 Multiple Vulnerabilities (Mac OS X)","vuln_index":83,"severity":3,"plugin_id":88089,"severity_index":60,"plugin_family":"MacOS X Local Security Checks"},{"count":1,"plugin_name":"Firefox < 44 Multiple Vulnerabilities (Mac OS X)","vuln_index":80,"severity":3,"plugin_id":88459,"severity_index":61,"plugin_family":"MacOS X Local Security Checks"},{"count":1,"plugin_name":"Adobe Photoshop for Mac Unsupported Version Detection","vuln_index":69,"severity":4,"plugin_id":62221,"severity_index":62,"plugin_family":"MacOS X Local Security Checks"},{"count":1,"plugin_name":"Adobe Acrobat Unsupported Version Detection (Mac OS X)","vuln_index":65,"severity":4,"plugin_id":70350,"severity_index":63,"plugin_family":"MacOS X Local Security Checks"}],"filters":[{"operators":["eq","neq","match","nmatch"],"control":{"readable_regex":"NUMBER","type":"entry","regex":"^[0-9]+$"},"name":"bid","readable_name":"Bugtraq ID"},{"operators":["eq","neq","match","nmatch"],"control":{"readable_regex":"Cert VU reference (ie: 10031)","type":"entry","regex":"^[0-9]+$"},"name":"cert","readable_name":"CERT Vulnerability ID"},{"operators":["eq","neq","match","nmatch"],"control":{"readable_regex":"TEXT","type":"entry","regex":".*"},"name":"cpe","readable_name":"CPE"},{"operators":["eq","neq","match","nmatch"],"control":{"readable_regex":"CVE-YYYY-ID (ie: CVE-2011-0018)","type":"entry","regex":"^(CVE|CAN)-(1999|20[01][0-9])-[0-9]{4,}$"},"name":"cve","readable_name":"CVE"},{"operators":["lt","gt","eq","neq","match","nmatch"],"control":{"readable_regex":"7.5","type":"entry","regex":"^[0-9]+(\\.[0-9]+)?$"},"name":"cvss_base_score","readable_name":"CVSS Base Score"},{"operators":["lt","gt","eq","neq","match","nmatch"],"control":{"readable_regex":"4.2","type":"entry","regex":"^[0-9]+(\\.[0-9]+)$"},"name":"cvss_temporal_score","readable_name":"CVSS Temporal Score"},{"operators":["eq","neq","match","nmatch"],"control":{"readable_regex":"TEXT","type":"entry","regex":".*"},"name":"cvss_temporal_vector","readable_name":"CVSS Temporal Vector"},{"operators":["eq","neq","match","nmatch"],"control":{"readable_regex":"TEXT","type":"entry","regex":".*"},"name":"cvss_vector","readable_name":"CVSS Vector"},{"operators":["eq","neq","match","nmatch"],"control":{"readable_regex":"CWE reference (ie: 200)","type":"entry","regex":"^([0-9]+)$"},"name":"cwe","readable_name":"CWE"},{"operators":["eq","neq"],"control":{"type":"dropdown","list":["true","false"]},"name":"exploit_available","readable_name":"Exploit Available"},{"operators":["eq","neq"],"control":{"type":"dropdown","list":["Exploits are available","No exploit is required","No known exploits are available"]},"name":"exploitability_ease","readable_name":"Exploitability Ease"},{"operators":["eq","neq"],"control":{"type":"dropdown","list":["true","false"]},"name":"exploited_by_nessus","readable_name":"Exploited By Nessus"},{"operators":["eq","neq","match","nmatch"],"control":{"readable_regex":"TEXT","type":"entry","regex":".*"},"name":"hostname","readable_name":"Hostname"},{"operators":["eq","neq","match","nmatch"],"control":{"readable_regex":"IAVA reference (ie: 2011-A-0151)","type":"entry","regex":"^[0-9]+-[A-Za-z]-[0-9]+$"},"name":"iava","readable_name":"IAVA ID"},{"operators":["eq","neq","match","nmatch"],"control":{"readable_regex":"IAVB reference (ie: 2011-B-0151)","type":"entry","regex":"^[0-9]+-[A-Za-z]-[0-9]+$"},"name":"iavb","readable_name":"IAVB ID"},{"operators":["eq","neq","match","nmatch"],"control":{"readable_regex":"IAVM Severity (ie: IV)","type":"entry","regex":"^[ivIV]+"},"name":"stig_severity","readable_name":"IAVM Severity"},{"operators":["eq","neq","match","nmatch"],"control":{"readable_regex":"NUMBER","type":"entry","regex":"^[0-9]+$"},"name":"osvdb","readable_name":"OSVDB ID"},{"operators":["date-lt","date-gt","date-eq","date-neq","match","nmatch"],"control":{"type":"datefield"},"name":"patch_publication_date","readable_name":"Patch Publication Date"},{"operators":["match","nmatch"],"control":{"readable_regex":"TEXT","type":"entry","regex":".*"},"name":"description","readable_name":"Plugin Description"},{"operators":["eq","neq"],"control":{"type":"dropdown","list":["AIX Local Security Checks","Amazon Linux Local Security Checks","Backdoors","CGI abuses","CGI abuses : XSS","CISCO","CentOS Local Security Checks","DNS","Databases","Debian Local Security Checks","Default Unix Accounts","Denial of Service","F5 Networks Local Security Checks","FTP","Fedora Local Security Checks","Firewalls","FreeBSD Local Security Checks","Gain a shell remotely","General","Gentoo Local Security Checks","HP-UX Local Security Checks","Huawei Local Security Checks","Junos Local Security Checks","MacOS X Local Security Checks","Mandriva Local Security Checks","Misc.","Mobile Devices","Netware","Oracle Linux Local Security Checks","OracleVM Local Security Checks","Palo Alto Local Security Checks","Peer-To-Peer File Sharing","Policy Compliance","Port scanners","RPC","Red Hat Local Security Checks","SCADA","SMTP problems","SNMP","Scientific Linux Local Security Checks","Service detection","Settings","Slackware Local Security Checks","Solaris Local Security Checks","SuSE Local Security Checks","Ubuntu Local Security Checks","VMware ESX Local Security Checks","Web Servers","Windows","Windows : Microsoft Bulletins","Windows : User management"]},"name":"plugin_family","readable_name":"Plugin Family"},{"operators":["eq","neq","match","nmatch"],"control":{"readable_regex":"NUMBER","type":"entry","regex":"^[0-9, ]+$"},"name":"plugin_id","readable_name":"Plugin ID"},{"operators":["date-lt","date-gt","date-eq","date-neq","match","nmatch"],"control":{"type":"datefield"},"name":"plugin_modification_date","readable_name":"Plugin Modification Date"},{"operators":["eq","neq","match","nmatch"],"control":{"readable_regex":"TEXT","type":"entry","regex":".*"},"name":"plugin_name","readable_name":"Plugin Name"},{"operators":["eq","neq","match","nmatch"],"control":{"readable_regex":"TEXT","type":"entry","regex":".*"},"name":"plugin_output","readable_name":"Plugin Output"},{"operators":["date-lt","date-gt","date-eq","date-neq","match","nmatch"],"control":{"type":"datefield"},"name":"plugin_publication_date","readable_name":"Plugin Publication Date"},{"operators":["eq","neq"],"control":{"type":"dropdown","list":["local","remote"]},"name":"plugin_type","readable_name":"Plugin Type"},{"operators":["eq","neq","match","nmatch"],"control":{"readable_regex":"80","type":"entry","regex":"^[0-9]+$"},"name":"port","readable_name":"Port"},{"operators":["eq","neq"],"control":{"type":"dropdown","list":["tcp","udp","icmp"]},"name":"protocol","readable_name":"Protocol"},{"operators":["eq","neq"],"control":{"type":"dropdown","list":["None","Low","Medium","High","Critical"]},"name":"risk_factor","readable_name":"Risk Factor"},{"operators":["eq","neq","match","nmatch"],"control":{"readable_regex":"TEXT","type":"entry","regex":".*"},"name":"see_also","readable_name":"See Also"},{"operators":["match","nmatch"],"control":{"readable_regex":"TEXT","type":"entry","regex":".*"},"name":"solution","readable_name":"Solution"},{"operators":["match","nmatch"],"control":{"readable_regex":"TEXT","type":"entry","regex":".*"},"name":"synopsis","readable_name":"Synopsis"},{"operators":["eq","neq"],"control":{"type":"dropdown","list":["true","false"]},"name":"unsupported_by_vendor","readable_name":"Unsupported By Vendor"},{"operators":["date-lt","date-gt","date-eq","date-neq","match","nmatch"],"control":{"type":"datefield"},"name":"vuln_publication_date","readable_name":"Vulnerability Publication Date"}],"history":[{"alt_targets_used":false,"scheduler":0,"status":"completed","type":"local","uuid":"37d6e0cc-5d19-60fb-25b7-0dcdd546451189d8813f3b060368","last_modification_date":1454369366,"creation_date":1454369152,"owner_id":3,"history_id":38},{"alt_targets_used":false,"scheduler":0,"status":"completed","type":"local","uuid":"3390954f-63b5-1604-78b9-94237d20c69fd45c9012e5d18f69","last_modification_date":1454371736,"creation_date":1454371611,"owner_id":3,"history_id":39}],"compliance":[],"info":{"acls":[{"permissions":0,"owner":null,"display_name":null,"name":null,"id":null,"type":"default"},{"permissions":128,"owner":1,"display_name":"testU","name":"testU","id":3,"type":"user"}],"edit_allowed":true,"alt_targets_used":null,"status":"completed","scanner_start":1454371611,"policy":"Advanced Scan","pci-can-upload":false,"hasaudittrail":true,"scan_start":1454371611,"user_permissions":128,"folder_id":24,"no_target":null,"targets":"localhost","control":true,"timestamp":1454371736,"object_id":36,"scanner_name":"Local Scanner","haskb":true,"uuid":"3390954f-63b5-1604-78b9-94237d20c69fd45c9012e5d18f69","scanner_end":1454371732,"hostcount":1,"scan_end":1454371736,"scan_type":"local","name":"test"}}`
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

	scanDetails, err := client.ScanDetails(httpClient, 36)
	if err != nil || scanDetails.Info.Control != true {
		fmt.Println(err)
		t.FailNow()
	}
}

func TestExportScan(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"file": 1}`
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

	exportStatus, err := client.ExportScan(httpClient, 36, `{"format":"csv"}`)
	if err != nil || exportStatus.File != 1 {
		t.FailNow()
	}
}

func TestScanExportStatus(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"status": "ready"}`
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

	exportStatus, err := client.ScanExportStatus(httpClient, 36, 1)
	if err != nil || exportStatus.Status != "ready" {
		t.FailNow()
	}
}

func TestLaunchScans(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"scan_uuid": "3390954f-63b5-1604-78b9-94237d20c69fd45c9012e5d18f69"}`
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

	launchedScan, err := client.LaunchScan(httpClient, 36)
	if err != nil || launchedScan.ScanUUID != "3390954f-63b5-1604-78b9-94237d20c69fd45c9012e5d18f69" {
		t.FailNow()
	}
}

func TestListScans(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"folders":[{"unread_count":null,"custom":0,"default_tag":0,"type":"trash","name":"Trash","id":23},{"unread_count":null,"custom":0,"default_tag":1,"type":"main","name":"My Scans","id":24}],"scans":[{"folder_id":24,"type":null,"read":true,"last_modification_date":0,"creation_date":0,"status":"empty","uuid":null,"shared":false,"user_permissions":128,"owner":"testU","timezone":null,"rrules":null,"starttime":null,"enabled":false,"control":true,"name":"test","id":36}],"timestamp":1454368895}`
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

	scanList, err := client.ListScans(httpClient)
	if err != nil || scanList.Scans[0].Name != "test" {
		t.FailNow()
	}
}

func TestPauseScan(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"token": "ExampleToken"}` // This is for CreateSession, this method alone returns nothing
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

	scanPaused, err := client.PauseScan(httpClient, 36)
	if err != nil || scanPaused != true {
		t.FailNow()
	}
}

func TestToggleScanResultReadStatus(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"token": "ExampleToken"}` // This is for CreateSession, this method alone returns nothing
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

	toggledScanReadStatus, err := client.ToggleScanResultReadStatus(httpClient, 36, true)
	if err != nil || toggledScanReadStatus != true {
		t.FailNow()
	}
}

func TestResumeScan(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"token": "ExampleToken"}` // This is for CreateSession, this method alone returns nothing
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

	scanResumed, err := client.ResumeScan(httpClient, 36)
	if err != nil || scanResumed != true {
		t.FailNow()
	}
}

func TestToggleScheduledScan(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"enabled": true,"control": true,"rrules": "Example","starttime": "Started Time","timezone": "Timezone"}`
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

	toggledScan, err := client.ToggleScheduledScan(httpClient, 36, true)
	if err != nil || toggledScan.Enabled != true {
		t.FailNow()
	}
}

func TestStopScan(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"token": "ExampleToken"}` // This is for CreateSession, this method alone returns nothing
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

	scanStopped, err := client.StopScan(httpClient, 36)
	if err != nil || scanStopped != true {
		t.FailNow()
	}
}

func TestListScanTimezones(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"timezones":[{"name":"Africa/Abidjan","value":"Africa/Abidjan"},{"name":"Africa/Accra","value":"Africa/Accra"}]}`
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

	scanTimezones, err := client.ListScanTimezones(httpClient)
	if err != nil || scanTimezones.Timezones[0].Name != "Africa/Abidjan" {
		t.FailNow()
	}
}
