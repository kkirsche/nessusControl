package nessus

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
