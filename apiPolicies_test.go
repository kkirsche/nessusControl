package nessus

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCopyPolicy(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"name":"Copy of Test Policy","id":29}`
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

	copiedPolicy, err := client.CopyPolicy(httpClient, 26)
	if err != nil || copiedPolicy.Name != "Copy of Test Policy" {
		t.FailNow()
	}
}

func TestCreatePolicy(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"policy_id": 25,"policy_name": "Example"}`
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

	createdPolicy, err := client.CreatePolicy(httpClient, `{"uuid": "9C3D4239-354A-438C-92C2-67AD32C24C0B"}`)
	if err != nil || createdPolicy.PolicyID != 25 {
		t.FailNow()
	}
}

func TestDeletePolicy(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"token":"TestToken"}` // DeletePolicy returns nothing. This is for CreateSession's benefit
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

	deleted, err := client.DeletePolicy(httpClient, 25)
	if err != nil || deleted != true {
		t.FailNow()
	}
}

func TestPolicyDetails(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"plugins":{"SMTP problems":{"status":"enabled"},"Backdoors":{"status":"enabled"},"Ubuntu Local Security Checks":{"status":"enabled"},"Gentoo Local Security Checks":{"status":"enabled"},"Oracle Linux Local Security Checks":{"status":"enabled"},"RPC":{"status":"enabled"},"Gain a shell remotely":{"status":"enabled"},"Service detection":{"status":"enabled"},"DNS":{"status":"enabled"},"Mandriva Local Security Checks":{"status":"enabled"},"Junos Local Security Checks":{"status":"enabled"},"Misc.":{"status":"enabled"},"FTP":{"status":"enabled"},"Slackware Local Security Checks":{"status":"enabled"},"Default Unix Accounts":{"status":"enabled"},"AIX Local Security Checks":{"status":"enabled"},"SNMP":{"status":"enabled"},"OracleVM Local Security Checks":{"status":"enabled"},"CGI abuses":{"status":"enabled"},"Settings":{"status":"enabled"},"CISCO":{"status":"enabled"},"Firewalls":{"status":"enabled"},"Databases":{"status":"enabled"},"Debian Local Security Checks":{"status":"enabled"},"Fedora Local Security Checks":{"status":"enabled"},"Netware":{"status":"enabled"},"Huawei Local Security Checks":{"status":"enabled"},"Windows : User management":{"status":"enabled"},"VMware ESX Local Security Checks":{"status":"enabled"},"CentOS Local Security Checks":{"status":"enabled"},"Peer-To-Peer File Sharing":{"status":"enabled"},"General":{"status":"enabled"},"Policy Compliance":{"status":"enabled"},"Amazon Linux Local Security Checks":{"status":"enabled"},"Solaris Local Security Checks":{"status":"enabled"},"F5 Networks Local Security Checks":{"status":"enabled"},"Denial of Service":{"status":"enabled"},"Windows : Microsoft Bulletins":{"status":"enabled"},"SuSE Local Security Checks":{"status":"enabled"},"Palo Alto Local Security Checks":{"status":"enabled"},"Red Hat Local Security Checks":{"status":"enabled"},"HP-UX Local Security Checks":{"status":"enabled"},"Mobile Devices":{"status":"enabled"},"CGI abuses : XSS":{"status":"enabled"},"FreeBSD Local Security Checks":{"status":"enabled"},"Windows":{"status":"enabled"},"MacOS X Local Security Checks":{"status":"enabled"},"Scientific Linux Local Security Checks":{"status":"enabled"},"Web Servers":{"status":"enabled"},"SCADA":{"status":"enabled"}},"settings":{"apm_force_updates":"yes","region_hkg_pref_name":"yes","http_login_max_redir":"0","portscan_range":"default","cisco_offline_configs":"","icmp_unreach_means_host_down":"no","test_local_nessus_host":"yes","ssh_port":"22","aws_ap_northeast_1":"no","av_grace_period":"0","http_login_auth_regex_nocase":"no","snmp_port":"161","aws_us_west_1":"no","enable_admin_shares":"no","icmp_ping_retries":"2","syn_firewall_detection":"Automatic (normal)","snmp_scanner":"yes","sonicos_offline_configs":"","aws_ap_southeast_1":"no","slice_network_addresses":"no","patch_audit_over_rsh":"no","aws_us_gov_west_1":"no","aws_verify_ssl":"yes","tcp_ping":"yes","additional_snmp_port3":"161","dell_f10_offline_configs":"","test_default_oracle_accounts":"no","only_portscan_if_enum_failed":"yes","apm_update_timeout":"5","ssl_prob_ports":"Known SSL ports","ping_the_remote_host":"yes","region_dfw_pref_name":"yes","win_known_good_hashes":"","max_simult_tcp_sessions_per_scan":"","scan_network_printers":"no","stop_scan_on_disconnect":"no","report_verbosity":"Normal","fast_network_discovery":"no","udp_ping":"no","aws_us_east_1":"no","never_send_win_creds_in_the_clear":"yes","win_known_bad_hashes":"","log_live_hosts":"no","enum_domain_users_start_uid":"1000","name":"Example Policy","aws_eu_west_1":"no","description":"This is an example Policy for GoNessus","http_login_invert_auth_regex":"no","smtp_from":"nobody@example.com","smtp_domain":"example.com","thorough_tests":"no","scan_webapps":"no","dont_use_ntlmv1":"yes","aws_sa_east_1":"no","reverse_lookup":"no","smtp_to":"postmaster@[AUTO_REPLACED_IP]","adtran_aos_offline_configs":"","procurve_config_to_audit":"Saved/(show config)","log_whole_attack":"no","microsoft_azure_subscriptions_ids":"","max_hosts_per_scan":"100","region_syd_pref_name":"yes","start_remote_registry":"no","aws_ap_southeast_2":"no","patch_audit_over_telnet":"no","aws_use_https":"yes","unscanned_closed":"no","scan_netware_hosts":"no","ssh_client_banner":"OpenSSH_5.0","enumerate_all_ciphers":"yes","netapp_offline_configs":"","wol_wait_time":"5","huawei_offline_configs":"","report_paranoia":"Normal","http_login_auth_regex_on_headers":"no","wmi_netstat_scanner":"yes","provided_creds_only":"yes","wol_mac_addresses":"","region_lon_pref_name":"yes","cert_expiry_warning_days":"60","host_whitelist":"","bluecoat_proxysg_offline_configs":"","display_unreachable_hosts":"no","verify_open_ports":"no","enum_local_users_end_uid":"1200","udp_scanner":"no","ssh_known_hosts":"","safe_checks":"yes","patch_audit_over_rexec":"no","fortios_offline_configs":"","brocade_offline_configs":"","aws_us_west_2":"no","allow_post_scan_editing":"yes","report_superseded_patches":"yes","max_simult_tcp_sessions_per_host":"","region_iad_pref_name":"yes","tcp_ping_dest_ports":"built-in","enum_domain_users_end_uid":"1200","max_checks_per_host":"5","junos_offline_configs":"","check_crl":"no","svc_detection_on_all_ports":"yes","syn_scanner":"yes","cisco_config_to_audit":"Saved/(show config)","detect_ssl":"yes","disable_dns_resolution":"no","request_windows_domain_info":"yes","network_receive_timeout":"5","aws_ui_region_type":"Rest of the World","additional_snmp_port1":"161","additional_snmp_port2":"161","reduce_connections_on_congestion":"no","icmp_ping":"yes","network_type":"Mixed (use RFC 1918)","checkpoint_gaia_offline_configs":"","procurve_offline_configs":"","arp_ping":"yes","region_ord_pref_name":"yes","enum_local_users_start_uid":"1000","fireeye_offline_configs":"","extremeos_offline_configs":"","http_login_method":"POST","ssh_netstat_scanner":"yes","silent_dependencies":"yes","enable_plugin_debugging":"no","http_reauth_delay":"0"},"uuid":"ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66"}`
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

	policy, err := client.PolicyDetails(httpClient, 25)
	if err != nil || policy.UUID == "" {
		t.FailNow()
	}
}

func TestImportPolicy(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"no_target":"false","template_uuid":"exampleuuid", "description":"This is an example Policy for GoNessus","name":"Example Policy","owner":"kkirsche","visibility":"shared","shared":1,"user_permissions":32,"last_modification_date":1454334708,"creation_date":1454334708,"owner_id":2,"id":25}`
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

	policy, err := client.ImportPolicy(httpClient, "testFile.nessus")
	if err != nil || policy.ID != 25 {

		t.FailNow()
	}
}

func TestExportPolicy(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"policies":"test"}` // Using JSON for CreateSession, otherwise this would return XML for ExportPolicy
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

	policies, err := client.ExportPolicy(httpClient, 25)
	if err != nil || policies == "" {
		t.FailNow()
	}
}

func TestListPolicy(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"policies":[{"no_target":"false","template_uuid":"exampleuuid", "description":"This is an example Policy for GoNessus","name":"Example Policy","owner":"kkirsche","visibility":"shared","shared":1,"user_permissions":32,"last_modification_date":1454334708,"creation_date":1454334708,"owner_id":2,"id":25}]}`
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

	policies, err := client.ListPolicy(httpClient)
	if err != nil || policies.Policies[0].Name != "Example Policy" {
		t.FailNow()
	}
}
