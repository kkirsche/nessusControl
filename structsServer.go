package nessus

type serverPropertiesResponse struct {
	Capabilities struct {
		MultiScanner      bool   `json:"multi_scanner"`
		MultiUser         string `json:"multi_user"`
		ReportEmailConfig bool   `json:"report_email_config"`
	} `json:"capabilities"`
	Enterprise     bool `json:"enterprise"`
	Expiration     int  `json:"expiration"`
	ExpirationTime int  `json:"expiration_time"`
	IdleTimeout    int  `json:"idle_timeout"`
	License        struct {
		Agents         int    `json:"agents"`
		ExpirationDate string `json:"expiration_date"`
		Ips            int    `json:"ips"`
		Scanners       int    `json:"scanners"`
	} `json:"license"`
	LoadedPluginSet string `json:"loaded_plugin_set"`
	LoginBanner     bool   `json:"login_banner"`
	NessusType      string `json:"nessus_type"`
	NessusUIVersion string `json:"nessus_ui_version"`
	Notifications   []struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"notifications"`
	PluginSet       string `json:"plugin_set"`
	ScannerBoottime int    `json:"scanner_boottime"`
	ServerUUID      string `json:"server_uuid"`
	ServerVersion   string `json:"server_version"`
	Update          []struct {
		Href       string `json:"href"`
		NewVersion bool   `json:"new_version"`
		Restart    bool   `json:"restart"`
	} `json:"update"`
}
