package nessusAPI

// ExportedScan is the response when a scan is successfully exported
type ExportedScan struct {
	File int `json:"file"`
}

// ScanExportStatus is the current status of the scan result exporting.
// A status of "ready" indicates the file can be downloaded.
type ScanExportStatus struct {
	Status string `json:"status"`
}

// LaunchedScan is returned when a scan is successfully launched
type LaunchedScan struct {
	ScanUUID string `json:"scan_uuid"`
}

// ScanList is a list of scans and folders
type ScanList struct {
	Folders   []Folder `json:"folders"`
	Scans     []Scan   `json:"scans"`
	Timestamp int      `json:"timestamp"`
}

// Scan represents the details of a scan.
type Scan struct {
	Control              bool   `json:"control"`
	CreationDate         int    `json:"creation_date"`
	Enabled              bool   `json:"enabled"`
	FolderID             int    `json:"folder_id"`
	ID                   int    `json:"id"`
	LastModificationDate int    `json:"last_modification_date"`
	Name                 string `json:"name"`
	Owner                string `json:"owner"`
	Read                 bool   `json:"read"`
	Rrules               string `json:"rrules"`
	Shared               bool   `json:"shared"`
	Starttime            string `json:"starttime"`
	Status               string `json:"status"`
	Timezone             string `json:"timezone"`
	Type                 string `json:"type"`
	UseDashboard         bool   `json:"use_dashboard"`
	UserPermissions      int    `json:"user_permissions"`
	UUID                 string `json:"uuid"`
}

// ToggleScheduledScan represents the response to a scheduled scan which has been
// enabled or disabled.
type ToggleScheduledScan struct {
	Control   bool   `json:"control"`
	Enabled   bool   `json:"enabled"`
	Rrules    string `json:"rrules"`
	Starttime string `json:"starttime"`
	Timezone  string `json:"timezone"`
}

// ScanTimezones is a list of scan timezone objects
type ScanTimezones struct {
	Timezones []ScanTimezone `json:"timezones"`
}

// ScanTimezone is used to ensure scans run at the proper local time.
type ScanTimezone struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ScanDetails represents details about a specific scan
type ScanDetails struct {
	Comphosts  []interface{} `json:"comphosts"`
	Compliance []interface{} `json:"compliance"`
	Filters    []struct {
		Control struct {
			ReadableRegex string `json:"readable_regex"`
			Regex         string `json:"regex"`
			Type          string `json:"type"`
		} `json:"control"`
		Name         string   `json:"name"`
		Operators    []string `json:"operators"`
		ReadableName string   `json:"readable_name"`
	} `json:"filters"`
	History []struct {
		AltTargetsUsed       bool        `json:"alt_targets_used"`
		CreationDate         interface{} `json:"creation_date"`
		HistoryID            interface{} `json:"history_id"`
		LastModificationDate interface{} `json:"last_modification_date"`
		OwnerID              interface{} `json:"owner_id"`
		Scheduler            interface{} `json:"scheduler"`
		Status               string      `json:"status"`
		Type                 string      `json:"type"`
		UUID                 string      `json:"uuid"`
	} `json:"history"`
	Hosts []struct {
		Critical            int         `json:"critical"`
		High                int         `json:"high"`
		HostID              int         `json:"host_id"`
		HostIndex           int         `json:"host_index"`
		Hostname            string      `json:"hostname"`
		Info                int         `json:"info"`
		Low                 int         `json:"low"`
		Medium              int         `json:"medium"`
		Numchecksconsidered int         `json:"numchecksconsidered"`
		Progress            string      `json:"progress"`
		Scanprogresscurrent interface{} `json:"scanprogresscurrent"`
		Scanprogresstotal   interface{} `json:"scanprogresstotal"`
		Score               interface{} `json:"score"`
		Severity            interface{} `json:"severity"`
		Severitycount       struct {
			Item []struct {
				Count         int `json:"count"`
				Severitylevel int `json:"severitylevel"`
			} `json:"item"`
		} `json:"severitycount"`
		Totalchecksconsidered int `json:"totalchecksconsidered"`
	} `json:"hosts"`
	Info struct {
		Acls []struct {
			DisplayName interface{} `json:"display_name"`
			ID          interface{} `json:"id"`
			Name        interface{} `json:"name"`
			Owner       interface{} `json:"owner"`
			Permissions interface{} `json:"permissions"`
			Type        string      `json:"type"`
		} `json:"acls"`
		AltTargetsUsed  interface{} `json:"alt_targets_used"`
		Control         bool        `json:"control"`
		EditAllowed     bool        `json:"edit_allowed"`
		FolderID        interface{} `json:"folder_id"`
		Hasaudittrail   bool        `json:"hasaudittrail"`
		Haskb           bool        `json:"haskb"`
		Hostcount       interface{} `json:"hostcount"`
		Name            string      `json:"name"`
		NoTarget        interface{} `json:"no_target"`
		ObjectID        interface{} `json:"object_id"`
		PCICanUpload    bool        `json:"pci-can-upload"`
		Policy          string      `json:"policy"`
		ScanEnd         interface{} `json:"scan_end"`
		ScanStart       interface{} `json:"scan_start"`
		ScanType        string      `json:"scan_type"`
		ScannerEnd      interface{} `json:"scanner_end"`
		ScannerName     string      `json:"scanner_name"`
		ScannerStart    interface{} `json:"scanner_start"`
		Status          string      `json:"status"`
		Targets         string      `json:"targets"`
		Timestamp       interface{} `json:"timestamp"`
		UserPermissions interface{} `json:"user_permissions"`
		UUID            string      `json:"uuid"`
	} `json:"info"`
	Notes        interface{} `json:"notes"`
	Remediations struct {
		NumCves           interface{} `json:"num_cves"`
		NumHosts          interface{} `json:"num_hosts"`
		NumImpactedHosts  interface{} `json:"num_impacted_hosts"`
		NumRemediatedCves interface{} `json:"num_remediated_cves"`
		Remediations      []struct {
			Hosts       interface{} `json:"hosts"`
			Remediation string      `json:"remediation"`
			Value       string      `json:"value"`
			Vulns       interface{} `json:"vulns"`
		} `json:"remediations"`
	} `json:"remediations"`
	Vulnerabilities []struct {
		Count         interface{} `json:"count"`
		PluginFamily  string      `json:"plugin_family"`
		PluginID      interface{} `json:"plugin_id"`
		PluginName    string      `json:"plugin_name"`
		Severity      interface{} `json:"severity"`
		SeverityIndex interface{} `json:"severity_index"`
		VulnIndex     interface{} `json:"vuln_index"`
	} `json:"vulnerabilities"`
}

// CreateScanResponse is the Nessus server response when successfully creating
// a scan
type CreateScanResponse struct {
	Scan struct {
		CreationDate           int    `json:"creation_date"`
		CustomTargets          string `json:"custom_targets"`
		DefaultPermisssions    int    `json:"default_permisssions"`
		Description            string `json:"description"`
		Emails                 string `json:"emails"`
		Enabled                bool   `json:"enabled"`
		ID                     int    `json:"id"`
		LastModificationDate   int    `json:"last_modification_date"`
		Name                   string `json:"name"`
		NotificationFilterType string `json:"notification_filter_type"`
		NotificationFilters    string `json:"notification_filters"`
		Owner                  string `json:"owner"`
		OwnerID                int    `json:"owner_id"`
		PolicyID               int    `json:"policy_id"`
		Rrules                 string `json:"rrules"`
		ScannerID              int    `json:"scanner_id"`
		Shared                 int    `json:"shared"`
		Starttime              string `json:"starttime"`
		TagID                  int    `json:"tag_id"`
		Timezone               string `json:"timezone"`
		Type                   string `json:"type"`
		UseDashboard           bool   `json:"use_dashboard"`
		UserPermissions        int    `json:"user_permissions"`
		UUID                   string `json:"uuid"`
	} `json:"scan"`
}

// CreateScan is the JSON object used to create a new scan in Nessus 6.
type CreateScan struct {
	UUID     string             `json:"uuid"`
	Settings CreateScanSettings `json:"settings"`
}

// CreateScanSettings is the sub-JSON structure used in CreateScan when
// generating a new scan in Nessus 6.
type CreateScanSettings struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	FolderID    string `json:"folder_id"`
	ScannerID   string `json:"scanner_id"`
	PolicyID    string `json:"policy_id"`
	TextTargets string `json:"text_targets"`
	FileTargets string `json:"file_targets"`
	Launch      string `json:"launch"`
	Enabled     bool   `json:"enabled"`
	LaunchNow   bool   `json:"launch_now"`
	Emails      string `json:"emails"`
}
