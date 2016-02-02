package nessus

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
