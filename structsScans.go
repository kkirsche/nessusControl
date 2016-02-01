package nessus

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

// ScanTimezones is a list of scan timezone objects
type ScanTimezones struct {
	Timezones []ScanTimezone `json:"timezones"`
}

// ScanTimezone is used to ensure scans run at the proper local time.
type ScanTimezone struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
