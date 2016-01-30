package nessus

// ListScannersResponse is the list of scanners returned by ListScanners
type ListScannersResponse struct {
	Scanners []struct {
		AwsAvailabilityZone  interface{} `json:"aws_availability_zone"`
		AwsUpdateInterval    interface{} `json:"aws_update_interval"`
		Challenge            string      `json:"challenge"`
		CreationDate         int         `json:"creation_date"`
		EngineBuild          string      `json:"engine_build"`
		EngineVersion        string      `json:"engine_version"`
		Expiration           int         `json:"expiration"`
		ExpirationTime       int         `json:"expiration_time"`
		ID                   int         `json:"id"`
		Key                  string      `json:"key"`
		LastConnect          interface{} `json:"last_connect"`
		LastModificationDate int         `json:"last_modification_date"`
		License              struct {
			ActivationCode string `json:"activation_code"`
			AgentsUsed     int    `json:"agents_used"`
			Drm            string `json:"drm"`
			ExpirationDate int    `json:"expiration_date"`
			Mode           int    `json:"mode"`
			Name           string `json:"name"`
			ScannersUsed   int    `json:"scanners_used"`
			Type           string `json:"type"`
			UpdatePassword string `json:"update_password"`
			UpdateURL      string `json:"update_url"`
		} `json:"license"`
		Linked           int         `json:"linked"`
		Loadavg          interface{} `json:"loadavg"`
		LoadedPluginSet  string      `json:"loaded_plugin_set"`
		Name             string      `json:"name"`
		NeedsRestart     interface{} `json:"needs_restart"`
		NumHosts         interface{} `json:"num_hosts"`
		NumScans         interface{} `json:"num_scans"`
		NumSessions      interface{} `json:"num_sessions"`
		NumTCPSessions   interface{} `json:"num_tcp_sessions"`
		Owner            string      `json:"owner"`
		OwnerID          int         `json:"owner_id"`
		OwnerName        string      `json:"owner_name"`
		Platform         string      `json:"platform"`
		RegistrationCode string      `json:"registration_code"`
		ScanCount        int         `json:"scan_count"`
		Shared           int         `json:"shared"`
		Status           string      `json:"status"`
		Timestamp        int         `json:"timestamp"`
		Token            interface{} `json:"token"`
		Type             string      `json:"type"`
		UIBuild          string      `json:"ui_build"`
		UIVersion        string      `json:"ui_version"`
		UserPermissions  int         `json:"user_permissions"`
		UUID             string      `json:"uuid"`
	} `json:"scanners"`
}
