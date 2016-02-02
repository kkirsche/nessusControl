package nessusAPI

// Permissions is used to display an array of permissions
type Permissions struct {
	Acls []Permission `json:"acls"`
}

// Permission are used to provide access rights to a given object
type Permission struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Owner       int    `json:"owner"`
	Permissions int    `json:"permissions"`
	Type        string `json:"type"`
	DisplayName string `json:"display_name"`
}
