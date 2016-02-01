package nessus

type Folder struct {
	Custom      int    `json:"custom"`
	DefaultTag  int    `json:"default_tag"`
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	UnreadCount int    `json:"unread_count"`
}
