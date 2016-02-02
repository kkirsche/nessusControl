package nessusAPI

// Agents lists agents known to the Nessus server
type Agents struct {
	Agents []Agent `json:"agents"`
}

// Agent is an indvidual Agent resource
type Agent struct {
	Distro      string `json:"distro"`
	ID          int    `json:"id"`
	IP          string `json:"ip"`
	LastScanned string `json:"last_scanned"`
	Name        string `json:"name"`
	Platform    string `json:"platform"`
	Token       string `json:"token"`
	UUID        string `json:"uuid"`
}
