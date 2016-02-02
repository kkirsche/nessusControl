package nessusAPI

// ViewProxyResponse is the returned proxy settings for the Nessus server.
type ViewProxyResponse struct {
	Proxy         string `json:"proxy"`
	ProxyPassword string `json:"proxy_password"`
	ProxyPort     string `json:"proxy_port"`
	ProxyUsername string `json:"proxy_username"`
	UserAgent     string `json:"user_agent"`
}
