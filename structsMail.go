package nessus

// MailSettings are Nessus's mail server settings
type MailSettings struct {
	SMTPAuth    string `json:"smtp_auth"`
	SMTPEnc     string `json:"smtp_enc"`
	SMTPFrom    string `json:"smtp_from"`
	SMTPHost    string `json:"smtp_host"`
	SMTPPass    string `json:"smtp_pass"`
	SMTPPort    string `json:"smtp_port"`
	SMTPUser    string `json:"smtp_user"`
	SMTPWwwHost string `json:"smtp_www_host"`
}
