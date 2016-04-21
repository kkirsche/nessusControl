package nessusProcessor

const (
	// RFC3339Safe is RFC3339 with :'s replaced with dashes for filesystem safety
	// This is also in nessusCreator
	RFC3339Safe = "2006-01-02T15-04-05Z07-00"
	// MySQLDateTime represents a DATETIME field within a MySQL database.
	// MySQL retrieves and displays DATETIME values in 'YYYY-MM-DD HH:MM:SS'
	// format. The supported range is '1000-01-01 00:00:00' to
	// '9999-12-31 23:59:59'.
	MySQLDateTime = "2006-01-02 15:04:05"
)
