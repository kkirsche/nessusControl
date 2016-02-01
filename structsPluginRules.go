package nessus

// PluginRuleResponse represents a single Plugin Rule
type PluginRuleResponse struct {
	Date     string `json:"date"`
	Host     string `json:"host"`
	ID       int    `json:"id"`
	Owner    string `json:"owner"`
	OwnerID  int    `json:"owner_id"`
	PluginID int    `json:"plugin_id"`
	Type     string `json:"type"`
}

// PluginRulesList represents a list of plugin rules for a user.
type PluginRulesList struct {
	PluginRules []PluginRuleResponse `json:"plugin_rules"`
}
