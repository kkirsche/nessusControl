package nessus

// PluginFamilies / plugin families are used to organize and group plugins
type PluginFamilies struct {
	Families []PluginFamily `json:"families"`
}

// PluginFamily / plugin families are used to organize and group plugins.
type PluginFamily struct {
	Count int    `json:"count"`
	ID    int    `json:"id"`
	Name  string `json:"name"`
}
