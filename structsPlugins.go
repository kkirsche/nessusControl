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

// PluginFamilyDetails is the list of plugins in a family
type PluginFamilyDetails struct {
	ID      int      `json:"id"`
	Name    string   `json:"name"`
	Plugins []Plugin `json:"plugins"`
}

// Plugin is the name and id of a plugin family
type Plugin struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// PluginDetails are the details for a given plugin
type PluginDetails struct {
	Attributes []PluginAttributes `json:"attributes"`
	FamilyName string             `json:"family_name"`
	ID         int                `json:"id"`
	Name       string             `json:"name"`
}

// PluginAttributes are the attributes for a given plugin
type PluginAttributes struct {
	AttributeName  string `json:"attribute_name"`
	AttributeValue string `json:"attribute_value"`
}
