package nessus

// ListPolicyResponse is the response of the List method on Nessus.Policies
type ListPolicyResponse struct {
	Policies []PolicyResponse `json:"policies"`
}

// PolicyResponse represents a single policy object
type PolicyResponse struct {
	CreationDate         int    `json:"creation_date"`
	Description          string `json:"description"`
	ID                   int    `json:"id"`
	LastModificationDate int    `json:"last_modification_date"`
	Name                 string `json:"name"`
	NoTarget             string `json:"no_target"`
	Owner                string `json:"owner"`
	OwnerID              int    `json:"owner_id"`
	Shared               int    `json:"shared"`
	TemplateUUID         string `json:"template_uuid"`
	UserPermissions      int    `json:"user_permissions"`
	Visibility           string `json:"visibility"`
}

// PolicyDetailsResponse represents the policy details object
type PolicyDetailsResponse struct {
	Plugins  interface{} `json:"plugins"`
	Settings interface{} `json:"settings"`
	UUID     string      `json:"uuid"`
}

// CreatePolicyResponse is the response to a successful creation of a new policy
type CreatePolicyResponse struct {
	PolicyID   int    `json:"policy_id"`
	PolicyName string `json:"policy_name"`
}

// CopyPolicyResponse is the response when copying a policy
type CopyPolicyResponse struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}
