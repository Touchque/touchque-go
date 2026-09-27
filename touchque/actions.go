package touchque

// ActionsResource manages action types ("LOGIN", "SEND_MONEY", …) — what a
// user is asked to approve. Define them from code at start-up instead of
// clicking them into the Dashboard.
type ActionsResource struct {
	http *httpClient
}

func newActionsResource(http *httpClient) *ActionsResource {
	return &ActionsResource{http: http}
}

// ActionType is one action type, as returned by Define / List.
type ActionType struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Critical actions always use number matching and never accept recovery
	// / offline time-based codes.
	Critical bool `json:"critical"`
	Active   bool `json:"active"`
}

// DefineOptions holds the optional fields for Define.
type DefineOptions struct {
	// Name shown on the phone and in the Dashboard (default: the slug).
	Name        string
	Description string
	// Critical: nil (the zero value pointer) keeps what the Dashboard has.
	Critical *bool
}

// Define creates the action type, or updates its name/description/critical
// flag. Safe to call on every start-up: it never re-enables a type an admin
// disabled.
func (a *ActionsResource) Define(actionType string, opts DefineOptions) (*ActionType, error) {
	name := opts.Name
	if name == "" {
		name = actionType
	}
	body := map[string]interface{}{"type": actionType, "name": name}
	if opts.Description != "" {
		body["description"] = opts.Description
	}
	if opts.Critical != nil {
		body["critical"] = *opts.Critical
	}
	res, err := a.http.post("/action-types", body)
	if err != nil {
		return nil, err
	}
	return parseActionType(res), nil
}

// List returns every action type defined for this integration.
func (a *ActionsResource) List() ([]ActionType, error) {
	rows, err := a.http.sendArray("GET", "/action-types", nil)
	if err != nil {
		return nil, err
	}
	out := make([]ActionType, 0, len(rows))
	for _, row := range rows {
		out = append(out, *parseActionType(row))
	}
	return out, nil
}

func parseActionType(res map[string]interface{}) *ActionType {
	a := &ActionType{}
	if v, ok := res["id"].(string); ok {
		a.ID = v
	}
	if v, ok := res["type"].(string); ok {
		a.Type = v
	}
	if v, ok := res["name"].(string); ok {
		a.Name = v
	}
	if v, ok := res["description"].(string); ok {
		a.Description = v
	}
	if v, ok := res["critical"].(bool); ok {
		a.Critical = v
	}
	if v, ok := res["active"].(bool); ok {
		a.Active = v
	}
	return a
}
