package touchque

// ActionTypesResource manages action types ("LOGIN", "SEND_MONEY", …) —
// what a user is asked to approve. Define them from code at start-up instead
// of clicking them into the Dashboard. (Before v4 this was Client.Actions;
// Client.Actions is TouchQue Actions now.)
type ActionTypesResource struct {
	http *httpClient
}

func newActionTypesResource(http *httpClient) *ActionTypesResource {
	return &ActionTypesResource{http: http}
}

// SecondThoughtQuestions are the questions an action type can ask (at most two).
var SecondThoughtQuestions = []string{
	"someone_guiding",
	"safe_account",
	"remote_access",
	"asked_for_code",
	"support_call",
	"met_online",
	"promised_return",
	"know_recipient",
	"sim_in_hand",
}

// SecondThought: short yes/no questions the phone asks before Approve, for
// actions people get talked into. A risky answer never refuses: the approval
// comes back provisional, the user's critical actions wait, and the phone
// asks "Was this you?" later. Hold the action until it is reconfirmed.
type SecondThought struct {
	Questions []string `json:"questions"`
	// Locale is the language on the phone: "tr" (default) or "en".
	Locale string `json:"locale,omitempty"`
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
	// SecondThought is nil when the type asks no questions.
	SecondThought *SecondThought `json:"secondThought,omitempty"`
}

// DefineOptions holds the optional fields for Define.
type DefineOptions struct {
	// Name shown on the phone and in the Dashboard (default: the slug).
	Name        string
	Description string
	// Critical: nil (the zero value pointer) keeps what the Dashboard has.
	Critical *bool
	// SecondThought: nil keeps what the Dashboard has; one without questions
	// turns them off.
	SecondThought *SecondThought
}

// Define creates the action type, or updates its name, description, critical
// flag and Second Thought questions. Safe to call on every start-up: it never re-enables a type an admin
// disabled.
func (a *ActionTypesResource) Define(actionType string, opts DefineOptions) (*ActionType, error) {
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
	if opts.SecondThought != nil {
		questions := opts.SecondThought.Questions
		if questions == nil {
			questions = []string{}
		}
		st := map[string]interface{}{"questions": questions}
		if opts.SecondThought.Locale != "" {
			st["locale"] = opts.SecondThought.Locale
		}
		body["secondThought"] = st
	}
	res, err := a.http.post("/action-types", body)
	if err != nil {
		return nil, err
	}
	return parseActionType(res), nil
}

// List returns every action type defined for this integration.
func (a *ActionTypesResource) List() ([]ActionType, error) {
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
	if v, ok := res["secondThought"].(map[string]interface{}); ok {
		st := &SecondThought{}
		if decodeInto(v, st) == nil && len(st.Questions) > 0 {
			a.SecondThought = st
		}
	}
	return a
}
