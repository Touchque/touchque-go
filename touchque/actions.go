package touchque

import (
	"encoding/json"
	"regexp"
	"strconv"
	"time"
)

// ActionsResource is TouchQue Actions: your own code at points of the
// approval pipeline (before the push is sent, the silent sign-in decision,
// after an approval, fraud reports, device and recovery events). TouchQue
// runs it in a sandbox; this resource deploys, tests, replays and observes it.
//
//	client.Actions.Deploy("night-alert", touchque.DeployActionOptions{
//		Trigger:  "approval.decided",
//		Template: &touchque.ActionTemplateRef{ID: "alert", Params: map[string]interface{}{"channel": "slack"}},
//	})
//
// Action code itself is JavaScript (exports.onExecute = async (event, api) => {...}),
// whatever language your server is written in.
type ActionsResource struct {
	http *httpClient
	// Secrets your Actions read (event.secrets.NAME) or notify with.
	Secrets *ActionSecretsResource
}

func newActionsResource(http *httpClient) *ActionsResource {
	return &ActionsResource{http: http, Secrets: &ActionSecretsResource{http: http}}
}

var (
	actionSlugRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
	actionSecretRE   = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	actionTemplateRE = regexp.MustCompile(`^[a-z_]{1,64}$`)
)

// ActionTemplateRef names a no-code template and its parameters.
type ActionTemplateRef struct {
	ID     string                 `json:"id"`
	Params map[string]interface{} `json:"params,omitempty"`
}

// ActionDraft is code to deploy, test or replay: Code or Template (with
// Trigger), or Slug for the deployed version of an existing Action.
type ActionDraft struct {
	Trigger      string
	Code         string
	Template     *ActionTemplateRef
	Slug         string
	Secrets      []string
	AllowedHosts []string
	// Capabilities: loosening powers (skip_number_match, override_block,
	// allow_silent); each needs an admin's phone approval in the dashboard.
	Capabilities []string
}

func (d ActionDraft) body() map[string]interface{} {
	b := map[string]interface{}{}
	if d.Trigger != "" {
		b["trigger"] = d.Trigger
	}
	if d.Slug != "" {
		b["slug"] = d.Slug
	}
	if d.Code != "" {
		b["code"] = d.Code
	}
	if d.Template != nil {
		b["template"] = d.Template
	}
	if d.Secrets != nil {
		b["secrets"] = d.Secrets
	}
	if d.AllowedHosts != nil {
		b["allowedHosts"] = d.AllowedHosts
	}
	if d.Capabilities != nil {
		b["capabilities"] = d.Capabilities
	}
	return b
}

// DeployActionOptions: Trigger is required for a new Action and cannot
// change later; Code or Template is required.
type DeployActionOptions struct {
	Trigger      string
	Name         string
	Code         string
	Template     *ActionTemplateRef
	Secrets      []string
	AllowedHosts []string
	Capabilities []string
	// OnFailure (pre triggers): "continue" (default, never blocks), "step_up" or "deny".
	OnFailure string
	Order     *int
	Enabled   *bool
	// Activate: false saves the version without making it live.
	Activate *bool
}

// ActionSummary is one Action.
type ActionSummary struct {
	Slug            string `json:"slug"`
	Name            string `json:"name"`
	Trigger         string `json:"trigger"`
	Enabled         bool   `json:"enabled"`
	Order           int    `json:"order"`
	OnFailure       string `json:"onFailure"`
	ActiveVersion   *int   `json:"activeVersion"`
	PendingApproval int    `json:"pendingApproval,omitempty"`
	CreatedAt       string `json:"createdAt,omitempty"`
	UpdatedAt       string `json:"updatedAt,omitempty"`
}

// ActionVersion is one immutable version of an Action.
type ActionVersion struct {
	Number               int                `json:"number"`
	Status               string             `json:"status"` // ready, pending_approval, rejected
	Active               bool               `json:"active"`
	Capabilities         []string           `json:"capabilities"`
	ApprovedCapabilities []string           `json:"approvedCapabilities"`
	AllowedHosts         []string           `json:"allowedHosts"`
	Secrets              []string           `json:"secrets"`
	Template             *ActionTemplateRef `json:"template"`
	CodeHash             string             `json:"codeHash"`
	Code                 string             `json:"code,omitempty"`
	CreatedAt            string             `json:"createdAt"`
	CreatedBy            *string            `json:"createdBy"`
	ApprovedAt           *string            `json:"approvedAt"`
}

// ActionApproval is set when a version loosens security and waits for an
// admin's phone approval.
type ActionApproval struct {
	Required     bool     `json:"required"`
	Capabilities []string `json:"capabilities"`
	Message      string   `json:"message"`
}

// ActionDeployResult is Deploy's answer.
type ActionDeployResult struct {
	Action  ActionSummary `json:"action"`
	Version ActionVersion `json:"version"`
	// Deployed: this version runs now.
	Deployed bool            `json:"deployed"`
	Approval *ActionApproval `json:"approval"`
	Warnings []string        `json:"warnings"`
}

// ActionDetail is an Action with the active version's code and its versions.
type ActionDetail struct {
	Action   ActionSummary   `json:"action"`
	Code     *string         `json:"code"`
	Versions []ActionVersion `json:"versions"`
}

// UpdateActionOptions: nil fields are left as they are.
type UpdateActionOptions struct {
	Name      *string
	Enabled   *bool
	Order     *int
	OnFailure *string
}

// ActionCall is one decision call an Action made (deny, stepUp, …).
type ActionCall struct {
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
}

// ActionLogLine is one line of an Action's console output.
type ActionLogLine struct {
	Level   string `json:"level"`
	Message string `json:"message"`
	At      int    `json:"at"`
}

// TestActionOptions runs a draft (or the deployed Action Slug) once.
type TestActionOptions struct {
	ActionDraft
	// EventID: a recorded event (Events()).
	EventID string
	// Event: your own event, merged over the trigger's sample.
	Event map[string]interface{}
	// Network: false turns api.fetch off (nil leaves it on).
	Network *bool
}

// ActionTestResult is what one test run did (nothing is sent).
type ActionTestResult struct {
	Outcome             string                   `json:"outcome"` // ok, error, timeout
	Error               *string                  `json:"error"`
	DurationMs          int                      `json:"durationMs"`
	CPUMs               float64                  `json:"cpuMs"`
	Calls               []ActionCall             `json:"calls"`
	Notifications       []map[string]interface{} `json:"notifications"`
	Logs                []ActionLogLine          `json:"logs"`
	Reasons             []RiskReason             `json:"reasons"`
	WouldBe             map[string]interface{}   `json:"wouldBe"`
	EventID             *string                  `json:"eventId"`
	Event               map[string]interface{}   `json:"event"`
	AssumedCapabilities []string                 `json:"assumedCapabilities"`
}

// DryRunActionOptions replays a draft against recent real decisions.
type DryRunActionOptions struct {
	ActionDraft
	// Replaces: the deployed Action this draft would replace (left out of the comparison).
	Replaces  string
	OnFailure string
	// Limit: how many recent events (1-1000; 0 = the API's 500).
	Limit int
	Since *time.Time
}

// ActionDryRunResult: how many decisions the draft would have changed, and how.
type ActionDryRunResult struct {
	Trigger             string                   `json:"trigger"`
	Evaluated           int                      `json:"evaluated"`
	From                *string                  `json:"from"`
	To                  *string                  `json:"to"`
	Matched             int                      `json:"matched"`
	Changed             *int                     `json:"changed"`
	Transitions         map[string]int           `json:"transitions"`
	Notifications       map[string]int           `json:"notifications"`
	Errors              int                      `json:"errors"`
	Timeouts            int                      `json:"timeouts"`
	ErrorSamples        []map[string]interface{} `json:"errorSamples"`
	P50Ms               int                      `json:"p50Ms"`
	P95Ms               int                      `json:"p95Ms"`
	Samples             []map[string]interface{} `json:"samples"`
	AssumedCapabilities []string                 `json:"assumedCapabilities"`
}

// RecordedActionEvent is an event a trigger fired with (kept 30 days).
type RecordedActionEvent struct {
	ID        string                 `json:"id"`
	Trigger   string                 `json:"trigger"`
	Time      string                 `json:"time"`
	User      *string                `json:"user"`
	RequestID *string                `json:"requestId"`
	Outcome   map[string]interface{} `json:"outcome"`
	Event     map[string]interface{} `json:"event"`
}

// ActionRun is one live run of an Action.
type ActionRun struct {
	ID            string                   `json:"id"`
	Time          string                   `json:"time"`
	Version       *int                     `json:"version"`
	EventID       *string                  `json:"eventId"`
	RequestID     *string                  `json:"requestId"`
	Outcome       string                   `json:"outcome"`
	Decision      *string                  `json:"decision"`
	Calls         []ActionCall             `json:"calls"`
	Notifications []map[string]interface{} `json:"notifications"`
	Logs          []ActionLogLine          `json:"logs"`
	Error         *string                  `json:"error"`
	DurationMs    int                      `json:"durationMs"`
}

// ActionMetrics are an Action's counts and timing over a window.
type ActionMetrics struct {
	Window        string         `json:"window"`
	Runs          int            `json:"runs"`
	Errors        int            `json:"errors"`
	Timeouts      int            `json:"timeouts"`
	ErrorRate     float64        `json:"errorRate"`
	P50Ms         int            `json:"p50Ms"`
	P95Ms         int            `json:"p95Ms"`
	Decisions     map[string]int `json:"decisions"`
	Notifications map[string]int `json:"notifications"`
}

// ActionTemplateInfo describes a no-code template.
type ActionTemplateInfo struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Triggers    []string          `json:"triggers"`
	Params      map[string]string `json:"params"`
}

// RenderedTemplate is a template as plain code.
type RenderedTemplate struct {
	Code         string   `json:"code"`
	Secrets      []string `json:"secrets"`
	AllowedHosts []string `json:"allowedHosts"`
	Capabilities []string `json:"capabilities"`
}

// ActionRollbackResult is Rollback's answer.
type ActionRollbackResult struct {
	Action  ActionSummary `json:"action"`
	Version ActionVersion `json:"version"`
}

func actionPath(slug string) (string, error) {
	if !actionSlugRE.MatchString(slug) {
		return "", &ConfigError{Message: `touchque: an Action slug is 2-63 lowercase letters, digits or - (e.g. "night-alert")`}
	}
	return "/actions/" + slug, nil
}

// decodeInto converts an API answer into a typed value.
func decodeInto(res interface{}, out interface{}) error {
	b, err := json.Marshal(res)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// Deploy creates the Action or adds a version and makes it live (idempotent:
// the same code and settings change nothing). A version asking for a
// loosening capability waits for an admin's phone approval: then Deployed is
// false and Approval.Required true.
func (a *ActionsResource) Deploy(slug string, opts DeployActionOptions) (*ActionDeployResult, error) {
	path, err := actionPath(slug)
	if err != nil {
		return nil, err
	}
	if opts.Code == "" && opts.Template == nil {
		return nil, &ConfigError{Message: "touchque: Actions.Deploy needs Code or Template"}
	}
	body := ActionDraft{Trigger: opts.Trigger, Code: opts.Code, Template: opts.Template, Secrets: opts.Secrets, AllowedHosts: opts.AllowedHosts, Capabilities: opts.Capabilities}.body()
	if opts.Name != "" {
		body["name"] = opts.Name
	}
	if opts.OnFailure != "" {
		body["onFailure"] = opts.OnFailure
	}
	if opts.Order != nil {
		body["order"] = *opts.Order
	}
	if opts.Enabled != nil {
		body["enabled"] = *opts.Enabled
	}
	if opts.Activate != nil {
		body["activate"] = *opts.Activate
	}
	res, err := a.http.put(path, body)
	if err != nil {
		return nil, err
	}
	out := &ActionDeployResult{}
	return out, decodeInto(res, out)
}

// List returns the workspace's Actions.
func (a *ActionsResource) List() ([]ActionSummary, error) {
	res, err := a.http.get("/actions")
	if err != nil {
		return nil, err
	}
	out := struct {
		Actions []ActionSummary `json:"actions"`
	}{}
	return out.Actions, decodeInto(res, &out)
}

// Get returns the Action, the active version's code and its versions.
func (a *ActionsResource) Get(slug string) (*ActionDetail, error) {
	path, err := actionPath(slug)
	if err != nil {
		return nil, err
	}
	res, err := a.http.get(path)
	if err != nil {
		return nil, err
	}
	out := &ActionDetail{}
	return out, decodeInto(res, out)
}

// Version returns one version with its code.
func (a *ActionsResource) Version(slug string, number int) (*ActionVersion, error) {
	path, err := actionPath(slug)
	if err != nil {
		return nil, err
	}
	res, err := a.http.get(path + "/versions/" + strconv.Itoa(number))
	if err != nil {
		return nil, err
	}
	out := &ActionVersion{}
	return out, decodeInto(res, out)
}

// Update renames, turns on or off, reorders, or changes OnFailure.
func (a *ActionsResource) Update(slug string, opts UpdateActionOptions) (*ActionSummary, error) {
	path, err := actionPath(slug)
	if err != nil {
		return nil, err
	}
	body := map[string]interface{}{}
	if opts.Name != nil {
		body["name"] = *opts.Name
	}
	if opts.Enabled != nil {
		body["enabled"] = *opts.Enabled
	}
	if opts.Order != nil {
		body["order"] = *opts.Order
	}
	if opts.OnFailure != nil {
		body["onFailure"] = *opts.OnFailure
	}
	res, err := a.http.patch(path, body)
	if err != nil {
		return nil, err
	}
	out := struct {
		Action ActionSummary `json:"action"`
	}{}
	return &out.Action, decodeInto(res, &out)
}

// Delete deletes the Action and its versions.
func (a *ActionsResource) Delete(slug string) error {
	path, err := actionPath(slug)
	if err != nil {
		return err
	}
	_, err = a.http.delete(path)
	return err
}

// Rollback goes back to version, or (nil) to the newest runnable version
// before the active one. It takes effect at once.
func (a *ActionsResource) Rollback(slug string, version *int) (*ActionRollbackResult, error) {
	path, err := actionPath(slug)
	if err != nil {
		return nil, err
	}
	body := map[string]interface{}{}
	if version != nil {
		body["version"] = *version
	}
	res, err := a.http.post(path+"/rollback", body)
	if err != nil {
		return nil, err
	}
	out := &ActionRollbackResult{}
	return out, decodeInto(res, out)
}

// Test runs a draft (or a deployed Action) once on a recorded, given or
// sample event. It sends no notification.
func (a *ActionsResource) Test(opts TestActionOptions) (*ActionTestResult, error) {
	body := opts.ActionDraft.body()
	if opts.EventID != "" {
		body["eventId"] = opts.EventID
	}
	if opts.Event != nil {
		body["event"] = opts.Event
	}
	if opts.Network != nil {
		body["network"] = *opts.Network
	}
	res, err := a.http.post("/actions/test", body)
	if err != nil {
		return nil, err
	}
	out := &ActionTestResult{}
	return out, decodeInto(res, out)
}

// DryRun replays a draft against recent real decisions: how many it would
// have changed (Changed, Transitions such as {"push→number_match": 12}),
// notifications it would have sent, errors and timing.
func (a *ActionsResource) DryRun(opts DryRunActionOptions) (*ActionDryRunResult, error) {
	body := opts.ActionDraft.body()
	if opts.Replaces != "" {
		body["replaces"] = opts.Replaces
	}
	if opts.OnFailure != "" {
		body["onFailure"] = opts.OnFailure
	}
	if opts.Limit != 0 {
		body["limit"] = opts.Limit
	}
	if opts.Since != nil {
		body["since"] = opts.Since.UTC().Format(time.RFC3339)
	}
	res, err := a.http.post("/actions/dry-run", body)
	if err != nil {
		return nil, err
	}
	out := &ActionDryRunResult{}
	return out, decodeInto(res, out)
}

// Events returns recorded events, newest first (trigger "" = all; limit 0 = the API's 20).
func (a *ActionsResource) Events(trigger string, limit int) ([]RecordedActionEvent, error) {
	params := map[string]string{}
	if trigger != "" {
		params["trigger"] = trigger
	}
	if limit != 0 {
		params["limit"] = strconv.Itoa(limit)
	}
	res, err := a.http.getWithQuery("/actions/events", params)
	if err != nil {
		return nil, err
	}
	out := struct {
		Events []RecordedActionEvent `json:"events"`
	}{}
	return out.Events, decodeInto(res, &out)
}

// Logs returns live runs of an Action (limit 0 = the API's 50; before nil = newest).
func (a *ActionsResource) Logs(slug string, limit int, before *time.Time) ([]ActionRun, error) {
	path, err := actionPath(slug)
	if err != nil {
		return nil, err
	}
	params := map[string]string{}
	if limit != 0 {
		params["limit"] = strconv.Itoa(limit)
	}
	if before != nil {
		params["before"] = before.UTC().Format(time.RFC3339)
	}
	res, err := a.http.getWithQuery(path+"/logs", params)
	if err != nil {
		return nil, err
	}
	out := struct {
		Logs []ActionRun `json:"logs"`
	}{}
	return out.Logs, decodeInto(res, &out)
}

// Metrics returns an Action's metrics; window is 1h, 24h ("" = 24h), 7d or 30d.
func (a *ActionsResource) Metrics(slug string, window string) (*ActionMetrics, error) {
	path, err := actionPath(slug)
	if err != nil {
		return nil, err
	}
	params := map[string]string{}
	if window != "" {
		params["window"] = window
	}
	res, err := a.http.getWithQuery(path+"/metrics", params)
	if err != nil {
		return nil, err
	}
	out := &ActionMetrics{}
	return out, decodeInto(res, out)
}

// Triggers returns every trigger with its decisions, capabilities,
// notification types and a sample event.
func (a *ActionsResource) Triggers() (map[string]interface{}, error) {
	return a.http.get("/actions/triggers")
}

// Templates returns the no-code templates.
func (a *ActionsResource) Templates() ([]ActionTemplateInfo, error) {
	res, err := a.http.get("/actions/templates")
	if err != nil {
		return nil, err
	}
	out := struct {
		Templates []ActionTemplateInfo `json:"templates"`
	}{}
	return out.Templates, decodeInto(res, &out)
}

// RenderTemplate returns a template as plain code.
func (a *ActionsResource) RenderTemplate(id, trigger string, params map[string]interface{}) (*RenderedTemplate, error) {
	if !actionTemplateRE.MatchString(id) {
		return nil, &ConfigError{Message: "touchque: unknown template id"}
	}
	if params == nil {
		params = map[string]interface{}{}
	}
	res, err := a.http.post("/actions/templates/"+id+"/render", map[string]interface{}{"trigger": trigger, "params": params})
	if err != nil {
		return nil, err
	}
	out := &RenderedTemplate{}
	return out, decodeInto(res, out)
}

// ActionSecretsResource: values are encrypted and never readable again
// through the API.
type ActionSecretsResource struct {
	http *httpClient
}

// ActionSecretInfo is a secret's name and dates (never its value).
type ActionSecretInfo struct {
	Name      string `json:"name"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

func actionSecretPath(name string) (string, error) {
	if !actionSecretRE.MatchString(name) {
		return "", &ConfigError{Message: "touchque: a secret name is capital letters, digits or _ (e.g. SLACK_WEBHOOK_URL)"}
	}
	return "/actions/secrets/" + name, nil
}

// Set stores a secret value.
func (s *ActionSecretsResource) Set(name, value string) (*ActionSecretInfo, error) {
	path, err := actionSecretPath(name)
	if err != nil {
		return nil, err
	}
	if value == "" {
		return nil, &ConfigError{Message: "touchque: a secret value is a non-empty string"}
	}
	res, err := s.http.put(path, map[string]interface{}{"value": value})
	if err != nil {
		return nil, err
	}
	out := &ActionSecretInfo{}
	return out, decodeInto(res, out)
}

// List returns secret names only.
func (s *ActionSecretsResource) List() ([]ActionSecretInfo, error) {
	res, err := s.http.get("/actions/secrets")
	if err != nil {
		return nil, err
	}
	out := struct {
		Secrets []ActionSecretInfo `json:"secrets"`
	}{}
	return out.Secrets, decodeInto(res, &out)
}

// Delete deletes a secret.
func (s *ActionSecretsResource) Delete(name string) error {
	path, err := actionSecretPath(name)
	if err != nil {
		return err
	}
	_, err = s.http.delete(path)
	return err
}
