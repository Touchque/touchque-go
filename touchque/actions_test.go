package touchque

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TouchQue Actions in the Go SDK: every management call sends exactly what
// the shared vectors (fixtures/actions-api-vectors.json) say, against the
// shared fake TouchQue API, signed like the real API.

type actionVector struct {
	Name    string                 `json:"name"`
	Args    map[string]interface{} `json:"args"`
	Request struct {
		Method string                 `json:"method"`
		Path   string                 `json:"path"`
		Query  map[string]string      `json:"query"`
		Body   map[string]interface{} `json:"body"`
	} `json:"request"`
	Expect map[string]interface{} `json:"expect"`
}

type actionVectors struct {
	Calls   []actionVector `json:"calls"`
	Context struct {
		LoginRequest struct {
			Body map[string]interface{} `json:"body"`
		} `json:"loginRequest"`
		RiskCheck struct {
			Body map[string]interface{} `json:"body"`
		} `json:"riskCheck"`
	} `json:"context"`
}

func loadActionVectors(t *testing.T) actionVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "fixtures", "actions-api-vectors.json"))
	if err != nil {
		t.Fatalf("vectors: %v", err)
	}
	var v actionVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("vectors: %v", err)
	}
	return v
}

func strs(v interface{}) []string {
	list, _ := v.([]interface{})
	out := make([]string, 0, len(list))
	for _, s := range list {
		out = append(out, s.(string))
	}
	return out
}

func template(v interface{}) *ActionTemplateRef {
	m := v.(map[string]interface{})
	params, _ := m["params"].(map[string]interface{})
	return &ActionTemplateRef{ID: m["id"].(string), Params: params}
}

func runActionVector(c *Client, v actionVector) (interface{}, error) {
	a := v.Args
	s := func(k string) string { x, _ := a[k].(string); return x }
	n := func(k string) int { x, _ := a[k].(float64); return int(x) }
	acts := c.Actions
	switch v.Name {
	case "deploy":
		return acts.Deploy(s("slug"), DeployActionOptions{Trigger: s("trigger"), Code: s("code"), Secrets: strs(a["secrets"]), Name: s("name")})
	case "deployTemplate":
		return acts.Deploy(s("slug"), DeployActionOptions{Trigger: s("trigger"), Template: template(a["template"]), OnFailure: s("onFailure")})
	case "deployLoosening":
		return acts.Deploy(s("slug"), DeployActionOptions{Trigger: s("trigger"), Code: s("code"), Capabilities: strs(a["capabilities"]), AllowedHosts: strs(a["allowedHosts"])})
	case "list":
		return acts.List()
	case "get":
		return acts.Get(s("slug"))
	case "version":
		return acts.Version(s("slug"), n("number"))
	case "update":
		enabled := a["enabled"].(bool)
		return acts.Update(s("slug"), UpdateActionOptions{Enabled: &enabled})
	case "rollback":
		version := n("version")
		return acts.Rollback(s("slug"), &version)
	case "rollbackPrevious":
		return acts.Rollback(s("slug"), nil)
	case "test":
		return acts.Test(TestActionOptions{ActionDraft: ActionDraft{Trigger: s("trigger"), Code: s("code")}, EventID: s("eventId")})
	case "testDeployed":
		return acts.Test(TestActionOptions{ActionDraft: ActionDraft{Slug: s("slug")}, Event: a["event"].(map[string]interface{})})
	case "dryRun":
		return acts.DryRun(DryRunActionOptions{ActionDraft: ActionDraft{Trigger: s("trigger"), Code: s("code")}, Replaces: s("replaces"), Limit: n("limit")})
	case "events":
		return acts.Events(s("trigger"), n("limit"))
	case "logs":
		return acts.Logs(s("slug"), n("limit"), nil)
	case "metrics":
		return acts.Metrics(s("slug"), s("window"))
	case "triggers":
		return acts.Triggers()
	case "templates":
		return acts.Templates()
	case "renderTemplate":
		return acts.RenderTemplate(s("id"), s("trigger"), a["params"].(map[string]interface{}))
	case "setSecret":
		return acts.Secrets.Set(s("name"), s("value"))
	case "listSecrets":
		return acts.Secrets.List()
	case "deleteSecret":
		return nil, acts.Secrets.Delete(s("name"))
	case "delete":
		return nil, acts.Delete(s("slug"))
	}
	return nil, nil
}

// asMap turns a typed result into the JSON shape the vectors' expect paths read.
func asMap(v interface{}) map[string]interface{} {
	b, _ := json.Marshal(v)
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	return m
}

func TestActionsAPIVectors(t *testing.T) {
	fake := startFakeAPI(t)
	defer fake.close()
	c := fake.client(t)
	vectors := loadActionVectors(t)
	for _, v := range vectors.Calls {
		result, err := runActionVector(c, v)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		calls := fake.calls()
		last := calls[len(calls)-1]
		if last["method"] != v.Request.Method || last["path"] != v.Request.Path {
			t.Fatalf("%s: sent %v %v, want %s %s", v.Name, last["method"], last["path"], v.Request.Method, v.Request.Path)
		}
		u, _ := url.Parse(last["url"].(string))
		query := map[string]string{}
		for k, vals := range u.Query() {
			query[k] = vals[0]
		}
		want := v.Request.Query
		if want == nil {
			want = map[string]string{}
		}
		if !reflect.DeepEqual(query, want) {
			t.Fatalf("%s: query %v, want %v", v.Name, query, want)
		}
		if v.Request.Method != "GET" && v.Request.Method != "DELETE" {
			wantBody := v.Request.Body
			if wantBody == nil {
				wantBody = map[string]interface{}{}
			}
			if !reflect.DeepEqual(last["body"], wantBody) {
				t.Fatalf("%s: body %v, want %v", v.Name, last["body"], wantBody)
			}
		}
		for path, wantVal := range v.Expect {
			var got interface{} = asMap(result)
			for _, k := range strings.Split(path, ".") {
				m, _ := got.(map[string]interface{})
				got = m[k]
			}
			if !reflect.DeepEqual(got, wantVal) {
				t.Fatalf("%s %s: %v, want %v", v.Name, path, got, wantVal)
			}
		}
	}
}

func TestActionsContextIsPassedThrough(t *testing.T) {
	fake := startFakeAPI(t)
	defer fake.close()
	c := fake.client(t)
	vectors := loadActionVectors(t)
	fake.link("ctx@example.com")
	if _, err := c.Login.RequestWithOptions(LoginRequestOptions{ExternalUsername: "ctx@example.com", Type: "LOGIN", Context: map[string]interface{}{"roles": []interface{}{"admin"}, "amount": 2500}}); err != nil {
		t.Fatal(err)
	}
	calls := fake.calls()
	if !reflect.DeepEqual(calls[len(calls)-1]["body"], vectors.Context.LoginRequest.Body) {
		t.Fatalf("login body %v", calls[len(calls)-1]["body"])
	}
	if _, err := c.Risk.Check(context.Background(), RiskCheckOptions{ExternalUsername: "ctx@example.com", Type: "LOGIN", Context: map[string]interface{}{"roles": []interface{}{"admin"}}}); err != nil {
		t.Fatal(err)
	}
	calls = fake.calls()
	if !reflect.DeepEqual(calls[len(calls)-1]["body"], vectors.Context.RiskCheck.Body) {
		t.Fatalf("risk body %v", calls[len(calls)-1]["body"])
	}
}

func TestActionsLooseningVersionWaitsForThePhone(t *testing.T) {
	fake := startFakeAPI(t)
	defer fake.close()
	c := fake.client(t)
	res, err := c.Actions.Deploy("silent-office", DeployActionOptions{Trigger: "risk.check", Code: `exports.onExecute = (e, api) => api.allowSilent("office");`, Capabilities: []string{"allow_silent"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Deployed || res.Approval == nil || !res.Approval.Required {
		t.Fatalf("expected a pending approval, got %+v", res)
	}
	fake.call("/__test/approve-version", map[string]interface{}{"slug": "silent-office", "number": 1})
	detail, err := c.Actions.Get("silent-office")
	if err != nil {
		t.Fatal(err)
	}
	if detail.Action.ActiveVersion == nil || *detail.Action.ActiveVersion != 1 {
		t.Fatalf("version 1 should be live: %+v", detail.Action)
	}
}

func TestActionsBadInputIsRefusedBeforeAnyRequest(t *testing.T) {
	fake := startFakeAPI(t)
	defer fake.close()
	c := fake.client(t)
	if _, err := c.Actions.Deploy("Bad Slug", DeployActionOptions{Trigger: "login.request", Code: "x"}); err == nil {
		t.Fatal("bad slug accepted")
	}
	if _, err := c.Actions.Deploy("no-code", DeployActionOptions{Trigger: "login.request"}); err == nil {
		t.Fatal("missing code accepted")
	}
	if _, err := c.Actions.Secrets.Set("lowercase", "v"); err == nil {
		t.Fatal("bad secret name accepted")
	}
	if len(fake.calls()) != 0 {
		t.Fatal("a request was sent")
	}
}
