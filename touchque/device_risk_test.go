package touchque

import (
	"context"
	"errors"
	"testing"
)

// Device risk against the shared fake API: the report goes through untouched
// and the answer fails toward asking. Same scenarios as the Node SDK's
// DeviceRisk tests.

func TestDeviceRiskCheckSendsTheReportAndReadsTheAnswer(t *testing.T) {
	api := startFakeAPI(t)
	defer api.close()
	tq := api.client(t)
	r, err := tq.DeviceRisk.Check(context.Background(), DeviceRiskCheckOptions{RequestID: "dre_flaggedaaaaaaaaaaaaaaa", Event: "sign_up", ExternalUsername: "ayse@acme.com", ClientIP: "203.0.113.7"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Report != "ok" || r.VisitorID != "tqv_fakeVisitor00000001" || len(r.Signals) != 1 || r.Signals[0].Code != "device_many_accounts" || r.Signals[0].Enforced || r.CaseCode != "DRK-2QX" {
		t.Fatalf("answer: %+v", r)
	}
	ev, err := tq.DeviceRisk.GetEvent(context.Background(), "dre_aaaaaaaaaaaaaaaaaaaaaa")
	if err != nil || ev["visitorId"] != "tqv_fakeVisitor00000001" {
		t.Fatalf("event: %v %v", ev, err)
	}
	if r.StepUp || !r.WouldStepUp || r.Mode != "shadow" {
		t.Fatalf("verdict: %+v", r)
	}
}

func TestDeviceRiskBadInputFailsBeforeAnyRequest(t *testing.T) {
	api := startFakeAPI(t)
	defer api.close()
	tq := api.client(t)
	var cfg *ConfigError
	if _, err := tq.DeviceRisk.Check(context.Background(), DeviceRiskCheckOptions{DeviceRisk: "r", Event: "tracking"}); !errors.As(err, &cfg) {
		t.Fatalf("unknown page: %v", err)
	}
	if _, err := tq.DeviceRisk.GetEvent(context.Background(), "../users"); !errors.As(err, &cfg) {
		t.Fatalf("bad request id: %v", err)
	}
}

func TestDeviceRiskAnswerFailsTowardAsking(t *testing.T) {
	if !ParseDeviceRiskCheck(map[string]interface{}{}).StepUp {
		t.Fatal("an answer without stepUp must ask")
	}
	if ParseDeviceRiskCheck(map[string]interface{}{"stepUp": false}).StepUp {
		t.Fatal("stepUp false is false")
	}
	r := ParseDeviceRiskCheck(map[string]interface{}{"signals": []interface{}{map[string]interface{}{"code": "device_tampered", "text": "t"}, nil, map[string]interface{}{"text": "x"}}, "requires": "passkey"})
	if len(r.Signals) != 1 || r.Signals[0].Strength != "number_match" || r.Requires != "passkey" || r.Report != "invalid" {
		t.Fatalf("parsed: %+v", r)
	}
}

func TestDeviceRiskEngineUnavailableComesThroughAndANormalAnswerHasNone(t *testing.T) {
	down := ParseDeviceRiskCheck(map[string]interface{}{"report": "ok", "signals": []interface{}{}, "stepUp": true, "wouldStepUp": true,
		"requires": "number_match", "mode": "enforce", "engine": "unavailable"})
	if down.Engine != "unavailable" || !down.StepUp || down.Requires != "number_match" {
		t.Fatalf("engine unavailable: %+v", down)
	}
	normal := ParseDeviceRiskCheck(map[string]interface{}{"report": "ok", "signals": []interface{}{}, "stepUp": false, "requires": "none", "mode": "shadow"})
	if normal.Engine != "" || normal.StepUp {
		t.Fatalf("normal answer: %+v", normal)
	}
	if ParseDeviceRiskCheck(map[string]interface{}{"engine": 42.0}).Engine != "" {
		t.Fatal("an engine that is not a string is left out")
	}
}

func TestDeviceRiskTheFormFieldAsItCameIsAnsweredNeverAnError(t *testing.T) {
	api := startFakeAPI(t)
	defer api.close()
	tq := api.client(t)
	r, err := tq.DeviceRisk.Check(context.Background(), DeviceRiskCheckOptions{RequestID: "", ExternalUsername: "ayse@acme.com"})
	if err != nil || r.Report != "missing" || r.VisitorID != "" || r.StepUp || !r.WouldStepUp {
		t.Fatalf("missing: %+v %v", r, err)
	}
	if len(r.Signals) != 1 || r.Signals[0].Code != "device_identification_missing" {
		t.Fatalf("signals: %+v", r.Signals)
	}
	if r, err := tq.DeviceRisk.Check(context.Background(), DeviceRiskCheckOptions{RequestID: "nope"}); err != nil || r.Report != "unknown" {
		t.Fatalf("unknown: %+v %v", r, err)
	}
	if ParseDeviceRiskCheck(map[string]interface{}{"report": "expired"}).Report != "expired" {
		t.Fatal("expired")
	}
}

func TestRiskCheckCarriesDeviceRisk(t *testing.T) {
	api := startFakeAPI(t)
	defer api.close()
	tq := api.client(t)
	if _, err := tq.Risk.Check(context.Background(), RiskCheckOptions{ExternalUsername: "ayse@acme.com", DeviceRiskRequestID: "dre_aaaaaaaaaaaaaaaaaaaaaa"}); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceRiskTheAddressTheCountsAndABotAnswerComeThrough(t *testing.T) {
	r := ParseDeviceRiskCheck(map[string]interface{}{"report": "ok", "network": map[string]interface{}{"type": "hosting"},
		"velocity": map[string]interface{}{"identifications1h": 2.0}, "bot": map[string]interface{}{"result": "suspected"}})
	if r.Network["type"] != "hosting" || r.Velocity["identifications1h"] != 2.0 || r.Bot["result"] != "suspected" {
		t.Fatalf("network, velocity, bot: %#v %#v %#v", r.Network, r.Velocity, r.Bot)
	}
	if ParseDeviceRiskCheck(map[string]interface{}{"network": "x"}).Network != nil {
		t.Fatal("a network that is not an object is left out")
	}
}

func TestDeviceRiskSearchEventsPagesWithTheOpaqueCursorAndSendsTheFilters(t *testing.T) {
	api := startFakeAPI(t)
	defer api.close()
	tq := api.client(t)
	no := false
	first, err := tq.DeviceRisk.SearchEvents(context.Background(), DeviceRiskSearchOptions{Account: "ada@example.com", StepUp: &no, IP: "203.0.113.0/24", Limit: 1})
	if err != nil || len(first.Events) != 1 || first.Events[0]["requestId"] != "dre_fakeEvent00000000002" || first.NextCursor != "" {
		t.Fatalf("first: %+v %v", first, err)
	}
	q := api.lastDeviceRiskSearch()
	if q["account"] != "ada@example.com" || q["stepUp"] != "false" || q["ip"] != "203.0.113.0/24" || q["limit"] != "1" || len(q) != 4 {
		t.Fatalf("query: %v", q)
	}
	var seen []string
	cursor := ""
	for {
		page, err := tq.DeviceRisk.SearchEvents(context.Background(), DeviceRiskSearchOptions{Limit: 1, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range page.Events {
			seen = append(seen, e["requestId"].(string))
		}
		if cursor = page.NextCursor; cursor == "" {
			break
		}
	}
	if len(seen) != 3 || seen[0] != "dre_fakeEvent00000000003" || seen[2] != "dre_fakeEvent00000000001" {
		t.Fatalf("pages: %v", seen)
	}
	var cfg *ConfigError
	if _, err := tq.DeviceRisk.SearchEvents(context.Background(), DeviceRiskSearchOptions{Limit: 101}); !errors.As(err, &cfg) {
		t.Fatalf("limit: %v", err)
	}
}
