package touchque

import (
	"encoding/json"
	"reflect"
	"testing"
)

// fixtures/silent-sign-in-vectors.json riskCheck: shared with the Node,
// Python, PHP and web SDKs, so every SDK reads every POST /risk/check answer
// the same way (fail closed).

func TestSilentSignInVectors_RiskCheck(t *testing.T) {
	var fx struct {
		RiskCheck struct {
			Cases []struct {
				Name     string          `json:"name"`
				Response json.RawMessage `json:"response"`
				Expected struct {
					Prompt      bool     `json:"prompt"`
					ReasonCodes []string `json:"reasonCodes"`
					Assurance   string   `json:"assurance"`
				} `json:"expected"`
			} `json:"cases"`
		} `json:"riskCheck"`
	}
	readFixture(t, "silent-sign-in-vectors.json", &fx)
	if len(fx.RiskCheck.Cases) == 0 {
		t.Fatal("no riskCheck vectors")
	}
	for _, c := range fx.RiskCheck.Cases {
		t.Run(c.Name, func(t *testing.T) {
			var raw interface{}
			if err := json.Unmarshal(c.Response, &raw); err != nil {
				t.Fatalf("bad vector: %v", err)
			}
			res := parseRiskCheck(raw)
			if res.Prompt != c.Expected.Prompt {
				t.Fatalf("prompt: got %v, want %v", res.Prompt, c.Expected.Prompt)
			}
			if got := reasonCodes(res.Reasons); !reflect.DeepEqual(got, c.Expected.ReasonCodes) {
				t.Fatalf("reason codes: got %v, want %v", got, c.Expected.ReasonCodes)
			}
			if res.Assurance != c.Expected.Assurance {
				t.Fatalf("assurance: got %q, want %q", res.Assurance, c.Expected.Assurance)
			}
		})
	}
}

func TestParseRiskCheck_AnythingButAJSONObjectAsks(t *testing.T) {
	want := &RiskCheckResult{Prompt: true, Reasons: []RiskReason{}, Assurance: "normal", SilentMode: "enforce"}
	for _, raw := range []string{`null`, `"false"`, `false`, `0`, `[]`, `{"prompt":0}`, `{"prompt":null}`, `{"prompt":"false"}`} {
		var v interface{}
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			t.Fatal(err)
		}
		if got := parseRiskCheck(v); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: got %+v, want %+v", raw, got, want)
		}
	}
	if got := parseRiskCheck(map[string]interface{}(nil)); !reflect.DeepEqual(got, want) {
		t.Fatalf("nil map: got %+v", got)
	}
}

func TestParseRiskCheck_ReasonsWithoutAStringCodeAreDroppedAMissingTextIsEmpty(t *testing.T) {
	var v interface{}
	_ = json.Unmarshal([]byte(`{"prompt":true,"reasons":[null,{"code":1},{"code":"new_browser"},"x",{"code":"risk_signal","text":"Risk signal: tor_exit_node"}]}`), &v)
	got := parseRiskCheck(v).Reasons
	want := []RiskReason{{Code: "new_browser", Text: ""}, {Code: "risk_signal", Text: "Risk signal: tor_exit_node"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseRiskCheck_AssuranceAndSilentMode(t *testing.T) {
	var v interface{}
	_ = json.Unmarshal([]byte(`{"prompt":false,"assurance":"very high","silentMode":"SHADOW"}`), &v)
	res := parseRiskCheck(v)
	if res.Prompt || res.Assurance != "normal" || res.SilentMode != "enforce" {
		t.Fatalf("unknown values fall back: %+v", res)
	}
	var w interface{}
	_ = json.Unmarshal([]byte(`{"prompt":true,"assurance":"low","silentMode":"shadow"}`), &w)
	res = parseRiskCheck(w)
	if !res.Prompt || res.Assurance != "low" || res.SilentMode != "shadow" {
		t.Fatalf("known values are kept: %+v", res)
	}
}
