package touchque

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

// 2FA setup context: the end user's address and User-Agent go with the request
// for a first-time QR (POST /auth/generate-secret, POST /auth/secret/reset) by
// the rules of POST /login/request, every adapter sends what it sends with the
// push, and POST /auth/secret/validate answers them as setupContext
// (fixtures/setup-context.json, shared with the other SDKs).

const (
	safariIPhoneUA = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"
	firefoxWinUA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
)

// bodyRecorder is a stub Touchque API that keeps every JSON body it got, by path.
type bodyRecorder struct {
	mu     sync.Mutex
	bodies map[string][]map[string]interface{}
}

func recordBodies(t *testing.T, answer func(path string) interface{}) (*Client, *bodyRecorder) {
	t.Helper()
	rec := &bodyRecorder{bodies: map[string][]map[string]interface{}{}}
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		rec.mu.Lock()
		rec.bodies[r.URL.Path] = append(rec.bodies[r.URL.Path], body)
		rec.mu.Unlock()
		_ = json.NewEncoder(w).Encode(answer(r.URL.Path))
	})
	t.Cleanup(closeFn)
	return c, rec
}

func (b *bodyRecorder) last(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	list := b.bodies[path]
	if len(list) == 0 {
		t.Fatalf("no call to %s", path)
	}
	return list[len(list)-1]
}

// bodyOf is the JSON body of the i-th call to path the fake API recorded.
func bodyOf(t *testing.T, api *fakeAPI, path string, i int) map[string]interface{} {
	t.Helper()
	calls := callsTo(api, path)
	if len(calls) <= i {
		t.Fatalf("%d calls to %s, want call %d", len(calls), path, i)
	}
	body, _ := calls[i]["body"].(map[string]interface{})
	return body
}

// clientFields is what a body says about the end user: clientIp and userAgent, when sent.
func clientFields(body map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for _, key := range []string{"clientIp", "userAgent"} {
		if v, ok := body[key]; ok {
			out[key] = v
		}
	}
	return out
}

// rightmostHop is the IP func of an app behind one trusted proxy: the hop that proxy appended,
// never the leftmost one, which the client controls.
func rightmostHop(r *http.Request) string {
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	return strings.TrimSpace(hops[len(hops)-1])
}

func showJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// ── Request bodies ───────────────────────────────────────────────────

func TestSetupContext_SecretBodiesSendClientIPAndUserAgentOnlyWhenSet(t *testing.T) {
	c, rec := recordBodies(t, func(string) interface{} { return map[string]interface{}{"secret": "S"} })
	for _, tc := range []struct {
		name, ip, ua string
		want         map[string]interface{}
	}{
		{"both", "203.0.113.7", safariIPhoneUA, map[string]interface{}{"externalUsername": "jane@acme.com", "clientIp": "203.0.113.7", "userAgent": safariIPhoneUA}},
		{"ip only", "203.0.113.7", "", map[string]interface{}{"externalUsername": "jane@acme.com", "clientIp": "203.0.113.7"}},
		{"user agent only", "", safariIPhoneUA, map[string]interface{}{"externalUsername": "jane@acme.com", "userAgent": safariIPhoneUA}},
		{"neither", "", "", map[string]interface{}{"externalUsername": "jane@acme.com"}},
	} {
		if _, err := c.Auth.GenerateSecretWithOptions(GenerateSecretOptions{ExternalUsername: "jane@acme.com", ClientIP: tc.ip, UserAgent: tc.ua}); err != nil {
			t.Fatal(err)
		}
		if got := rec.last(t, "/auth/generate-secret"); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("generate, %s: %v", tc.name, got)
		}
		if _, err := c.Auth.ResetSecretWithOptions(ResetSecretOptions{ExternalUsername: "jane@acme.com", ClientIP: tc.ip, UserAgent: tc.ua}); err != nil {
			t.Fatal(err)
		}
		if got := rec.last(t, "/auth/secret/reset"); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("reset, %s: %v", tc.name, got)
		}
	}

	// The positional forms send the user alone, as before.
	user := map[string]interface{}{"externalUsername": "jane@acme.com"}
	if res, err := c.Auth.GenerateSecret("jane@acme.com"); err != nil || res.Secret != "S" {
		t.Fatalf("GenerateSecret = %+v, %v", res, err)
	}
	if got := rec.last(t, "/auth/generate-secret"); !reflect.DeepEqual(got, user) {
		t.Errorf("GenerateSecret body: %v", got)
	}
	if res, err := c.Auth.ResetSecret("jane@acme.com"); err != nil || res.Secret != "S" {
		t.Fatalf("ResetSecret = %+v, %v", res, err)
	}
	if got := rec.last(t, "/auth/secret/reset"); !reflect.DeepEqual(got, user) {
		t.Errorf("ResetSecret body: %v", got)
	}
}

// The login request's rules, exactly: each field only when it is not "", sent as given (no trimming,
// no length cap, no address check).
func TestSetupContext_SecretBodiesFollowTheLoginRequestRules(t *testing.T) {
	c, rec := recordBodies(t, func(path string) interface{} {
		if path == "/login/request" {
			return map[string]interface{}{"requestId": "req_1"}
		}
		return map[string]interface{}{"secret": "S"}
	})
	for _, v := range []string{"", " ", "\t", " 203.0.113.7 ", "203.0.113.7:443", "[2001:db8::1]:443", "::1", "unknown", "UA\nwith a newline", strings.Repeat("a", 4096)} {
		if _, err := c.Login.RequestWithOptions(LoginRequestOptions{ExternalUsername: "jane@acme.com", ClientIP: v, UserAgent: v}); err != nil {
			t.Fatal(err)
		}
		login := clientFields(rec.last(t, "/login/request"))
		if _, err := c.Auth.GenerateSecretWithOptions(GenerateSecretOptions{ExternalUsername: "jane@acme.com", ClientIP: v, UserAgent: v}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Auth.ResetSecretWithOptions(ResetSecretOptions{ExternalUsername: "jane@acme.com", ClientIP: v, UserAgent: v}); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"/auth/generate-secret", "/auth/secret/reset"} {
			if got := clientFields(rec.last(t, path)); !reflect.DeepEqual(got, login) {
				t.Errorf("%s for %.20q: sent %v, the login request %v", path, v, got, login)
			}
		}
	}
}

// ── Adapters ─────────────────────────────────────────────────────────

func TestSetupContext_RelayEnrollStartSendsTheBrowser(t *testing.T) {
	api := startFakeAPI(t)
	h := mountRelay(api.client(t), RelayOptions{})
	rec, out := relayCall(t, h, "POST", "/enroll/start", nil, fromAddr("203.0.113.7:51234"), withHeader("User-Agent", safariIPhoneUA))
	if rec.Code != 200 || out["secret"] != "S" {
		t.Fatalf("first QR: %d %v", rec.Code, out)
	}
	want := map[string]interface{}{"externalUsername": "user@example.com", "clientIp": "203.0.113.7", "userAgent": safariIPhoneUA}
	if got := bodyOf(t, api, "/auth/generate-secret", 0); !reflect.DeepEqual(got, want) {
		t.Fatalf("generate-secret body: %v", got)
	}
	v, err := api.client(t).Auth.ValidateSecret("S")
	if err != nil || v.SetupContext == nil || v.SetupContext.IP != "203.0.113.7" || v.SetupContext.Location == nil || v.SetupContext.Location.City != "Berlin" ||
		v.SetupContext.Device == nil || v.SetupContext.Device.Browser != "Safari" {
		t.Fatalf("the phone sees: %s, %v", showJSON(v), err)
	}

	// An unscanned QR is re-issued (409, then reset) with this request's browser.
	rec, out = relayCall(t, h, "POST", "/enroll/start", nil, fromAddr("[2001:db8::7]:443"), withHeader("User-Agent", "UA/2"))
	if rec.Code != 200 || out["secret"] != "S2" {
		t.Fatalf("re-issued QR: %d %v", rec.Code, out)
	}
	want = map[string]interface{}{"externalUsername": "user@example.com", "clientIp": "2001:db8::7", "userAgent": "UA/2"}
	if got := bodyOf(t, api, "/auth/secret/reset", 0); !reflect.DeepEqual(got, want) {
		t.Fatalf("reset body: %v", got)
	}
}

// The relay's IP option is the address of the push and of the QR alike: the hop a trusted proxy
// appended, never the leftmost one. A POST /login for a user without a phone makes both calls.
func TestSetupContext_RelayUsesItsIPOptionForTheQRAsForThePush(t *testing.T) {
	api := startFakeAPI(t)
	h := mountRelay(api.client(t), RelayOptions{
		UserID:    func(*http.Request) string { return "enroll@example.com" },
		LoginUser: func(*http.Request) string { return "new@example.com" },
		RateLimit: &RateLimitOptions{Disabled: true},
		IP:        rightmostHop,
	})
	behindProxy := []func(*http.Request){withHeader("X-Forwarded-For", "6.6.6.6, 203.0.113.7"), withHeader("User-Agent", safariIPhoneUA)}
	rec, out := relayCall(t, h, "POST", "/login", map[string]interface{}{}, behindProxy...)
	if step, _ := out["touchque"].(map[string]interface{}); rec.Code != 202 || step["state"] != "enroll" || step["enroll"] == nil {
		t.Fatalf("expected the first-time QR, got %d %s", rec.Code, rec.Body.String())
	}
	want := map[string]interface{}{"clientIp": "203.0.113.7", "userAgent": safariIPhoneUA}
	if got := clientFields(bodyOf(t, api, "/login/request", 0)); !reflect.DeepEqual(got, want) {
		t.Fatalf("login request: %v", got)
	}
	if got := clientFields(bodyOf(t, api, "/auth/generate-secret", 0)); !reflect.DeepEqual(got, want) {
		t.Fatalf("the guard's QR: %v", got)
	}
	if rec, _ := relayCall(t, h, "POST", "/enroll/start", nil, behindProxy...); rec.Code != 200 {
		t.Fatalf("enroll/start: %d %s", rec.Code, rec.Body.String())
	}
	if got := bodyOf(t, api, "/auth/generate-secret", 1); got["externalUsername"] != "enroll@example.com" || !reflect.DeepEqual(clientFields(got), want) {
		t.Fatalf("enroll/start's QR: %v", got)
	}
}

// No address (an IP func that has none, or no RemoteAddr): none is sent, as on the push.
func TestSetupContext_RelaySendsNoAddressWhenItHasNone(t *testing.T) {
	api := startFakeAPI(t)
	noIP := mountRelay(api.client(t), RelayOptions{UserID: func(*http.Request) string { return "a@example.com" }, IP: func(*http.Request) string { return "" }})
	if rec, _ := relayCall(t, noIP, "POST", "/enroll/start", nil, withHeader("User-Agent", "UA/1")); rec.Code != 200 {
		t.Fatalf("enroll/start: %d %s", rec.Code, rec.Body.String())
	}
	if got := bodyOf(t, api, "/auth/generate-secret", 0); !reflect.DeepEqual(got, map[string]interface{}{"externalUsername": "a@example.com", "userAgent": "UA/1"}) {
		t.Fatalf("an IP func without an address: %v", got)
	}
	noRemote := mountRelay(api.client(t), RelayOptions{UserID: func(*http.Request) string { return "b@example.com" }})
	if rec, _ := relayCall(t, noRemote, "POST", "/enroll/start", nil, fromAddr(""), withHeader("User-Agent", "")); rec.Code != 200 {
		t.Fatalf("enroll/start: %d %s", rec.Code, rec.Body.String())
	}
	if got := bodyOf(t, api, "/auth/generate-secret", 1); !reflect.DeepEqual(got, map[string]interface{}{"externalUsername": "b@example.com"}) {
		t.Fatalf("no RemoteAddr, no User-Agent: %v", got)
	}
}

// Like TestRequire_SendsHostOnlyClientIP: the host part of r.RemoteAddr, never "ip:port".
func TestSetupContext_RequireSendsHostOnlyClientIPWithTheFirstTimeQR(t *testing.T) {
	api := startFakeAPI(t)
	handler := Require(api.client(t), "LOGIN", http.NotFoundHandler(), RequireOptions{
		User: func(r *http.Request) string { return r.Header.Get("X-User") },
	})
	for i, remote := range []string{"192.0.2.1:1234", "[2001:db8::1]:443"} {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = remote
		req.Header.Set("X-User", "new"+itoa(i)+"@acme.com")
		req.Header.Set("User-Agent", "UA/"+itoa(i))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != 202 || !strings.Contains(rec.Body.String(), `"qrCodeDataUrl"`) {
			t.Fatalf("expected the first-time QR, got %d %s", rec.Code, rec.Body.String())
		}
	}
	for i, ip := range []string{"192.0.2.1", "2001:db8::1"} {
		if got := clientFields(bodyOf(t, api, "/auth/generate-secret", i)); !reflect.DeepEqual(got, map[string]interface{}{"clientIp": ip, "userAgent": "UA/" + itoa(i)}) {
			t.Errorf("QR %d: %v", i, got)
		}
		if login, qr := clientFields(bodyOf(t, api, "/login/request", i)), clientFields(bodyOf(t, api, "/auth/generate-secret", i)); !reflect.DeepEqual(login, qr) {
			t.Errorf("QR %d: %v, the push would have had %v", i, qr, login)
		}
	}
}

// RequireOptions.IP (a trusted proxy's hop) goes with the first-time QR, and the QR a poll renews
// (409, then reset) carries that poll's browser.
func TestSetupContext_RequireSendsItsIPOptionWithTheQRAndItsRenewal(t *testing.T) {
	api := startFakeAPI(t)
	api.opts(map[string]interface{}{"secretTtlMs": 1000}) // within 15 s of its expiry: the next poll renews it
	handler := Require(api.client(t), "LOGIN", http.NotFoundHandler(), RequireOptions{
		User: func(*http.Request) string { return "new@acme.com" },
		IP:   rightmostHop,
	})
	send := func(xff, ua, token string) map[string]interface{} {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.Header.Set("X-Forwarded-For", xff)
		req.Header.Set("User-Agent", ua)
		if token != "" {
			req.Header.Set(GuardTokenHeader, token)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		var out map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if step, _ := out["touchque"].(map[string]interface{}); rec.Code != 202 || step["enroll"] == nil {
			t.Fatalf("expected a first-time QR, got %d %s", rec.Code, rec.Body.String())
		}
		return out
	}
	first := send("6.6.6.6, 203.0.113.7", safariIPhoneUA, "")
	want := map[string]interface{}{"clientIp": "203.0.113.7", "userAgent": safariIPhoneUA}
	if got := clientFields(bodyOf(t, api, "/auth/generate-secret", 0)); !reflect.DeepEqual(got, want) {
		t.Fatalf("first QR: %v", got)
	}
	api.opts(map[string]interface{}{"secretTtlMs": 300000}) // the renewed QR lives long enough to validate
	send("7.7.7.7, 198.51.100.23", firefoxWinUA, first["token"].(string))
	want = map[string]interface{}{"clientIp": "198.51.100.23", "userAgent": firefoxWinUA}
	if got := clientFields(bodyOf(t, api, "/auth/secret/reset", 0)); !reflect.DeepEqual(got, want) {
		t.Fatalf("renewed QR: %v", got)
	}
	v, err := api.client(t).Auth.ValidateSecret("S2")
	if err != nil || v.SetupContext == nil || v.SetupContext.Location == nil || v.SetupContext.Location.City != "New York" ||
		v.SetupContext.Device == nil || v.SetupContext.Device.OS != "Windows" {
		t.Fatalf("the phone sees: %s, %v", showJSON(v), err)
	}
}

func TestSetupContext_StartAndRunGuardSendTheirIPAndUserAgent(t *testing.T) {
	api := startFakeAPI(t)
	c := api.client(t)
	step, err := c.Start("LOGIN", "start@acme.com", StartOptions{IP: "203.0.113.7", UserAgent: "UA/1"})
	if err != nil || step.State != StepEnroll || step.Enroll == nil {
		t.Fatalf("start: %+v %v", step, err)
	}
	if got := bodyOf(t, api, "/auth/generate-secret", 0); !reflect.DeepEqual(got, map[string]interface{}{"externalUsername": "start@acme.com", "clientIp": "203.0.113.7", "userAgent": "UA/1"}) {
		t.Fatalf("Start's QR: %v", got)
	}
	res := RunGuard(context.Background(), c, GuardInput{User: "guard@acme.com", Action: "LOGIN", IP: "198.51.100.23", UserAgent: "UA/2"})
	if res.Status != 202 || res.Body.Touchque.Enroll == nil {
		t.Fatalf("RunGuard: %d %+v", res.Status, res.Body)
	}
	if got := bodyOf(t, api, "/auth/generate-secret", 1); !reflect.DeepEqual(got, map[string]interface{}{"externalUsername": "guard@acme.com", "clientIp": "198.51.100.23", "userAgent": "UA/2"}) {
		t.Fatalf("RunGuard's QR: %v", got)
	}
	// Without them, neither is sent, as on the push.
	if res := RunGuard(context.Background(), c, GuardInput{User: "bare@acme.com", Action: "LOGIN"}); res.Body.Touchque.Enroll == nil {
		t.Fatalf("RunGuard: %d %+v", res.Status, res.Body)
	}
	if got := bodyOf(t, api, "/auth/generate-secret", 2); !reflect.DeepEqual(got, map[string]interface{}{"externalUsername": "bare@acme.com"}) {
		t.Fatalf("a bare QR: %v", got)
	}
	if got := clientFields(bodyOf(t, api, "/login/request", 2)); len(got) != 0 {
		t.Fatalf("the bare push: %v", got)
	}
}

// ── setupContext on the validate answer ──────────────────────────────

// wantSetupContext is the fixture's expected setupContext as this SDK's type, read strictly (a null
// string is ""): a value the fixture does not define is a broken fixture, not something to parse.
func wantSetupContext(t *testing.T, v interface{}) *SetupContext {
	t.Helper()
	if v == nil {
		return nil
	}
	keys := func(m map[string]interface{}, names ...string) {
		t.Helper()
		got := make([]string, 0, len(m))
		for k := range m {
			got = append(got, k)
		}
		sort.Strings(got)
		sort.Strings(names)
		if !reflect.DeepEqual(got, names) {
			t.Fatalf("expected keys %v, the fixture has %v", names, got)
		}
	}
	str := func(m map[string]interface{}, key string) string {
		t.Helper()
		switch s := m[key].(type) {
		case nil:
			return ""
		case string:
			return s
		}
		t.Fatalf("expected %s: %v", key, m[key])
		return ""
	}
	obj := func(m map[string]interface{}, key string) map[string]interface{} {
		t.Helper()
		switch o := m[key].(type) {
		case nil:
			return nil
		case map[string]interface{}:
			return o
		}
		t.Fatalf("expected %s: %v", key, m[key])
		return nil
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		t.Fatalf("expected setupContext: %v", v)
	}
	keys(m, "ip", "location", "device", "requestedAt", "farFromPhone")
	want := &SetupContext{IP: str(m, "ip"), RequestedAt: str(m, "requestedAt")}
	if loc := obj(m, "location"); loc != nil {
		keys(loc, "city", "country", "countryCode")
		want.Location = &SetupLocation{City: str(loc, "city"), Country: str(loc, "country"), CountryCode: str(loc, "countryCode")}
	}
	if dev := obj(m, "device"); dev != nil {
		keys(dev, "browser", "os", "model")
		want.Device = &SetupDevice{Browser: str(dev, "browser"), OS: str(dev, "os"), Model: str(dev, "model")}
	}
	switch far := m["farFromPhone"].(type) {
	case nil:
	case bool:
		want.FarFromPhone = &far
	default:
		t.Fatalf("expected farFromPhone: %v", far)
	}
	return want
}

// Every case of fixtures/setup-context.json (full, allNull, missing, null, wrongTypes, extraFields,
// and any added later) through ValidateSecret, against its expected entry.
func TestSetupContext_ValidateSecretReadsTheSharedFixture(t *testing.T) {
	var fx map[string]json.RawMessage
	readFixture(t, "setup-context.json", &fx)
	var expected map[string]interface{}
	if err := json.Unmarshal(fx["expected"], &expected); err != nil || expected == nil {
		t.Fatalf("expected: %v", err)
	}
	names := make([]string, 0, len(fx))
	for name := range fx {
		if name != "expected" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range []string{"allNull", "extraFields", "full", "missing", "null", "wrongTypes"} {
		if _, ok := fx[name]; !ok {
			t.Fatalf("the fixture has no %q case: %v", name, names)
		}
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			want, ok := expected[name]
			if !ok {
				t.Fatalf("no expected entry for %q", name)
			}
			answer := fx[name]
			c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(answer)
			})
			defer closeFn()
			resp, err := c.Auth.ValidateSecret("S")
			if err != nil {
				t.Fatalf("ValidateSecret: %v", err)
			}
			if !resp.Valid || resp.ExternalUsername != "user@example.com" {
				t.Fatalf("the other fields: %+v", resp)
			}
			if w := wantSetupContext(t, want); !reflect.DeepEqual(resp.SetupContext, w) {
				t.Fatalf("setupContext = %s, want %s", showJSON(resp.SetupContext), showJSON(w))
			}
		})
	}
}

// The JSON names are the API's: a full SetupContext encodes back to the fixture's object.
func TestSetupContext_EncodesWithTheAPIsNames(t *testing.T) {
	var fx struct {
		Expected struct {
			Full json.RawMessage `json:"full"`
		} `json:"expected"`
	}
	readFixture(t, "setup-context.json", &fx)
	var raw, again interface{}
	if err := json.Unmarshal(fx.Expected.Full, &raw); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(parseSetupContext(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out, &again); err != nil || !reflect.DeepEqual(again, raw) {
		t.Fatalf("encoded %s, want %s", out, fx.Expected.Full)
	}
}

func TestSetupContext_LenientParsing(t *testing.T) {
	no, yes := false, true
	for name, tc := range map[string]struct {
		in   interface{}
		want *SetupContext
	}{
		"missing":                      {nil, nil},
		"a string":                     {"Berlin, Germany", nil},
		"a number":                     {float64(203), nil},
		"true":                         {true, nil},
		"an array":                     {[]interface{}{map[string]interface{}{"ip": "203.0.113.7"}}, nil},
		"an empty object":              {map[string]interface{}{}, &SetupContext{}},
		"an empty location and device": {map[string]interface{}{"location": map[string]interface{}{}, "device": map[string]interface{}{}}, &SetupContext{Location: &SetupLocation{}, Device: &SetupDevice{}}},
		"location fields of other types": {map[string]interface{}{"location": map[string]interface{}{"city": float64(1), "country": true, "countryCode": []interface{}{"DE"}}},
			&SetupContext{Location: &SetupLocation{}}},
		"location an array":      {map[string]interface{}{"location": []interface{}{"Berlin"}}, &SetupContext{}},
		"device a string":        {map[string]interface{}{"device": "iPhone"}, &SetupContext{}},
		"requestedAt a number":   {map[string]interface{}{"requestedAt": float64(1763285400000)}, &SetupContext{}},
		"requestedAt kept as is": {map[string]interface{}{"requestedAt": "not a date"}, &SetupContext{RequestedAt: "not a date"}},
		"farFromPhone false":     {map[string]interface{}{"farFromPhone": false}, &SetupContext{FarFromPhone: &no}},
		"farFromPhone true":      {map[string]interface{}{"farFromPhone": true}, &SetupContext{FarFromPhone: &yes}},
		"farFromPhone 1":         {map[string]interface{}{"farFromPhone": float64(1)}, &SetupContext{}},
		"farFromPhone null":      {map[string]interface{}{"farFromPhone": nil}, &SetupContext{}},
	} {
		if got := parseSetupContext(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %s, want %s", name, showJSON(got), showJSON(tc.want))
		}
	}

	// Through ValidateSecret too: never an error for its shape.
	for answer, want := range map[string]*SetupContext{
		`{"valid":true,"setupContext":"Berlin"}`:                             nil,
		`{"valid":true,"setupContext":[1]}`:                                  nil,
		`{"valid":true,"setupContext":false}`:                                nil,
		`{"valid":true,"setupContext":{"ip":["x"],"location":7,"device":0}}`: {},
	} {
		c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(answer)) })
		resp, err := c.Auth.ValidateSecret("S")
		closeFn()
		if err != nil || !resp.Valid || !reflect.DeepEqual(resp.SetupContext, want) {
			t.Fatalf("%s: %s %v", answer, showJSON(resp), err)
		}
	}
}

// ── End to end, against the shared fake ──────────────────────────────

func TestSetupContext_ThePhoneSeesWhereTheQRWasAskedFor(t *testing.T) {
	api := startFakeAPI(t)
	c := api.client(t)

	gen, err := c.Auth.GenerateSecretWithOptions(GenerateSecretOptions{ExternalUsername: "jane@acme.com", ClientIP: "203.0.113.7", UserAgent: safariIPhoneUA})
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.Auth.ValidateSecret(gen.Secret)
	if err != nil || !v.Valid || v.ExternalUsername != "jane@acme.com" || v.SetupContext == nil {
		t.Fatalf("validate: %s %v", showJSON(v), err)
	}
	want := &SetupContext{
		IP: "203.0.113.7", Location: &SetupLocation{City: "Berlin", Country: "Germany", CountryCode: "DE"},
		Device: &SetupDevice{Browser: "Safari", OS: "iOS", Model: "iPhone"}, RequestedAt: v.SetupContext.RequestedAt,
	}
	if _, ok := isoMs(v.SetupContext.RequestedAt); !ok || !reflect.DeepEqual(v.SetupContext, want) {
		t.Fatalf("setupContext = %s", showJSON(v.SetupContext))
	}

	// A reset QR, asked for from another browser, has its own.
	reset, err := c.Auth.ResetSecretWithOptions(ResetSecretOptions{ExternalUsername: "jane@acme.com", ClientIP: "198.51.100.23", UserAgent: firefoxWinUA})
	if err != nil {
		t.Fatal(err)
	}
	v, err = c.Auth.ValidateSecret(reset.Secret)
	if err != nil || v.SetupContext == nil {
		t.Fatalf("validate the reset: %s %v", showJSON(v), err)
	}
	want = &SetupContext{
		IP: "198.51.100.23", Location: &SetupLocation{City: "New York", Country: "United States", CountryCode: "US"},
		Device: &SetupDevice{Browser: "Firefox", OS: "Windows"}, RequestedAt: v.SetupContext.RequestedAt,
	}
	if !reflect.DeepEqual(v.SetupContext, want) {
		t.Fatalf("reset setupContext = %s", showJSON(v.SetupContext))
	}

	// A reset without them clears the old QR's: the new one has none.
	bare, err := c.Auth.ResetSecret("jane@acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if v, err := c.Auth.ValidateSecret(bare.Secret); err != nil || !v.Valid || v.ExternalUsername != "jane@acme.com" || v.SetupContext != nil {
		t.Fatalf("validate a reset without them: %s %v", showJSON(v), err)
	}

	// Nothing named: no setup context.
	plain, err := c.Auth.GenerateSecret("bob@acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if v, err := c.Auth.ValidateSecret(plain.Secret); err != nil || v.ExternalUsername != "bob@acme.com" || v.SetupContext != nil {
		t.Fatalf("validate without: %s %v", showJSON(v), err)
	}

	// A private address and a client that is not a browser: a setup context with nothing known but the time.
	private, err := c.Auth.GenerateSecretWithOptions(GenerateSecretOptions{ExternalUsername: "carol@acme.com", ClientIP: "10.1.2.3", UserAgent: "curl/8.7.1"})
	if err != nil {
		t.Fatal(err)
	}
	v, err = c.Auth.ValidateSecret(private.Secret)
	if err != nil || v.ExternalUsername != "carol@acme.com" || v.SetupContext == nil || v.SetupContext.RequestedAt == "" ||
		!reflect.DeepEqual(v.SetupContext, &SetupContext{RequestedAt: v.SetupContext.RequestedAt}) {
		t.Fatalf("nothing known: %s %v", showJSON(v), err)
	}

	// A server that answers setupContext: null.
	api.opts(map[string]interface{}{"setupContextNull": true})
	if v, err := c.Auth.ValidateSecret(private.Secret); err != nil || !v.Valid || v.SetupContext != nil {
		t.Fatalf("null: %s %v", showJSON(v), err)
	}
}
