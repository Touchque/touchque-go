package touchque

// Spawns the shared Node fake TouchQue API (testing/fake-touchque-api.mjs)
// for contract tests: verifies this SDK's requests are signed exactly like
// the real backend expects, using a real HTTP round trip (not mocks).

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

type fakeAPI struct {
	baseURL string
	cmd     *exec.Cmd
	t       *testing.T
}

func startFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is required for contract tests")
	}
	script, err := filepath.Abs(filepath.Join("..", "testing", "fake-touchque-api.mjs"))
	if err != nil {
		t.Fatalf("could not resolve fake-touchque-api.mjs path: %v", err)
	}
	cmd := exec.Command("node", script)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("could not attach stdout: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("could not start fake-touchque-api.mjs: %v", err)
	}

	decoder := json.NewDecoder(stdout)
	var line struct {
		Port int `json:"port"`
	}
	done := make(chan error, 1)
	go func() { done <- decoder.Decode(&line) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("could not read fake-touchque-api.mjs port: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for fake-touchque-api.mjs to start")
	}

	api := &fakeAPI{baseURL: "http://127.0.0.1:" + itoa(line.Port), cmd: cmd, t: t}
	t.Cleanup(api.close)
	return api
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func (f *fakeAPI) close() {
	if f.cmd.Process != nil {
		_ = f.cmd.Process.Kill()
		_ = f.cmd.Wait()
	}
}

func (f *fakeAPI) call(path string, body map[string]interface{}) map[string]interface{} {
	f.t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(f.baseURL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		f.t.Fatalf("call %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]interface{}
	_ = json.Unmarshal(raw, &out)
	return out
}

func (f *fakeAPI) link(user string) { f.call("/__test/link", map[string]interface{}{"user": user}) }

func (f *fakeAPI) opts(o map[string]interface{}) { f.call("/__test/opts", o) }

func (f *fakeAPI) approve(id string) { f.call("/__test/approve", map[string]interface{}{"id": id}) }

func (f *fakeAPI) approveVia(id, via string) {
	f.call("/__test/approve", map[string]interface{}{"id": id, "via": via})
}

func (f *fakeAPI) reject(id string) { f.call("/__test/reject", map[string]interface{}{"id": id}) }

func (f *fakeAPI) calls() []map[string]interface{} {
	f.t.Helper()
	resp, err := http.Get(f.baseURL + "/__test/calls")
	if err != nil {
		f.t.Fatalf("calls: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out []map[string]interface{}
	_ = json.Unmarshal(raw, &out)
	return out
}

func (f *fakeAPI) client(t *testing.T) *Client {
	t.Helper()
	return NewClient(&Config{APIKey: "tq_test_key", APISecret: "test_secret", BaseURL: f.baseURL, TimeoutMs: 5000})
}
