package touchque

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"
)

const sdkVersion = "3.1.0"

type httpClient struct {
	config *Config
	client *http.Client
}

func newHTTPClient(config *Config) *httpClient {
	return &httpClient{
		config: config,
		client: &http.Client{
			Timeout: time.Duration(config.TimeoutMs) * time.Millisecond,
			// An API endpoint should never redirect; following one could
			// replay the signed auth headers to another host.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// buildQuery returns a deterministic query string: keys sorted, `?`-prefixed (or "").
func buildQuery(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	v := url.Values{}
	for _, k := range keys {
		v.Set(k, params[k])
	}
	return "?" + v.Encode()
}

func (h *httpClient) post(endpoint string, body interface{}) (map[string]interface{}, error) {
	var bodyBytes []byte
	var err error
	if body != nil {
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	} else {
		bodyBytes = []byte("{}")
	}
	return h.send("POST", endpoint, bodyBytes)
}

func (h *httpClient) get(endpoint string) (map[string]interface{}, error) {
	return h.getWithQuery(endpoint, nil)
}

func (h *httpClient) getWithQuery(endpoint string, params map[string]string) (map[string]interface{}, error) {
	return h.send("GET", endpoint+buildQuery(params), nil)
}

func (h *httpClient) delete(endpoint string) (map[string]interface{}, error) {
	return h.send("DELETE", endpoint, nil)
}

func (h *httpClient) send(method, pathWithQuery string, bodyBytes []byte) (map[string]interface{}, error) {
	_, respBody, resp, err := h.do(method, pathWithQuery, bodyBytes)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &result); err != nil {
			result = make(map[string]interface{})
		}
	}
	if resp.StatusCode >= 400 {
		return nil, apiErrorFrom(resp, result)
	}
	return result, nil
}

// sendArray is for endpoints whose success body is a bare JSON array (e.g.
// GET /action-types), which send()/map[string]interface{} can't represent.
func (h *httpClient) sendArray(method, pathWithQuery string, bodyBytes []byte) ([]map[string]interface{}, error) {
	_, respBody, resp, err := h.do(method, pathWithQuery, bodyBytes)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		var errResult map[string]interface{}
		_ = json.Unmarshal(respBody, &errResult)
		return nil, apiErrorFrom(resp, errResult)
	}
	var result []map[string]interface{}
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &result); err != nil {
			return nil, &NetworkError{Message: "touchque: could not decode the response: " + err.Error()}
		}
	}
	return result, nil
}

func (h *httpClient) do(method, pathWithQuery string, bodyBytes []byte) (int, []byte, *http.Response, error) {
	reqURL := h.config.BaseURL + pathWithQuery

	var reader io.Reader
	if bodyBytes != nil {
		reader = bytes.NewBuffer(bodyBytes)
	}
	req, err := http.NewRequest(method, reqURL, reader)
	if err != nil {
		return 0, nil, nil, err
	}

	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	// 16 bytes / 32 hex chars — the API requires at least 16 hex chars.
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return 0, nil, nil, &ConfigError{Message: "touchque: could not generate a nonce: " + err.Error()}
	}
	nonce := hex.EncodeToString(nonceBytes)

	signature := h.signRequest(method, pathWithQuery, bodyBytes, timestamp, nonce)

	req.Header.Set("x-api-key", h.config.APIKey)
	req.Header.Set("x-signature", signature)
	req.Header.Set("x-timestamp", timestamp)
	req.Header.Set("x-nonce", nonce)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "touchque-go-sdk/"+sdkVersion)

	resp, err := h.client.Do(req)
	if err != nil {
		return 0, nil, nil, &NetworkError{Message: "Network error: " + err.Error()}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, nil, &NetworkError{Message: "Network error: could not read the response body: " + err.Error()}
	}
	return resp.StatusCode, respBody, resp, nil
}

func apiErrorFrom(resp *http.Response, result map[string]interface{}) *APIError {
	errMsg := "Unknown API Error"
	if msg, ok := result["error"].(string); ok && msg != "" {
		errMsg = msg
	} else if msg, ok := result["message"].(string); ok && msg != "" {
		errMsg = msg
	}
	apiErr := &APIError{StatusCode: resp.StatusCode, Message: errMsg, Data: result}
	if c, ok := result["code"].(string); ok {
		apiErr.Code = c
	}
	if r, ok := result["reason"].(string); ok {
		apiErr.Reason = r
	}
	if a, ok := result["attemptsLeft"].(float64); ok {
		apiErr.AttemptsLeft = int(a)
	}
	if ra, ok := result["retryAfter"].(float64); ok {
		apiErr.RetryAfter = int(ra)
	} else if h := resp.Header.Get("Retry-After"); h != "" {
		if n, err := strconv.Atoi(h); err == nil {
			apiErr.RetryAfter = n
		}
	}
	return apiErr
}

func (h *httpClient) signRequest(method string, pathWithQuery string, body []byte, timestamp string, nonce string) string {
	hasher := sha256.New()
	hasher.Write(body)
	bodyHash := hex.EncodeToString(hasher.Sum(nil))

	message := method + ":" + pathWithQuery + ":" + timestamp + ":" + nonce + ":" + bodyHash

	mac := hmac.New(sha256.New, []byte(h.config.APISecret))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}
