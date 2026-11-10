package touchque

import (
	"errors"
	"testing"
)

// A feature the workspace's organization cannot use comes back as an
// *APIError that errors.Is matches to its sentinel, with the feature's id.
// Same scenarios as the Node SDK, against the shared fake TouchQue API.
func TestFeatureRefusalsMatchTheirSentinels(t *testing.T) {
	api := startFakeAPI(t)
	defer api.close()
	api.link("jane@acme.com")
	c := api.client(t)
	cases := map[string]error{"feature_not_in_plan": ErrFeatureNotInPlan, "feature_read_only": ErrFeatureReadOnly, "feature_off": ErrFeatureOff}
	for code, sentinel := range cases {
		api.opts(map[string]interface{}{"featureRefused": code, "feature": "device_risk"})
		_, err := c.Login.Request("jane@acme.com", "LOGIN", "", "", "", false, false)
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != 403 || apiErr.Feature != "device_risk" {
			t.Fatalf("%s: want a 403 *APIError for device_risk, got %v", code, err)
		}
		if !errors.Is(err, sentinel) || !errors.Is(err, ErrFeature) {
			t.Fatalf("%s: errors.Is does not match its sentinel", code)
		}
		for other, s := range cases {
			if other != code && errors.Is(err, s) {
				t.Fatalf("%s matches %s too", code, other)
			}
		}
	}
	api.opts(map[string]interface{}{"featureRefused": nil, "blocked": "access_policy"})
	_, err := c.Login.Request("jane@acme.com", "LOGIN", "", "", "", false, false)
	if err == nil || errors.Is(err, ErrFeature) {
		t.Fatalf("a plain refusal must not match ErrFeature: %v", err)
	}
}
