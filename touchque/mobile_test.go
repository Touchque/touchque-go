package touchque

import (
	"encoding/json"
	"testing"
	"time"
)

// Mobile SDK (the partner's own app as the approver) against the shared fake
// API: a token the app spends once, replace for a second phone, the devices,
// the settings, and the push a MOBILE_PUSH webhook becomes. Same scenarios as
// the Node SDK's tests.
func TestMobileEnrollmentDevicesAndSettings(t *testing.T) {
	api := startFakeAPI(t)
	client := NewClient(&Config{APIKey: "tq_test_key", APISecret: "test_secret", BaseURL: api.baseURL})

	first, err := client.Mobile.CreateEnrollment(CreateMobileEnrollmentOptions{ExternalUsername: "ada@shop.example"})
	if err != nil || len(first.EnrollmentToken) != 47 {
		t.Fatalf("enrollment: %+v %v", first, err)
	}
	device := api.call("/__test/mobile-enroll", map[string]interface{}{"enrollmentToken": first.EnrollmentToken, "platform": "android"})
	if _, err := client.Mobile.CreateEnrollment(CreateMobileEnrollmentOptions{ExternalUsername: "ada@shop.example"}); err == nil || err.(*APIError).Code != "already_enrolled" {
		t.Fatalf("want already_enrolled, got %v", err)
	}
	second, err := client.Mobile.CreateEnrollment(CreateMobileEnrollmentOptions{ExternalUsername: "ada@shop.example", Replace: true, TTLSeconds: 300})
	if err != nil || second.ReplacesDeviceID != device["deviceId"] {
		t.Fatalf("replace: %+v %v", second, err)
	}
	api.call("/__test/mobile-enroll", map[string]interface{}{"enrollmentToken": second.EnrollmentToken})
	active, err := client.Mobile.ListDevices(ListMobileDevicesOptions{ExternalUsername: "ada@shop.example"})
	if err != nil || len(active.Devices) != 1 || active.Devices[0].Platform != "ios" {
		t.Fatalf("active devices: %+v %v", active, err)
	}
	old, err := client.Mobile.GetDevice(device["deviceId"].(string))
	if err != nil || old.RevokedReason != "replaced" {
		t.Fatalf("old device: %+v %v", old, err)
	}
	if tp, err := client.Mobile.TestPush(active.Devices[0].DeviceID); err != nil || tp.Via != "webhook" || !tp.OK {
		t.Fatalf("test push: %+v %v", tp, err)
	}
	if linked, err := client.Mobile.RemoveDevice(active.Devices[0].DeviceID); err != nil || !linked {
		t.Fatalf("remove: %v %v", linked, err)
	}

	s, err := client.Mobile.UpdateSettings(map[string]interface{}{"androidPackages": []string{"com.shop.app"}, "attestation": "required"})
	if err != nil || s.Attestation != "required" || s.EnrollTTLSeconds != 600 || s.AndroidPackages[0] != "com.shop.app" {
		t.Fatalf("settings: %+v %v", s, err)
	}
	if _, err := client.Mobile.UpdateSettings(map[string]interface{}{"colour": "blue"}); err == nil {
		t.Fatal("an unknown setting must be refused")
	}

	// Your own push keys: Touchque sends that platform's push and never shows the key back.
	s, err = client.Mobile.UpdateSettings(map[string]interface{}{
		"apns": map[string]interface{}{"keyId": "ABC123DEFG", "teamId": "TEAM123456", "topic": "com.shop.app", "key": "-----BEGIN PRIVATE KEY-----"},
		"fcm":  map[string]interface{}{"serviceAccount": map[string]interface{}{"project_id": "shop", "client_email": "push@shop.iam.gserviceaccount.com", "private_key": "x"}},
	})
	if err != nil || s.Push.IOS != "touchque" || s.Push.Android != "touchque" || s.Push.APNs == nil || s.Push.APNs.KeyID != "ABC123DEFG" || s.Push.FCM.ProjectID != "shop" {
		t.Fatalf("push keys: %+v %v", s, err)
	}
	if s, err = client.Mobile.UpdateSettings(map[string]interface{}{"apns": nil}); err != nil || s.Push.IOS != "webhook" || s.Push.APNs != nil {
		t.Fatalf("apns removed: %+v %v", s, err)
	}
}

func TestMobilePushFromWebhook(t *testing.T) {
	var event map[string]interface{}
	_ = json.Unmarshal([]byte(`{"event":"MOBILE_PUSH","externalUsername":"ada@shop.example","deviceId":"d1","platform":"ios","pushToken":"apns-token",
		"kind":"approval","requestId":"r1","expiresAt":"2026-10-26T10:00:30.000Z",
		"alert":{"title":"Change delivery address","body":"Demo Shop is waiting for your approval."},
		"data":{"touchque":"{\"v\":1,\"k\":\"approval\",\"did\":\"d1\",\"rid\":\"r1\"}"}}`), &event)
	push, ok := MobilePushFromWebhook(event)
	if !ok || push.PushToken != "apns-token" || push.FCMData["touchque"] != `{"v":1,"k":"approval","did":"d1","rid":"r1"}` {
		t.Fatalf("push: %+v", push)
	}
	if push.APNs["touchque"] != push.FCMData["touchque"] || push.APNs["aps"].(map[string]interface{})["alert"] == nil {
		t.Fatalf("apns: %+v", push.APNs)
	}
	if _, ok := MobilePushFromWebhook(map[string]interface{}{"event": "DEVICE_LINKED"}); ok {
		t.Fatal("other events are not pushes")
	}
	if !push.Expired(time.Date(2026, 10, 26, 10, 1, 0, 0, time.UTC)) || push.Expired(time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)) {
		t.Fatal("expiry")
	}
}
