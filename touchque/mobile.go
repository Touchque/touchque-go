package touchque

import (
	"encoding/json"
	"net/url"
	"strconv"
	"time"
)

// MobileResource is the TouchQue Mobile SDK, your backend's side: your own
// iOS/Android app is the approver of your users (white-label); they never
// install the TouchQue app.
//
//  1. A user signed in to your app turns approvals on: CreateEnrollment gives
//     a one-time token; your app hands it to the SDK (TouchQue.enroll).
//  2. Ask for approvals as always (Login.Request, Start, the middleware...):
//     they reach your app over the SDK's encrypted connection.
//  3. TouchQue holds no push key of your app. For each request it sends you a
//     signed MOBILE_PUSH webhook: verify it (Webhook), then
//     MobilePushFromWebhook gives the APNs payload / FCM data to send with
//     your own credentials.
type MobileResource struct {
	http *httpClient
}

func newMobileResource(http *httpClient) *MobileResource {
	return &MobileResource{http: http}
}

// MobileEnrollment is a one-time enrollment token. Hand EnrollmentToken to
// your app over your own signed-in API; never put it in a URL or QR code.
type MobileEnrollment struct {
	EnrollmentID     string `json:"enrollmentId"`
	EnrollmentToken  string `json:"enrollmentToken"`
	ExternalUsername string `json:"externalUsername"`
	ExpiresAt        string `json:"expiresAt"`
	Replace          bool   `json:"replace"`
	// ReplacesDeviceID is, with Replace, the device that approves today.
	ReplacesDeviceID string `json:"replacesDeviceId,omitempty"`
}

// CreateMobileEnrollmentOptions holds the POST /mobile/enrollments fields.
type CreateMobileEnrollmentOptions struct {
	ExternalUsername string
	// Replace moves the user from the device they approve with today
	// (otherwise an APIError with Code "already_enrolled").
	Replace bool
	// TTLSeconds is 60-86400; 0 keeps the workspace's default (600).
	TTLSeconds int
}

// MobileDevice is a device inside your app that approves for one of your users.
type MobileDevice struct {
	DeviceID         string `json:"deviceId"`
	ExternalUsername string `json:"externalUsername"`
	Platform         string `json:"platform"`
	AppID            string `json:"appId,omitempty"`
	SDKVersion       string `json:"sdkVersion,omitempty"`
	// Attestation is "apple-appattest" / "android-key" when the app and its key were proven.
	Attestation   string `json:"attestation,omitempty"`
	Status        string `json:"status"`
	RevokedReason string `json:"revokedReason,omitempty"`
	RevokedAt     string `json:"revokedAt,omitempty"`
	EnrolledAt    string `json:"enrolledAt"`
	LastSeenAt    string `json:"lastSeenAt,omitempty"`
	// Linked (GetDevice only) says whether it is the user's approver right now.
	Linked      *bool `json:"linked,omitempty"`
	HardwareKey *struct {
		Registered  bool   `json:"registered"`
		Attestation string `json:"attestation,omitempty"`
		LostAt      string `json:"lostAt,omitempty"`
	} `json:"hardwareKey,omitempty"`
	PushToken bool                   `json:"pushToken"`
	Posture   map[string]interface{} `json:"posture,omitempty"`
}

// ListMobileDevicesOptions filters ListDevices. Status: active (default), revoked or all.
type ListMobileDevicesOptions struct {
	ExternalUsername string
	Status           string
	Limit            int
	Cursor           string
}

// MobileDevices is one page of devices.
type MobileDevices struct {
	Devices    []MobileDevice `json:"devices"`
	NextCursor string         `json:"nextCursor,omitempty"`
}

// MobileSDKSettings says which apps may enrol and whether they must prove themselves.
type MobileSDKSettings struct {
	IOSAppIDs        []string            `json:"iosAppIds"`
	AndroidPackages  []string            `json:"androidPackages"`
	AndroidCerts     map[string][]string `json:"androidCerts"`
	Attestation      string              `json:"attestation"`
	EnrollTTLSeconds int                 `json:"enrollTtlSeconds"`
	Push             MobilePushSettings  `json:"push"`
	UpdatedAt        string              `json:"updatedAt,omitempty"`
}

// MobilePushSettings says who sends the push per platform: "touchque" (with
// your own APNs key / FCM service account) or "webhook" (MOBILE_PUSH to you).
// The keys themselves are never shown back.
type MobilePushSettings struct {
	IOS     string `json:"ios"`
	Android string `json:"android"`
	APNs    *struct {
		KeyID      string `json:"keyId"`
		TeamID     string `json:"teamId"`
		Topic      string `json:"topic"`
		Production bool   `json:"production"`
	} `json:"apns"`
	FCM *struct {
		ProjectID   string `json:"projectId"`
		ClientEmail string `json:"clientEmail"`
	} `json:"fcm"`
}

// CreateEnrollment issues a one-time enrollment token for a user you signed in.
// Whoever spends it becomes the user's approver, so authenticate the user first.
func (m *MobileResource) CreateEnrollment(opts CreateMobileEnrollmentOptions) (*MobileEnrollment, error) {
	if opts.ExternalUsername == "" {
		return nil, &ConfigError{Message: "touchque: Mobile.CreateEnrollment needs the user (ExternalUsername)"}
	}
	body := map[string]interface{}{"externalUsername": opts.ExternalUsername}
	if opts.Replace {
		body["replace"] = true
	}
	if opts.TTLSeconds > 0 {
		body["ttlSeconds"] = opts.TTLSeconds
	}
	res, err := m.http.post("/mobile/enrollments", body)
	if err != nil {
		return nil, err
	}
	var out MobileEnrollment
	return &out, decodeInto(res, &out)
}

// ListDevices lists the devices inside your app, newest first.
func (m *MobileResource) ListDevices(opts ListMobileDevicesOptions) (*MobileDevices, error) {
	params := map[string]string{}
	if opts.ExternalUsername != "" {
		params["externalUsername"] = opts.ExternalUsername
	}
	if opts.Status != "" {
		params["status"] = opts.Status
	}
	if opts.Limit > 0 {
		params["limit"] = strconv.Itoa(opts.Limit)
	}
	if opts.Cursor != "" {
		params["cursor"] = opts.Cursor
	}
	res, err := m.http.getWithQuery("/mobile/devices", params)
	if err != nil {
		return nil, err
	}
	var out MobileDevices
	return &out, decodeInto(res, &out)
}

// GetDevice reads one device inside your app.
func (m *MobileResource) GetDevice(deviceID string) (*MobileDevice, error) {
	if deviceID == "" {
		return nil, &ConfigError{Message: "touchque: Mobile.GetDevice needs the device id"}
	}
	res, err := m.http.get("/mobile/devices/" + url.PathEscape(deviceID))
	if err != nil {
		return nil, err
	}
	var out struct {
		Device MobileDevice `json:"device"`
	}
	return &out.Device, decodeInto(res, &out)
}

// RemoveDevice stops a device from approving (the user has no approver until you enrol again).
// It reports whether the device was the user's approver.
func (m *MobileResource) RemoveDevice(deviceID string) (bool, error) {
	if deviceID == "" {
		return false, &ConfigError{Message: "touchque: Mobile.RemoveDevice needs the device id"}
	}
	res, err := m.http.delete("/mobile/devices/" + url.PathEscape(deviceID))
	if err != nil {
		return false, err
	}
	linked, _ := res["wasLinked"].(bool)
	return linked, nil
}

// MobileTestPush says how a test push went: Via "touchque" (your key for the
// device's platform) or "webhook" (MOBILE_PUSH, kind "test"); OK when APNs /
// FCM accepted it (or the webhook left).
type MobileTestPush struct {
	Via    string `json:"via"`
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

// TestPush sends a harmless push to the device, the way a request would reach it.
func (m *MobileResource) TestPush(deviceID string) (*MobileTestPush, error) {
	if deviceID == "" {
		return nil, &ConfigError{Message: "touchque: Mobile.TestPush needs the device id"}
	}
	res, err := m.http.post("/mobile/devices/"+url.PathEscape(deviceID)+"/test-push", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	var out MobileTestPush
	return &out, decodeInto(res, &out)
}

// Settings reads your Mobile SDK settings (defaults when never set).
func (m *MobileResource) Settings() (*MobileSDKSettings, error) {
	res, err := m.http.get("/mobile/settings")
	if err != nil {
		return nil, err
	}
	var out struct {
		Settings MobileSDKSettings `json:"settings"`
	}
	return &out.Settings, decodeInto(res, &out)
}

// UpdateSettings changes only the keys given: iosAppIds, androidPackages,
// androidCerts (package → SHA-256 of its signing certificate),
// attestation (off | optional | required), enrollTtlSeconds, apns
// ({keyId, teamId, topic, key: the .p8 text, production}: TouchQue then sends
// the iOS push itself) and fcm ({serviceAccount: the JSON}: the Android push);
// nil removes a key.
func (m *MobileResource) UpdateSettings(changes map[string]interface{}) (*MobileSDKSettings, error) {
	for k := range changes {
		switch k {
		case "iosAppIds", "androidPackages", "androidCerts", "attestation", "enrollTtlSeconds", "apns", "fcm":
		default:
			return nil, &ConfigError{Message: "touchque: Mobile.UpdateSettings: unknown setting " + k}
		}
	}
	res, err := m.http.put("/mobile/settings", changes)
	if err != nil {
		return nil, err
	}
	var out struct {
		Settings MobileSDKSettings `json:"settings"`
	}
	return &out.Settings, decodeInto(res, &out)
}

// MobilePush is a MOBILE_PUSH webhook, ready to send with your own APNs / FCM credentials.
type MobilePush struct {
	DeviceID         string
	ExternalUsername string
	Platform         string
	// PushToken is the token your app handed to the SDK; empty: send to the
	// user's devices by your own mapping.
	PushToken string
	RequestID string
	ExpiresAt string
	Kind      string
	// Alert is suggested text (English); translate or replace it.
	Alert map[string]string
	// APNs is the APNs payload: the alert plus the custom key "touchque".
	APNs map[string]interface{}
	// FCMData is the FCM data map (a data message; your app builds the notification).
	FCMData map[string]string
}

// MobilePushFromWebhook turns a verified MOBILE_PUSH webhook into the push to
// send; ok is false for any other event. The data carries no secret, no
// details and no matching number.
func MobilePushFromWebhook(event map[string]interface{}) (push *MobilePush, ok bool) {
	if event == nil || event["event"] != "MOBILE_PUSH" {
		return nil, false
	}
	str := func(v interface{}) string { s, _ := v.(string); return s }
	data, _ := event["data"].(map[string]interface{})
	touchque := str(data["touchque"])
	if touchque == "" && data["touchque"] != nil {
		b, _ := json.Marshal(data["touchque"])
		touchque = string(b)
	}
	aps := map[string]interface{}{"sound": "default", "interruption-level": "time-sensitive"}
	var alert map[string]string
	if a, isMap := event["alert"].(map[string]interface{}); isMap {
		alert = map[string]string{"title": str(a["title"]), "body": str(a["body"])}
		aps["alert"] = alert
	}
	platform := "ios"
	if event["platform"] == "android" {
		platform = "android"
	}
	kind := "approval"
	if event["kind"] == "notice" || event["kind"] == "test" { // test: a test push sent from the dashboard
		kind = str(event["kind"])
	}
	return &MobilePush{
		DeviceID: str(event["deviceId"]), ExternalUsername: str(event["externalUsername"]), Platform: platform,
		PushToken: str(event["pushToken"]), RequestID: str(event["requestId"]), ExpiresAt: str(event["expiresAt"]), Kind: kind,
		Alert: alert, APNs: map[string]interface{}{"aps": aps, "touchque": touchque}, FCMData: map[string]string{"touchque": touchque},
	}, true
}

// Expired reports whether the push is past its request's expiry (don't send it any more).
func (p *MobilePush) Expired(now time.Time) bool {
	if p.ExpiresAt == "" {
		return false
	}
	at, err := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	return err == nil && !at.After(now)
}
