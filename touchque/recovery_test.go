package touchque

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Never Locked Out against the shared fake API: vouchers, start, status,
// list and veto. Same scenarios as the Node SDK's Recovery tests.

func recoveryAPI(t *testing.T) (*fakeAPI, *Client) {
	api := startFakeAPI(t)
	for _, u := range []string{"ada@acme.com", "bo@acme.com", "cy@acme.com"} {
		api.link(u)
	}
	return api, api.client(t)
}

func TestRecoveryVouchersSayWhoCanVouch(t *testing.T) {
	_, tq := recoveryAPI(t)
	out, err := tq.Recovery.SetVouchers(context.Background(), "ada@acme.com", []string{"bo@acme.com", "zed@acme.com"})
	if err != nil {
		t.Fatal(err)
	}
	want := []RecoveryVoucherEligibility{{ExternalUsername: "bo@acme.com", Eligible: true}, {ExternalUsername: "zed@acme.com", Reason: "no_phone"}}
	if !reflect.DeepEqual(out.Vouchers, want) {
		t.Fatalf("vouchers = %+v", out.Vouchers)
	}
	got, err := tq.Recovery.Vouchers(context.Background(), "ada@acme.com")
	if err != nil || got.Vouchers[0].ExternalUsername != "bo@acme.com" {
		t.Fatalf("Vouchers() = %+v, %v", got, err)
	}
}

func TestRecoveryStartsWithAQrAndMovesOn(t *testing.T) {
	api, tq := recoveryAPI(t)
	ctx := context.Background()
	if _, err := tq.Recovery.SetVouchers(ctx, "ada@acme.com", []string{"bo@acme.com", "cy@acme.com"}); err != nil {
		t.Fatal(err)
	}
	r, err := tq.Recovery.Start(ctx, StartRecoveryOptions{ExternalUsername: "ada@acme.com", ClientIP: "203.0.113.7", DisplayName: "Ada", CoolOffMinutes: 90})
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "AWAITING_DEVICE" || !strings.HasPrefix(r.BindURI, "touchque://recover?id=") {
		t.Fatalf("start = %+v", r)
	}
	calls := api.calls()
	body := calls[len(calls)-1]["body"].(map[string]interface{})
	if !reflect.DeepEqual(body, map[string]interface{}{"externalUsername": "ada@acme.com", "clientIp": "203.0.113.7", "displayName": "Ada", "coolOffMinutes": float64(90)}) {
		t.Fatalf("start body = %v", body)
	}
	api.recovery("VOUCHING")
	now, err := tq.Recovery.Status(ctx, r.RecoveryID)
	if err != nil || !now.Open() || now.Vouchers[0].Code != "11" || now.Vouchers[1].Code != "12" {
		t.Fatalf("status = %+v, %v", now, err)
	}
	api.recovery("COMPLETED")
	if now, _ = tq.Recovery.Status(ctx, r.RecoveryID); now.Status != "COMPLETED" || now.Open() {
		t.Fatalf("status = %+v", now)
	}
	list, err := tq.Recovery.List(ctx, "ada@acme.com", false)
	if err != nil || len(list) != 1 || list[0].RecoveryID != r.RecoveryID {
		t.Fatalf("list = %+v, %v", list, err)
	}
}

func TestRecoveryVetoAndTooFewVouchers(t *testing.T) {
	_, tq := recoveryAPI(t)
	ctx := context.Background()
	_, err := tq.Recovery.Start(ctx, StartRecoveryOptions{ExternalUsername: "ada@acme.com"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 409 || apiErr.Code != "not_enough_vouchers" {
		t.Fatalf("err = %v", err)
	}
	r, err := tq.Recovery.Start(ctx, StartRecoveryOptions{ExternalUsername: "ada@acme.com", FallbackVouchers: []string{"bo@acme.com", "cy@acme.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if open, _ := tq.Recovery.List(ctx, "", true); len(open) != 1 {
		t.Fatalf("open = %+v", open)
	}
	v, err := tq.Recovery.Veto(ctx, r.RecoveryID, "admin@acme.com", "")
	if err != nil || v.Status != "VETOED" || v.EndedBy != "admin@acme.com" {
		t.Fatalf("veto = %+v, %v", v, err)
	}
	if _, err := tq.Recovery.Veto(ctx, r.RecoveryID, "", ""); err == nil {
		t.Fatal("a second veto should fail")
	}
	if open, _ := tq.Recovery.List(ctx, "", true); len(open) != 0 {
		t.Fatalf("open = %+v", open)
	}
}

func TestRecoveryMissingArgumentsFailBeforeAnyRequest(t *testing.T) {
	api, tq := recoveryAPI(t)
	ctx := context.Background()
	var cfg *ConfigError
	for _, err := range []error{
		func() error { _, e := tq.Recovery.Start(ctx, StartRecoveryOptions{}); return e }(),
		func() error { _, e := tq.Recovery.Status(ctx, ""); return e }(),
		func() error { _, e := tq.Recovery.List(ctx, "", false); return e }(),
		func() error { _, e := tq.Recovery.Veto(ctx, "", "", ""); return e }(),
	} {
		if !errors.As(err, &cfg) {
			t.Fatalf("err = %v", err)
		}
	}
	if len(api.calls()) != 0 {
		t.Fatal("no request expected")
	}
}
