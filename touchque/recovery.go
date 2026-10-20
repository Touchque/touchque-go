package touchque

import (
	"context"
	"encoding/json"
	"net/url"
)

// RecoveryResource is Never Locked Out: move a user whose phone is lost, dead
// or replaced to a new phone without a help desk.
//
//  1. Let users name colleagues who can vouch for them (SetVouchers), behind
//     an approval on their phone.
//  2. When the phone is gone, after the password (or your IdP): Start. Show
//     BindURI as a QR for the TouchQue app on the new phone, then poll Status
//     and show each voucher's Code: the user reads it to the colleague on a
//     call, who types it on their own phone.
//  3. After the cooling-off nobody vetoed, the account is on the new phone
//     (Status == "COMPLETED"); critical actions wait 24 h (probation).
//
// Admins can stop a running recovery with Veto.
type RecoveryResource struct {
	http *httpClient
}

func newRecoveryResource(http *httpClient) *RecoveryResource {
	return &RecoveryResource{http: http}
}

// RecoveryVoucherEligibility says whether a named colleague can vouch today.
type RecoveryVoucherEligibility struct {
	ExternalUsername string `json:"externalUsername"`
	Eligible         bool   `json:"eligible"`
	// Reason why not: no_phone, no_hardware_key, keys_lost, frozen,
	// on_probation, same_phone.
	Reason string `json:"reason,omitempty"`
}

// RecoveryVouchers is a user's named vouchers.
type RecoveryVouchers struct {
	ExternalUsername string                       `json:"externalUsername"`
	Vouchers         []RecoveryVoucherEligibility `json:"vouchers"`
	UpdatedAt        string                       `json:"updatedAt,omitempty"`
	// ProbationUntil is set while the user's own account is on probation
	// after a vouch recovery.
	ProbationUntil string `json:"probationUntil,omitempty"`
}

// StartRecoveryOptions holds every POST /recovery/start field.
type StartRecoveryOptions struct {
	// ExternalUsername is the user in YOUR system. Required.
	ExternalUsername string
	// ClientIP is the user's address: the risk engine and the vouchers see it.
	ClientIP  string
	UserAgent string
	// DisplayName is how the vouchers know the user.
	DisplayName string
	// FallbackVouchers fill up a short named list, e.g. the organization's admins.
	FallbackVouchers []string
	// Required raises the floor of 2 vouchers; 0 keeps it.
	Required int
	// CoolOffMinutes raises the floor of 15 minutes (default 60); 0 keeps it.
	CoolOffMinutes int
	// Details is what the vouchers' phones show instead of the default English lines.
	Details []LoginDetail
	// NoticeDetails is what the old phone shows (approve to move now, reject
	// to stop) instead of the default English lines.
	NoticeDetails []LoginDetail
}

// RecoveryVoucherState is one voucher of a running recovery.
type RecoveryVoucherState struct {
	ExternalUsername string `json:"externalUsername"`
	Source           string `json:"source,omitempty"`
	// State: waiting, pending, approved, expired, unreachable.
	State string `json:"state"`
	// Code is the number this voucher must type, while their request is open.
	Code string `json:"code,omitempty"`
}

// RecoveryReceipt is one step of a recovery, hash-chained to the one before.
type RecoveryReceipt struct {
	Seq   int                    `json:"seq"`
	At    string                 `json:"at"`
	Step  string                 `json:"step"`
	Actor map[string]interface{} `json:"actor"`
	Data  map[string]interface{} `json:"data"`
	Prev  string                 `json:"prev,omitempty"`
	Hash  string                 `json:"hash"`
}

// Recovery is a recovery case.
type Recovery struct {
	RecoveryID       string `json:"recoveryId"`
	ExternalUsername string `json:"externalUsername"`
	Method           string `json:"method"`
	// Status: AWAITING_DEVICE, VOUCHING, COOLING, COMPLETED, VETOED, EXPIRED, FAILED.
	Status    string                 `json:"status"`
	Required  int                    `json:"required"`
	Approvals int                    `json:"approvals"`
	Vouchers  []RecoveryVoucherState `json:"vouchers"`
	OldPhone  struct {
		Notified bool   `json:"notified"`
		Code     string `json:"code,omitempty"`
	} `json:"oldPhone"`
	CoolOffMinutes int               `json:"coolOffMinutes"`
	CoolOffUntil   string            `json:"coolOffUntil,omitempty"`
	Elevated       bool              `json:"elevated"`
	Reasons        []string          `json:"reasons"`
	Location       string            `json:"location,omitempty"`
	NewPhoneBound  bool              `json:"newPhoneBound"`
	ExpiresAt      string            `json:"expiresAt,omitempty"`
	CompletedAt    string            `json:"completedAt,omitempty"`
	EndedReason    string            `json:"endedReason,omitempty"`
	EndedBy        string            `json:"endedBy,omitempty"`
	CreatedAt      string            `json:"createdAt,omitempty"`
	Receipts       []RecoveryReceipt `json:"receipts"`
	// BindCode and BindURI are set by Start only (shown once): show BindURI as a QR.
	BindCode string `json:"bindCode,omitempty"`
	BindURI  string `json:"bindUri,omitempty"`
}

// Open reports whether the recovery still waits for the new phone, the
// vouchers or the cooling-off.
func (r *Recovery) Open() bool {
	return r.Status == "AWAITING_DEVICE" || r.Status == "VOUCHING" || r.Status == "COOLING"
}

// remarshal decodes an answer into a typed struct.
func remarshal(in interface{}, out interface{}) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// Vouchers lists the colleagues a user named, and whether each can vouch today.
func (rr *RecoveryResource) Vouchers(ctx context.Context, externalUsername string) (*RecoveryVouchers, error) {
	if externalUsername == "" {
		return nil, &ConfigError{Message: "touchque: Recovery.Vouchers() needs the user (externalUsername)"}
	}
	res, err := rr.http.getWithQueryCtx(ctx, "/recovery/vouchers", map[string]string{"externalUsername": externalUsername})
	if err != nil {
		return nil, err
	}
	out := &RecoveryVouchers{}
	return out, remarshal(res, out)
}

// SetVouchers replaces the user's vouchers (at most 5 are kept). Ask for the
// user's phone first: whoever sets them chooses who may move the account.
func (rr *RecoveryResource) SetVouchers(ctx context.Context, externalUsername string, vouchers []string) (*RecoveryVouchers, error) {
	if externalUsername == "" {
		return nil, &ConfigError{Message: "touchque: Recovery.SetVouchers() needs the user (externalUsername)"}
	}
	if vouchers == nil {
		vouchers = []string{}
	}
	res, err := rr.http.postCtx(ctx, "/recovery/vouchers", map[string]interface{}{"externalUsername": externalUsername, "vouchers": vouchers})
	if err != nil {
		return nil, err
	}
	out := &RecoveryVouchers{}
	return out, remarshal(res, out)
}

// Start starts moving the user to a new phone. Call it only after the first
// factor. An *APIError with Code not_enough_vouchers, recovery_in_progress,
// blocked, frozen or rate_limited says why not.
func (rr *RecoveryResource) Start(ctx context.Context, opts StartRecoveryOptions) (*Recovery, error) {
	if opts.ExternalUsername == "" {
		return nil, &ConfigError{Message: "touchque: Recovery.Start() needs the user (ExternalUsername)"}
	}
	body := map[string]interface{}{"externalUsername": opts.ExternalUsername}
	if opts.ClientIP != "" {
		body["clientIp"] = opts.ClientIP
	}
	if opts.UserAgent != "" {
		body["userAgent"] = opts.UserAgent
	}
	if opts.DisplayName != "" {
		body["displayName"] = opts.DisplayName
	}
	if len(opts.FallbackVouchers) > 0 {
		body["fallbackVouchers"] = opts.FallbackVouchers
	}
	if opts.Required > 0 {
		body["required"] = opts.Required
	}
	if opts.CoolOffMinutes > 0 {
		body["coolOffMinutes"] = opts.CoolOffMinutes
	}
	if len(opts.Details) > 0 {
		body["details"] = opts.Details
	}
	if len(opts.NoticeDetails) > 0 {
		body["noticeDetails"] = opts.NoticeDetails
	}
	res, err := rr.http.postCtx(ctx, "/recovery/start", body)
	if err != nil {
		return nil, err
	}
	out := &Recovery{}
	return out, remarshal(res, out)
}

// Status returns the recovery now, with its receipt chain. Poll it while the user waits.
func (rr *RecoveryResource) Status(ctx context.Context, recoveryID string) (*Recovery, error) {
	if recoveryID == "" {
		return nil, &ConfigError{Message: "touchque: Recovery.Status() needs the recovery id"}
	}
	res, err := rr.http.getWithQueryCtx(ctx, "/recovery/"+url.PathEscape(recoveryID), nil)
	if err != nil {
		return nil, err
	}
	out := &Recovery{}
	return out, remarshal(res, out)
}

// List returns a user's recoveries, or (open) every running one of your workspace.
func (rr *RecoveryResource) List(ctx context.Context, externalUsername string, open bool) ([]Recovery, error) {
	if externalUsername == "" && !open {
		return nil, &ConfigError{Message: "touchque: Recovery.List() needs externalUsername or open"}
	}
	params := map[string]string{}
	if externalUsername != "" {
		params["externalUsername"] = externalUsername
	}
	if open {
		params["open"] = "true"
	}
	res, err := rr.http.getWithQueryCtx(ctx, "/recovery", params)
	if err != nil {
		return nil, err
	}
	var out struct {
		Recoveries []Recovery `json:"recoveries"`
	}
	if err := remarshal(res, &out); err != nil {
		return nil, err
	}
	if out.Recoveries == nil {
		out.Recoveries = []Recovery{}
	}
	return out.Recoveries, nil
}

// Veto stops a running recovery (e.g. an admin who does not believe it). It
// does not freeze the user. by is shown in the receipts; reason defaults to
// partner_veto.
func (rr *RecoveryResource) Veto(ctx context.Context, recoveryID, by, reason string) (*Recovery, error) {
	if recoveryID == "" {
		return nil, &ConfigError{Message: "touchque: Recovery.Veto() needs the recovery id"}
	}
	body := map[string]interface{}{}
	if by != "" {
		body["by"] = by
	}
	if reason != "" {
		body["reason"] = reason
	}
	res, err := rr.http.postCtx(ctx, "/recovery/"+url.PathEscape(recoveryID)+"/veto", body)
	if err != nil {
		return nil, err
	}
	out := &Recovery{}
	return out, remarshal(res, out)
}
