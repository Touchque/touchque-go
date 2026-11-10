package touchque

// Safe Guard approvals, checked without trusting TouchQue. The approver's
// phone decodes the raw Safe transaction itself and signs, with a P-256 key
// only its biometrics unlock, a 105-byte approval that TouchQueSafeGuard
// checks on chain:
//
//	index (1) | expiresAt (8) | displayDigest (32) | r (32) | s (32)
//
// over the SHA-256 of the 149-byte message
//
//	"TQG1" | purpose (1) | chainId (32) | guard (20) | Safe (20) | subject (32) | expiresAt (8) | displayDigest (32)
//
// where subject is the Safe transaction hash (EIP-712, purpose 1 "approve")
// or, for a change the guard schedules, the governance hash (purpose 2
// "schedule"). VerifySafeApproval makes the guard's check off chain: both
// hashes are computed here from the raw fields, so a co-signer (or your own
// server) refuses an approval of anything else, whoever relayed it. It accepts
// a schedule approval only when you ask for one: the governance hash has no
// Safe nonce and on chain it only starts the waiting time.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"math/bits"
	"regexp"
	"sort"
	"strings"
	"time"
)

// SafeTxCall is a Safe transaction: the fields the owners sign (Safe v1.3+
// EIP-712 SafeTx). Integers are decimal strings ("" = 0); Data is 0x hex
// ("" = 0x); GasToken and RefundReceiver default to the zero address.
type SafeTxCall struct {
	To             string `json:"to"`
	Value          string `json:"value,omitempty"`
	Data           string `json:"data,omitempty"`
	Operation      int    `json:"operation"`
	SafeTxGas      string `json:"safeTxGas,omitempty"`
	BaseGas        string `json:"baseGas,omitempty"`
	GasPrice       string `json:"gasPrice,omitempty"`
	GasToken       string `json:"gasToken,omitempty"`
	RefundReceiver string `json:"refundReceiver,omitempty"`
	Nonce          string `json:"nonce"`
}

// SafeTxTarget is where the transaction runs: what the approval hashes cover.
// ChainID is a decimal string; Guard is the TouchQueSafeGuard on the Safe.
type SafeTxTarget struct {
	ChainID string     `json:"chainId"`
	Safe    string     `json:"safe"`
	Guard   string     `json:"guard"`
	Tx      SafeTxCall `json:"tx"`
}

// SafeDisplayRow is one row the phone showed, in order.
type SafeDisplayRow struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// SafeApprovalMessageFields are the parts of the message the phone signs.
// Purpose is "approve" or "schedule"; Subject the Safe transaction hash or the
// governance hash; ExpiresAt Unix seconds.
type SafeApprovalMessageFields struct {
	Purpose       string
	ChainID       string
	Guard         string
	Safe          string
	Subject       string
	ExpiresAt     uint64
	DisplayDigest string
}

// VerifySafeApprovalOptions narrows what VerifySafeApproval accepts.
type VerifySafeApprovalOptions struct {
	// Purpose you expect ("approve" or "schedule"). Empty means "approve"
	// only: name "schedule" to accept an approval of a governance change,
	// which covers no Safe nonce and is never permission to execute.
	Purpose string
	// ApproverIndex is the approver's index in the guard: the approval must name it.
	ApproverIndex *int
	// DisplayDigest of the rows the phone must have shown (from your own
	// decoding), or the Rows themselves.
	DisplayDigest string
	Rows          []SafeDisplayRow
	// Now is the time to check the expiry against (zero: now).
	Now time.Time
}

// SafeApprovalVerification is VerifySafeApproval's verdict. Reason is "" when
// valid, else approval_malformed, public_key_invalid, approver_index_mismatch,
// approval_expired, rows_differ, high_s or signature_invalid. ApproverIndex,
// ExpiresAt (Unix seconds) and DisplayDigest are set once the approval parsed.
type SafeApprovalVerification struct {
	Valid          bool
	Reason         string
	Purpose        string
	ApproverIndex  int
	ExpiresAt      uint64
	DisplayDigest  string
	SafeTxHash     string
	GovernanceHash string
}

var (
	safeMagic          = []byte("TQG1")
	safePurposes       = map[string]byte{"approve": 1, "schedule": 2}
	safeAddressRe      = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	safeHexRe          = regexp.MustCompile(`^0x([0-9a-fA-F]{2})*$`)
	safeDecimalRe      = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	safeApprovalRe     = regexp.MustCompile(`^(0x)?[0-9a-fA-F]{210}$`)
	safeKeyRe          = regexp.MustCompile(`^[0-9a-fA-F]{128}$`)
	safeHalfN, _       = new(big.Int).SetString("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8", 16)
	safeMaxUint256     = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	safeMaxUint64      = new(big.Int).SetUint64(^uint64(0))
	safeDomainTypeHash = keccak256([]byte("EIP712Domain(uint256 chainId,address verifyingContract)"))
	safeTxTypeHash     = keccak256([]byte("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"))
	safeGovTypeHash    = keccak256([]byte("TouchQueGovernance(uint256 chainId,address safe,address to,uint256 value,bytes32 dataHash,uint8 operation)"))
	safeScheduleSel    = keccak256([]byte("schedule(address,bytes32,bytes)"))[:4]
)

// The guard (MAX_APPROVAL_TTL) refuses an approval valid for longer than a day.
const safeMaxApprovalTTL = 86400

// ── Keccak-256 (the Ethereum hash: Keccak padding, not SHA3-256) ──

var keccakRC = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009, 0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
	0x000000000000800a, 0x800000008000000a, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

// Rotation of lane x + 5y.
var keccakRot = [25]int{0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14}

func keccakF(a *[25]uint64) {
	var c [5]uint64
	var b [25]uint64
	for _, rc := range keccakRC {
		for x := 0; x < 5; x++ {
			c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20]
		}
		for x := 0; x < 5; x++ {
			d := c[(x+4)%5] ^ bits.RotateLeft64(c[(x+1)%5], 1)
			for y := 0; y < 25; y += 5 {
				a[x+y] ^= d
			}
		}
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				b[y+5*((2*x+3*y)%5)] = bits.RotateLeft64(a[x+5*y], keccakRot[x+5*y])
			}
		}
		for y := 0; y < 25; y += 5 {
			for x := 0; x < 5; x++ {
				a[x+y] = b[x+y] ^ (^b[(x+1)%5+y] & b[(x+2)%5+y])
			}
		}
		a[0] ^= rc
	}
}

func keccak256(data []byte) []byte {
	const rate = 136
	padded := make([]byte, len(data)/rate*rate+rate)
	copy(padded, data)
	padded[len(data)] ^= 0x01
	padded[len(padded)-1] ^= 0x80
	var a [25]uint64
	for off := 0; off < len(padded); off += rate {
		for k := 0; k < rate/8; k++ {
			a[k] ^= binary.LittleEndian.Uint64(padded[off+8*k:])
		}
		keccakF(&a)
	}
	out := make([]byte, 32)
	for k := 0; k < 4; k++ {
		binary.LittleEndian.PutUint64(out[8*k:], a[k])
	}
	return out
}

// ── Field parsing: the partner's own data, so a wrong field is an error ──

type safeFields struct {
	chainID, value, safeTxGas, baseGas, gasPrice, nonce []byte
	safe, guard, to, gasToken, refundReceiver           []byte
	data                                                []byte
	operation                                           byte
}

func safeConfigError(msg string) error { return &ConfigError{Message: "touchque: safe guard: " + msg} }

func safeUint(value, field string, max *big.Int) ([]byte, error) {
	if value == "" {
		value = "0"
	}
	v, ok := new(big.Int).SetString(value, 10)
	if !safeDecimalRe.MatchString(value) || !ok || v.Cmp(max) > 0 {
		return nil, safeConfigError(field + " must be a non-negative integer as a decimal string")
	}
	return v.FillBytes(make([]byte, 32)), nil
}

func safeAddress(value, field string) ([]byte, error) {
	if !safeAddressRe.MatchString(value) {
		return nil, safeConfigError(field + " must be an address (0x and 40 hex characters)")
	}
	b, _ := hex.DecodeString(value[2:])
	return append(make([]byte, 12), b...), nil
}

func safeHex(value, field string, size int) ([]byte, error) {
	if !safeHexRe.MatchString(value) || (size >= 0 && len(value) != 2+2*size) {
		return nil, safeConfigError(field + " must be 0x-prefixed hex")
	}
	b, _ := hex.DecodeString(value[2:])
	return b, nil
}

func parseSafeTarget(t SafeTxTarget) (*safeFields, error) {
	var f safeFields
	var err error
	if t.Tx.Operation != 0 && t.Tx.Operation != 1 {
		return nil, safeConfigError("tx.operation must be 0 (call) or 1 (delegatecall)")
	}
	f.operation = byte(t.Tx.Operation)
	data, gasToken, refund := t.Tx.Data, t.Tx.GasToken, t.Tx.RefundReceiver
	if data == "" {
		data = "0x"
	}
	if gasToken == "" {
		gasToken = "0x0000000000000000000000000000000000000000"
	}
	if refund == "" {
		refund = "0x0000000000000000000000000000000000000000"
	}
	if t.Tx.Nonce == "" {
		return nil, safeConfigError("tx.nonce is required")
	}
	for _, u := range []struct {
		dst        *[]byte
		value, key string
		max        *big.Int
	}{
		{&f.chainID, t.ChainID, "chainId", safeMaxUint64}, {&f.value, t.Tx.Value, "tx.value", safeMaxUint256},
		{&f.safeTxGas, t.Tx.SafeTxGas, "tx.safeTxGas", safeMaxUint256}, {&f.baseGas, t.Tx.BaseGas, "tx.baseGas", safeMaxUint256},
		{&f.gasPrice, t.Tx.GasPrice, "tx.gasPrice", safeMaxUint256}, {&f.nonce, t.Tx.Nonce, "tx.nonce", safeMaxUint256},
	} {
		if *u.dst, err = safeUint(u.value, u.key, u.max); err != nil {
			return nil, err
		}
	}
	for _, a := range []struct {
		dst        *[]byte
		value, key string
	}{
		{&f.safe, t.Safe, "safe"}, {&f.guard, t.Guard, "guard"}, {&f.to, t.Tx.To, "tx.to"},
		{&f.gasToken, gasToken, "tx.gasToken"}, {&f.refundReceiver, refund, "tx.refundReceiver"},
	} {
		if *a.dst, err = safeAddress(a.value, a.key); err != nil {
			return nil, err
		}
	}
	if f.data, err = safeHex(data, "tx.data", -1); err != nil {
		return nil, err
	}
	return &f, nil
}

func safeWord(b byte) []byte { w := make([]byte, 32); w[31] = b; return w }

func concat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// SafeTxHash is the Safe transaction hash (EIP-712, domain = chainId + the
// Safe): what the owners sign and an ordinary approval covers.
func SafeTxHash(t SafeTxTarget) (string, error) {
	f, err := parseSafeTarget(t)
	if err != nil {
		return "", err
	}
	domain := keccak256(concat(safeDomainTypeHash, f.chainID, f.safe))
	structHash := keccak256(concat(safeTxTypeHash, f.to, f.value, keccak256(f.data), safeWord(f.operation), f.safeTxGas,
		f.baseGas, f.gasPrice, f.gasToken, f.refundReceiver, f.nonce))
	return "0x" + hex.EncodeToString(keccak256(concat([]byte{0x19, 0x01}, domain, structHash))), nil
}

// SafeGovernanceHash is what the guard schedules a governance change under:
// the change itself, without the nonce or gas fields.
func SafeGovernanceHash(t SafeTxTarget) (string, error) {
	f, err := parseSafeTarget(t)
	if err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(keccak256(concat(safeGovTypeHash, f.chainID, f.safe, f.to, f.value, keccak256(f.data), safeWord(f.operation)))), nil
}

// SafeApprovalMessage is the 149-byte message the phone signs (its SHA-256 is
// what the guard verifies), as 0x hex.
func SafeApprovalMessage(m SafeApprovalMessageFields) (string, error) {
	purpose, ok := safePurposes[m.Purpose]
	if !ok {
		return "", safeConfigError(`purpose is "approve" or "schedule"`)
	}
	chainID, err := safeUint(m.ChainID, "chainId", safeMaxUint64)
	if err != nil {
		return "", err
	}
	guard, err := safeAddress(m.Guard, "guard")
	if err != nil {
		return "", err
	}
	safe, err := safeAddress(m.Safe, "safe")
	if err != nil {
		return "", err
	}
	subject, err := safeHex(m.Subject, "subject", 32)
	if err != nil {
		return "", err
	}
	digest, err := safeHex(m.DisplayDigest, "displayDigest", 32)
	if err != nil {
		return "", err
	}
	expires := binary.BigEndian.AppendUint64(nil, m.ExpiresAt)
	return "0x" + hex.EncodeToString(concat(safeMagic, []byte{purpose}, chainID, guard[12:], safe[12:], subject, expires, digest)), nil
}

// SafeDisplayDigest is the SHA-256 of the rows as "label\x1Fvalue" joined by
// "\x1E" (UTF-8), as 0x hex: the digest an approval carries.
func SafeDisplayDigest(rows []SafeDisplayRow) string {
	parts := make([]string, len(rows))
	for i, r := range rows {
		parts[i] = r.Label + "\x1f" + r.Value
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1e")))
	return "0x" + hex.EncodeToString(sum[:])
}

// VerifySafeApproval checks a phone's Safe Guard approval the way
// TouchQueSafeGuard does, without trusting the server that relayed it: the
// Safe and governance hashes come from t, the key from the guard's approver
// list on chain (x || y, 128 hex characters). The error is set only when t is
// not a Safe transaction; a refused approval is a verdict. Without
// opts.Purpose only an ordinary approval ("approve") is valid; pass
// Purpose "schedule" to check one for a governance change you will schedule.
//
//	status, _ := client.SafeGuard.Status(ctx, requestID)
//	check, err := touchque.VerifySafeApproval(myTx, status.SafeTx.Approval, approverKeyFromChain, touchque.VerifySafeApprovalOptions{ApproverIndex: &index})
//	if err != nil || !check.Valid { ... refuse ... }
func VerifySafeApproval(t SafeTxTarget, approval, publicKey string, opts VerifySafeApprovalOptions) (*SafeApprovalVerification, error) {
	f, err := parseSafeTarget(t)
	if err != nil {
		return nil, err
	}
	safeTxHash, _ := SafeTxHash(t)
	govHash, _ := SafeGovernanceHash(t)
	v := &SafeApprovalVerification{SafeTxHash: safeTxHash, GovernanceHash: govHash}
	refuse := func(reason string) (*SafeApprovalVerification, error) { v.Reason = reason; return v, nil }
	if !safeApprovalRe.MatchString(approval) {
		return refuse("approval_malformed")
	}
	b, _ := hex.DecodeString(strings.TrimPrefix(approval, "0x"))
	v.ApproverIndex = int(b[0])
	v.ExpiresAt = binary.BigEndian.Uint64(b[1:9])
	v.DisplayDigest = "0x" + hex.EncodeToString(b[9:41])
	xy := strings.TrimPrefix(publicKey, "0x")
	if !safeKeyRe.MatchString(xy) {
		return refuse("public_key_invalid")
	}
	raw, _ := hex.DecodeString("04" + xy)
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return refuse("public_key_invalid")
	}
	if opts.ApproverIndex != nil && *opts.ApproverIndex != v.ApproverIndex {
		return refuse("approver_index_mismatch")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	seconds := now.Unix()
	if seconds < 0 || v.ExpiresAt < uint64(seconds) || v.ExpiresAt > uint64(seconds)+safeMaxApprovalTTL {
		return refuse("approval_expired")
	}
	expected := opts.DisplayDigest
	if expected == "" && opts.Rows != nil {
		expected = SafeDisplayDigest(opts.Rows)
	}
	if expected != "" && "0x"+strings.TrimPrefix(strings.ToLower(expected), "0x") != v.DisplayDigest {
		return refuse("rows_differ")
	}
	r := new(big.Int).SetBytes(b[41:73])
	s := new(big.Int).SetBytes(b[73:105])
	if s.Cmp(safeHalfN) > 0 {
		return refuse("high_s")
	}
	purpose := opts.Purpose
	if purpose == "" {
		purpose = "approve"
	}
	subject := safeTxHash
	if purpose == "schedule" {
		subject = govHash
	}
	message, err := SafeApprovalMessage(SafeApprovalMessageFields{
		Purpose: purpose, ChainID: new(big.Int).SetBytes(f.chainID).String(), Guard: "0x" + hex.EncodeToString(f.guard[12:]),
		Safe: "0x" + hex.EncodeToString(f.safe[12:]), Subject: subject, ExpiresAt: v.ExpiresAt, DisplayDigest: v.DisplayDigest,
	})
	if err != nil {
		return nil, err
	}
	signed, _ := hex.DecodeString(message[2:])
	digest := sha256.Sum256(signed)
	if !ecdsa.Verify(key, digest[:], r, s) {
		return refuse("signature_invalid")
	}
	v.Valid, v.Purpose = true, purpose
	return v, nil
}

func safeApprovalBytes(approvals []string) ([][]byte, error) {
	if len(approvals) < 1 || len(approvals) > 255 {
		return nil, safeConfigError("pass 1 to 255 approvals")
	}
	out := make([][]byte, len(approvals))
	for i, a := range approvals {
		if !strings.HasPrefix(a, "0x") {
			a = "0x" + a
		}
		b, err := safeHex(a, "approvals", 105)
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out, nil
}

// WithSafeApprovals is the owners' Safe signatures with the approvals appended
// (approvals by index | count | "TQG1"): the signatures argument of
// execTransaction for an ordinary transaction.
func WithSafeApprovals(ownerSignatures string, approvals []string) (string, error) {
	owners, err := safeHex(ownerSignatures, "ownerSignatures", -1)
	if err != nil {
		return "", err
	}
	items, err := safeApprovalBytes(approvals)
	if err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(concat(owners, bytes.Join(items, nil), []byte{byte(len(items))}, safeMagic)), nil
}

// SafeScheduleCall is the call data of guard.schedule(safe, governanceHash,
// approvals), which starts a governance change's waiting time.
func SafeScheduleCall(safe, governanceHash string, approvals []string) (string, error) {
	safeWordBytes, err := safeAddress(safe, "safe")
	if err != nil {
		return "", err
	}
	gov, err := safeHex(governanceHash, "governanceHash", 32)
	if err != nil {
		return "", err
	}
	items, err := safeApprovalBytes(approvals)
	if err != nil {
		return "", err
	}
	joined := bytes.Join(items, nil)
	length := new(big.Int).SetInt64(int64(len(joined))).FillBytes(make([]byte, 32))
	padding := make([]byte, (32-len(joined)%32)%32)
	return "0x" + hex.EncodeToString(concat(safeScheduleSel, safeWordBytes, gov, safeWord(96), length, joined, padding)), nil
}
