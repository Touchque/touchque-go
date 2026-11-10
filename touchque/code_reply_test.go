package touchque

import "testing"

// A code typed back on the phone against the shared fake API, which seals it
// like the phone does: it opens only with the one-time key, for that request.
func TestCodeReplyOpensOnlyWithTheOneTimeKeyForThatRequest(t *testing.T) {
	api := startFakeAPI(t)
	api.link("ayse@acme.com")
	c := api.client(t)

	key, err := NewCodeReplyKey()
	if err != nil {
		t.Fatal(err)
	}
	sent, err := c.Login.RequestWithOptions(LoginRequestOptions{ExternalUsername: "ayse@acme.com", Type: "LOGIN",
		Reply: &LoginReplyRequest{Kind: "code", Key: key.PublicKey, Channel: "sms", Target: "+**********26"}})
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := c.Login.Status(sent.RequestID); st.Reply != nil {
		t.Fatalf("no reply before the phone answers, got %+v", st.Reply)
	}
	api.call("/__test/approve", map[string]interface{}{"id": sent.RequestID, "replyCode": "482 913"})
	st, err := c.Login.Status(sent.RequestID)
	if err != nil || st.Reply == nil {
		t.Fatalf("expected a reply, got %+v (%v)", st, err)
	}
	if code, ok := OpenCodeReply(key.PrivateKey, sent.RequestID, st.Reply.CT); !ok || code != "482 913" {
		t.Fatalf("expected the typed code, got %q %v", code, ok)
	}
	other, _ := NewCodeReplyKey()
	for _, tc := range []struct{ priv, rid, ct string }{
		{key.PrivateKey, "another-request", st.Reply.CT},
		{other.PrivateKey, sent.RequestID, st.Reply.CT},
		{key.PrivateKey, sent.RequestID, "v1.bad.ct"},
	} {
		if _, ok := OpenCodeReply(tc.priv, tc.rid, tc.ct); ok {
			t.Fatalf("expected no code for %+v", tc)
		}
	}
}
