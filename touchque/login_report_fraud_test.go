package touchque

import "testing"

func TestReportFraud(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	c := api.client(t)
	req, err := c.Login.RequestWithOptions(LoginRequestOptions{ExternalUsername: "jane@acme.com", Type: "LOGIN"})
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	res, err := c.Login.ReportFraud(req.RequestID, ReportFraudOptions{Reason: FraudChargeback, Note: "Disputed by card holder"})
	if err != nil {
		t.Fatalf("ReportFraud: %v", err)
	}
	if !res.Reported || res.AlreadyReported || res.RequestID != req.RequestID {
		t.Fatalf("unexpected first report: %+v", res)
	}
	again, err := c.Login.ReportFraud(req.RequestID, ReportFraudOptions{})
	if err != nil || !again.AlreadyReported {
		t.Fatalf("repeat should answer alreadyReported, got %+v, %v", again, err)
	}
	if _, err := c.Login.ReportFraud(req.RequestID, ReportFraudOptions{Reason: "because"}); apiStatus(err) != 400 {
		t.Fatalf("invalid reason should be 400, got %v", err)
	}
	if _, err := c.Login.ReportFraud("unknown-id", ReportFraudOptions{}); apiStatus(err) != 404 {
		t.Fatalf("unknown request should be 404, got %v", err)
	}
	if _, err := c.Login.ReportFraud("", ReportFraudOptions{}); err == nil {
		t.Fatal("empty id must fail locally")
	}
}
