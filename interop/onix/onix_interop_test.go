package signvalidator

// Copied into pkg/plugin/implementation/signvalidator of a beckn-onix checkout by CI. It is not part of
// ONIX. It validates vectors signed by the eval workspace with ONIX's own validator and signs the same
// bodies with ONIX's own signer, writing both outcomes for interop/onix/crosscheck.py to compare.

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/beckn-one/beckn-onix/pkg/model"
	"github.com/beckn-one/beckn-onix/pkg/plugin/implementation/signer"
)

type vectors struct {
	SeedB64          string `json:"seed_b64"`
	PublicB64        string `json:"public_b64"`
	Created          int64  `json:"created"`
	Expires          int64  `json:"expires"`
	Body             string `json:"body"`
	AckBody          string `json:"ack_body"`
	Header           string `json:"header"`
	AckHeader        string `json:"ack_header"`
	RequestSignature string `json:"request_signature"`
}

type verdict struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

func verdictOf(err error) verdict {
	if err != nil {
		return verdict{false, err.Error()}
	}
	return verdict{true, ""}
}

func TestInteropWithEvalWorkspace(t *testing.T) {
	in, out := os.Getenv("ONIX_VECTORS"), os.Getenv("ONIX_RESULTS")
	if in == "" || out == "" {
		t.Skip("ONIX_VECTORS and ONIX_RESULTS not set")
	}
	raw, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	val, _, err := New(ctx, &Config{})
	if err != nil {
		t.Fatal(err)
	}
	body, ack := []byte(v.Body), []byte(v.AckBody)
	res := map[string]any{}
	res["validates_ours"] = verdictOf(val.Validate(&model.StepContext{Context: ctx, Body: body}, v.Header, v.PublicB64, false))
	res["validates_ours_ack"] = verdictOf(val.ValidateAck(&model.StepContext{Context: ctx, Body: ack}, ack, v.AckHeader, v.RequestSignature, v.PublicB64, false))
	sg, _, _ := signer.New(ctx, &signer.Config{})
	sig, err := sg.Sign(ctx, body, v.SeedB64, v.Created, v.Expires)
	if err != nil {
		t.Fatal(err)
	}
	asig, err := sg.SignAck(ctx, ack, v.RequestSignature, v.SeedB64, v.Created, v.Expires)
	if err != nil {
		t.Fatal(err)
	}
	res["signature"], res["ack_signature"] = sig, asig
	b, _ := json.MarshalIndent(res, "", "  ")
	if err := os.WriteFile(out, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
