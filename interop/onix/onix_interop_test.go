package signvalidator

// Copied into pkg/plugin/implementation/signvalidator of a beckn-onix checkout by CI. It is not part of
// ONIX. It validates vectors signed by the eval workspace with ONIX's own validator and signs the same
// bodies with ONIX's own signer, writing both outcomes for interop/onix/crosscheck.py to compare.
// Only the plugin functions are called: no HTTP, key lookup or identity check (checkIdentity=false).

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/beckn-one/beckn-onix/pkg/model"
	"github.com/beckn-one/beckn-onix/pkg/plugin/implementation/signer"
)

type vcase struct {
	Name             string  `json:"name"`
	Body             string  `json:"body"`
	AckBody          string  `json:"ack_body"`
	Header           string  `json:"header"`
	AckHeader        *string `json:"ack_header"`
	RequestSignature string  `json:"request_signature"`
	Sign             bool    `json:"sign"`
	Created          int64   `json:"created"`
	Expires          int64   `json:"expires"`
}

type vectors struct {
	SeedB64   string  `json:"seed_b64"`
	PublicB64 string  `json:"public_b64"`
	Cases     []vcase `json:"cases"`
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
	sg, _, err := signer.New(ctx, &signer.Config{})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]any{}
	for _, c := range v.Cases {
		body, ack := []byte(c.Body), []byte(c.AckBody)
		res := map[string]any{
			"validates_ours": verdictOf(val.Validate(&model.StepContext{Context: ctx, Body: body}, c.Header, v.PublicB64, false)),
		}
		if c.AckHeader != nil {
			res["validates_ours_ack"] = verdictOf(val.ValidateAck(&model.StepContext{Context: ctx, Body: ack}, ack, *c.AckHeader, c.RequestSignature, v.PublicB64, false))
		}
		if c.Sign {
			sig, err := sg.Sign(ctx, body, v.SeedB64, c.Created, c.Expires)
			if err != nil {
				t.Fatal(err)
			}
			asig, err := sg.SignAck(ctx, ack, c.RequestSignature, v.SeedB64, c.Created, c.Expires)
			if err != nil {
				t.Fatal(err)
			}
			res["signature"], res["ack_signature"] = sig, asig
		}
		cases[c.Name] = res
	}
	b, _ := json.MarshalIndent(map[string]any{"cases": cases}, "", "  ")
	if err := os.WriteFile(out, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
