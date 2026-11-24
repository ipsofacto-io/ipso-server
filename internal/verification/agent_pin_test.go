package verification

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestAgentPinSPKIAndLiveSignature(t *testing.T) {
	now := time.Date(2026, 11, 24, 15, 0, 0, 0, time.UTC)
	ts := now.Format(time.RFC3339)
	body := []byte(`{"check":"plan","report":{"report_version":2,"ipso_version":"0.1.0","evaluated_at":"2026-11-24T15:00:00Z","env":"prod","live":true,"build_sha256":"` +
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" +
		`","plan_sha256":"` +
		"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" +
		`","verdicts":[{"decision_id":"01J9Z000000000000000000001","slug":"deny-egress","check_index":0,"mode":"block","result":"pass","violations":0,"fingerprints":[]}]}}`)

	up, err := Parse(body)
	if err != nil {
		t.Fatalf("Parse live plan upload: %v", err)
	}
	if !up.Live || up.SourceKind != "live" {
		t.Fatalf("expected live source_kind, got Live=%v SourceKind=%q", up.Live, up.SourceKind)
	}

	// ECDSA P-256 round-trip
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER}))
	parsedDER, _, err := ParseSPKI(ecPEM)
	if err != nil {
		t.Fatalf("ParseSPKI ECDSA: %v", err)
	}
	sig, err := SignLivePayload(ecKey, ts, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyLivePayload(parsedDER, ts, sig, body, now); err != nil {
		t.Fatalf("VerifyLivePayload ECDSA: %v", err)
	}
	if err := VerifyLivePayload(parsedDER, ts, sig, append(body, ' '), now); err == nil {
		t.Fatal("expected tampered body to fail verification")
	}
	if err := VerifyLivePayload(parsedDER, ts, sig, body, now.Add(10*time.Minute)); err == nil {
		t.Fatal("expected stale timestamp to fail verification")
	}

	// Ed25519 round-trip
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edDER, err := x509.MarshalPKIXPublicKey(edPub)
	if err != nil {
		t.Fatal(err)
	}
	edPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: edDER}))
	parsedEdDER, _, err := ParseSPKI(edPEM)
	if err != nil {
		t.Fatalf("ParseSPKI Ed25519: %v", err)
	}
	edSig, err := SignLivePayload(edPriv, ts, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyLivePayload(parsedEdDER, ts, edSig, body, now); err != nil {
		t.Fatalf("VerifyLivePayload Ed25519: %v", err)
	}
}

func TestParseLLMReportUpload(t *testing.T) {
	body := []byte(`{"check":"llm","report":{"report_version":3,"ipso_version":"0.1.0","evaluated_at":"2026-11-24T15:00:00Z","env":"prod","live":true,"build_sha256":"` +
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" +
		`","input_sha256":"` +
		"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" +
		`","target":"json-snapshot","model_id":"mistral-large-eu","prompt_version":"llm-check-v1","verdicts":[{"decision_id":"01J9Z000000000000000000001","slug":"deny-egress","check_index":0,"mode":"block","result":"fail","violations":1,"fingerprints":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}]}}`)
	up, err := Parse(body)
	if err != nil {
		t.Fatalf("Parse llm upload: %v", err)
	}
	if up.Check != "llm" || up.SourceKind != "live" || len(up.Verdicts) != 1 {
		t.Fatalf("unexpected upload: %+v", up)
	}
	if up.Verdicts[0].ModelID != "mistral-large-eu" || up.Verdicts[0].PromptVersion != "llm-check-v1" {
		t.Fatalf("expected inherited model metadata, got %+v", up.Verdicts[0])
	}
}
