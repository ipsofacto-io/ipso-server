package eehooks

import (
	"context"
	"io"
	"testing"
)

func TestTheDefaultGateDeniesSAML(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	if Allow(FeatureSAML) {
		t.Fatal("sso.saml is allowed with no gate installed")
	}
	if Allow(FeatureTrackers) {
		t.Fatal("connectors.trackers is allowed with no gate installed")
	}
}

func TestANilGateDeniesEveryKey(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	SetGate(allowOne{feature: FeatureSAML})
	if !Allow(FeatureSAML) {
		t.Fatal("the test gate did not allow sso.saml")
	}
	SetGate(nil)
	if Allow(FeatureSAML) {
		t.Fatal("a nil gate allowed sso.saml")
	}
}

type allowOne struct{ feature string }

func (a allowOne) Allow(feature string) bool { return feature == a.feature }

func TestACommandIsFoundByName(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	if _, ok := Command("dataplane"); ok {
		t.Fatal("a command is registered in a fresh process")
	}
	RegisterCommand("dataplane", func(_ context.Context, args []string, getenv func(string) string, _ io.Writer) int {
		return len(args) + len(getenv("X"))
	})
	fn, ok := Command("dataplane")
	if !ok {
		t.Fatal("the command is not found")
	}
	if got := fn(context.Background(), []string{"a", "b"}, func(string) string { return "c" }, io.Discard); got != 3 {
		t.Fatalf("exit %d", got)
	}
	RegisterCommand("", func(context.Context, []string, func(string) string, io.Writer) int { return 0 })
	RegisterCommand("nothing", nil)
	for _, name := range []string{"", "nothing"} {
		if _, ok := Command(name); ok {
			t.Fatalf("%q was registered", name)
		}
	}
	ResetForTest()
	if _, ok := Command("dataplane"); ok {
		t.Fatal("ResetForTest kept a command")
	}
}
