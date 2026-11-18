package eehooks

import "testing"

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
