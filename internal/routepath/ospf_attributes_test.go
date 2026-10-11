package routepath

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/heymaikol/network-doctor/internal/netmodel"
)

// withOSPF is threeRouters with each router's control plane naming its link
// interface. area1 and area2 are the effective areas on r1 eth1 and r2 eth0,
// and an empty area leaves the attribute off. A declared end adds an intended
// neighbor on that interface, so the link is declared from that side.
func withOSPF(area1, area2 string, declared1, declared2 bool) []netmodel.Observation {
	obs := threeRouters()
	for i := range obs {
		if obs[i].Plane != netmodel.PlaneControl {
			continue
		}
		switch obs[i].Node {
		case "r1":
			obs[i].Interfaces = []netmodel.Interface{ospfIface(ifc("eth1", "10.0.12.1/30"), area1)}
		case "r2":
			obs[i].Interfaces = []netmodel.Interface{ospfIface(ifc("eth0", "10.0.12.2/30"), area2)}
		}
	}
	if declared1 {
		obs = append(obs, intended("r1", "eth1", "r2", "eth0", addr("10.0.12.2")))
	}
	if declared2 {
		obs = append(obs, intended("r2", "eth0", "r1", "eth1", addr("10.0.12.1")))
	}
	return obs
}

func ospfIface(i netmodel.Interface, area string) netmodel.Interface {
	if area != "" {
		i.Attributes = []netmodel.Attribute{{Key: "ospf.effective_area", Value: area}}
	}
	return i
}

func intended(node, iface, remote, remoteIface string, remoteAddr netip.Addr) netmodel.Observation {
	return netmodel.Observation{
		Provenance: netmodel.Provenance{Source: "intent:" + node, CollectedAt: t0},
		Plane:      netmodel.PlaneIntended,
		Node:       node,
		VRF:        "default",
		Neighbors: []netmodel.Neighbor{{
			LocalInterface:  iface,
			RemoteNode:      remote,
			RemoteInterface: remoteIface,
			RemoteAddr:      remoteAddr,
		}},
	}
}

// walkWithSource walks from r1 toward 10.20.40.8 with r1's address named as the
// source, so the explanation carries an asymmetry check as well as the forward path.
func walkWithSource(t *testing.T, obs []netmodel.Observation) Explanation {
	t.Helper()
	m, err := netmodel.New(obs...)
	if err != nil {
		t.Fatalf("netmodel.New: %v", err)
	}
	return Explain(File{Source: fromR1, Model: m, SourceAddr: addr("10.0.1.1")}, addr(dest))
}

// TestOSPFEvidenceDoesNotChangeTheRoutePath checks that an effective area, agreeing
// or not, and a declared link change nothing the walk reports. The OSPF analyzer
// reads that evidence. Routes are read from the control, configured, and FIB
// planes only.
func TestOSPFEvidenceDoesNotChangeTheRoutePath(t *testing.T) {
	want := walkWithSource(t, withOSPF("", "", false, false))
	if len(want.Forwarding.Next) == 0 {
		t.Fatal("baseline forwarding path is empty, so the comparison proves nothing")
	}
	if want.Asymmetry == nil {
		t.Fatal("baseline has no asymmetry, so the comparison proves nothing about it")
	}
	variants := []struct {
		name string
		obs  []netmodel.Observation
	}{
		{"areas agree on a declared link", withOSPF("0.0.0.0", "0.0.0.0", true, true)},
		{"areas differ on a declared link", withOSPF("0.0.0.0", "0.0.0.1", true, true)},
		{"one side declares the link", withOSPF("0.0.0.0", "0.0.0.1", true, false)},
		{"areas present without a declaration", withOSPF("0.0.0.0", "0.0.0.1", false, false)},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			got := walkWithSource(t, v.obs)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("explanation changed:\n got %+v\nwant %+v", got, want)
			}
		})
	}
}
