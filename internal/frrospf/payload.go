package frrospf

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
)

// detailRecord is one neighbor entry from show ip ospf neighbor detail json.
// Pointers tell a missing key from a present one. A value of the wrong JSON
// type fails the whole capture, because the schema is strict on types.
type detailRecord struct {
	IfaceAddress      *string `json:"ifaceAddress"`
	AreaID            *string `json:"areaId"`
	IfaceName         *string `json:"ifaceName"`
	LocalIfaceAddress *string `json:"localIfaceAddress"`
	NbrState          *string `json:"nbrState"`
}

// detailPayload is the top level of show ip ospf neighbor detail json. The
// neighbors map is keyed by router ID. FRR uses the placeholder key noNbrId for
// a neighbor whose router ID is not known yet. Each list is a pointer, so a null
// list is told apart from an empty one.
type detailPayload struct {
	Neighbors *map[string]*[]detailRecord `json:"neighbors"`
}

// maxEntries bounds the neighbor records or interfaces in one capture. Real FRR
// output holds far fewer. The bound keeps a hostile capture from multiplying a
// 1 MiB input into a much larger working set.
const maxEntries = 4096

// interfaceRecord is one entry from show ip ospf interface json. Other keys are
// not read here.
type interfaceRecord struct {
	IPAddress          *string `json:"ipAddress"`
	IPAddressPrefixlen *int    `json:"ipAddressPrefixlen"`
	RouterID           *string `json:"routerId"`
	Area               *string `json:"area"`
}

// interfacePayload is the top level of show ip ospf interface json, keyed by
// interface name.
type interfacePayload struct {
	Interfaces *map[string]interfaceRecord `json:"interfaces"`
}

// noNbrID is the placeholder FRR uses in the detail form when a neighbor has no
// router ID yet. It is a real state FRR reports, not an error, so the record is
// kept and judged on its address and state alone.
const noNbrID = "noNbrId"

// decodeNeighborDetail reads a neighbor detail capture. The second return is
// the reason the capture is refused, empty when it is accepted. An empty
// neighbors object is accepted, and it is kept distinct from a refusal: it is
// evidence of the command's answer, while a missing neighbors object means the
// command produced nothing usable.
func decodeNeighborDetail(data []byte) (map[string][]detailRecord, string) {
	top, err := decodeTopLevel(data)
	if err != nil {
		return nil, err.Error()
	}
	if _, ok := top["interfaces"]; ok {
		return nil, "output holds an interfaces object, not neighbors"
	}
	if _, ok := top["neighbors"]; !ok {
		return nil, `output has no "neighbors" object; the command failed, the VRF is unknown, or OSPF is not running`
	}
	var p detailPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Sprintf("malformed neighbor output: %v", err)
	}
	if p.Neighbors == nil {
		return nil, `"neighbors" is null`
	}
	// Keys are walked in sorted order, so one input always gives one refusal.
	out := make(map[string][]detailRecord, len(*p.Neighbors))
	records := 0
	for _, key := range slices.Sorted(maps.Keys(*p.Neighbors)) {
		list := (*p.Neighbors)[key]
		if key != noNbrID {
			if _, ok := parseIPv4(key); !ok {
				return nil, fmt.Sprintf("neighbor key %s is not a dotted IPv4 router ID or %s", quote(key), noNbrID)
			}
		}
		switch {
		case list == nil:
			return nil, fmt.Sprintf("neighbor list for %s is null", quote(key))
		case len(*list) == 0:
			// FRR creates a router ID's list when it adds the first neighbor to it,
			// so an empty list never comes from FRR.
			return nil, fmt.Sprintf("neighbor list for %s is empty", quote(key))
		}
		records += len(*list)
		out[key] = *list
	}
	if records > maxEntries {
		return nil, fmt.Sprintf("output holds %d neighbor records; more than %d is refused", records, maxEntries)
	}
	return out, ""
}

// decodeInterfaces reads an interface capture. The same empty-versus-refused
// rule as decodeNeighborDetail applies.
func decodeInterfaces(data []byte) (map[string]interfaceRecord, string) {
	top, err := decodeTopLevel(data)
	if err != nil {
		return nil, err.Error()
	}
	if _, ok := top["neighbors"]; ok {
		return nil, "output holds a neighbors object, not interfaces"
	}
	if _, ok := top["interfaces"]; !ok {
		return nil, `output has no "interfaces" object; the command failed, the VRF is unknown, or OSPF is not running`
	}
	var p interfacePayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Sprintf("malformed interface output: %v", err)
	}
	if p.Interfaces == nil {
		return nil, `"interfaces" is null`
	}
	if n := len(*p.Interfaces); n > maxEntries {
		return nil, fmt.Sprintf("output holds %d interfaces; more than %d is refused", n, maxEntries)
	}
	return *p.Interfaces, ""
}

// decodeTopLevel runs the strict checks and returns the top-level keys. Output
// that is not JSON, such as a vtysh error line, is refused here with its first
// line quoted.
func decodeTopLevel(data []byte) (map[string]json.RawMessage, error) {
	if err := checkStrictJSON(data); err != nil {
		if errors.Is(err, errNotJSON) {
			return nil, fmt.Errorf("not JSON output: %s", firstLine(data))
		}
		return nil, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("malformed output: %w", err)
	}
	return top, nil
}
