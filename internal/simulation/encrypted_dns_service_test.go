package simulation

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
)

func TestFrameDoTReplyBoundsLength(t *testing.T) {
	reply := bytes.Repeat([]byte{0xab}, 1<<16-1)
	framed, err := frameDoTReply(reply)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(framed[:2]); got != 1<<16-1 {
		t.Fatalf("length = %d, want %d", got, 1<<16-1)
	}
	if !bytes.Equal(framed[2:], reply) {
		t.Fatal("framing changed the response")
	}
	if framed, err := frameDoTReply(make([]byte, 1<<16)); err == nil || framed != nil {
		t.Fatalf("oversized response = %d bytes, %v; want rejection", len(framed), err)
	}
}

func TestDoHInvalidResponseModeReturnsGarbage(t *testing.T) {
	query := dnsQuery("example.test", dnsTypeA)
	req := httptest.NewRequest(http.MethodPost, encryptedDNSPath, bytes.NewReader(query))
	rec := httptest.NewRecorder()
	svc := Service{Name: encryptedDNSProbeService, Type: ServiceEncryptedDNS, Port: 443, DoHResponse: DoHResponseInvalid}
	serveDoH(rec, req, testZone(t), svc, nil)
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != encryptedDNSMediaType || string(body) != "not dns" {
		t.Fatalf("invalid DoH response = %d %q %q", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
}

// A reply is only evidence once it has been sent, so the record has to come
// from serving one; the configured mode alone must leave the log empty.
func TestDoHRecordsTheResponseItActuallySent(t *testing.T) {
	for _, tc := range []struct{ mode, want string }{
		{DoHResponseInvalid, DoHResponseInvalid},
		{"", replyResponded},
	} {
		t.Run("mode="+tc.mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "evidence.jsonl")
			recorder, err := openEvidenceRecorder(path, "internet")
			if err != nil {
				t.Fatal(err)
			}
			svc := Service{Name: encryptedDNSProbeService, Type: ServiceEncryptedDNS, Port: 443, DoHResponse: tc.mode}

			unanswered, err := readEvidence([]string{path})
			if err != nil {
				t.Fatal(err)
			}
			if len(unanswered.ServiceReplies) != 0 {
				t.Fatalf("configured but unqueried fixture recorded %+v", unanswered.ServiceReplies)
			}

			req := httptest.NewRequest(http.MethodPost, encryptedDNSPath, bytes.NewReader(dnsQuery("example.test", dnsTypeA)))
			serveDoH(httptest.NewRecorder(), req, testZone(t), svc, recorder)
			if err := recorder.Close(); err != nil {
				t.Fatal(err)
			}
			evidence, err := readEvidence([]string{path})
			if err != nil {
				t.Fatal(err)
			}
			want := []ServiceReplyEvidence{{Node: "internet", Service: encryptedDNSProbeService,
				Type: ServiceEncryptedDNS, Port: 443, Status: http.StatusOK, Result: tc.want, Count: 1}}
			if !reflect.DeepEqual(evidence.ServiceReplies, want) {
				t.Fatalf("recorded replies = %+v, want %+v", evidence.ServiceReplies, want)
			}
		})
	}
}

func TestEncryptedDNSRejectsUnknownDoHResponseMode(t *testing.T) {
	node := Node{Name: "resolver", Services: []Service{{Name: encryptedDNSProbeService, Type: ServiceEncryptedDNS,
		Port: 443, Zone: map[string]string{"example.test": "192.0.2.1"}, DoHResponse: "surprise",
		Certificate: &TLSCertificate{Mode: TLSCertificateValid, DNSNames: []string{diagnostic.EncryptedDNSHost}}}}}
	if err := node.validateServices(map[string]bool{}); err == nil {
		t.Fatal("accepted unknown DoH response mode")
	}
}
