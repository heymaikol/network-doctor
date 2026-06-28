package main

import "testing"

func factVal(facts []Fact, key string) (string, bool) {
	for _, f := range facts {
		if f.Key == key {
			return f.Value, true
		}
	}
	return "", false
}

func TestExtractCurl(t *testing.T) {
	stdout := []string{"200 0.123456 140.82.112.3 0"}
	facts := extractFacts("c", stdout, 1, "job1", "github.com")
	if v, ok := factVal(facts, "http_code"); !ok || v != "200" {
		t.Errorf("http_code = %q (%v), want 200", v, ok)
	}
	if v, ok := factVal(facts, "remote_ip"); !ok || v != "140.82.112.3" {
		t.Errorf("remote_ip = %q, want 140.82.112.3", v)
	}
	if v, ok := factVal(facts, "time_total"); !ok || v != "0.123456s" {
		t.Errorf("time_total = %q, want 0.123456s", v)
	}
}

func TestExtractPing(t *testing.T) {
	stdout := []string{
		"PING github.com (140.82.112.3) 56(84) bytes of data.",
		"4 packets transmitted, 4 received, 0% packet loss, time 3005ms",
		"rtt min/avg/max/mdev = 1.0/2.0/3.0/0.5 ms",
	}
	facts := extractFacts("p", stdout, 1, "job1", "github.com")
	if v, ok := factVal(facts, "packet_loss"); !ok || v != "0% packet loss" {
		t.Errorf("packet_loss = %q, want '0%% packet loss'", v)
	}
	if v, ok := factVal(facts, "rtt"); !ok || v != "1.0/2.0/3.0/0.5 ms" {
		t.Errorf("rtt = %q, want '1.0/2.0/3.0/0.5 ms'", v)
	}
}

func TestExtractDig(t *testing.T) {
	stdout := []string{
		";; ANSWER SECTION:",
		"github.com.\t60\tIN\tA\t140.82.112.3",
		"github.com.\t60\tIN\tA\t140.82.113.4",
	}
	facts := extractFacts("d", stdout, 1, "job1", "github.com")
	v, ok := factVal(facts, "A_records")
	if !ok || v != "140.82.112.3, 140.82.113.4" {
		t.Errorf("A_records = %q, want both IPs", v)
	}
}

func TestShellArgsQuotes(t *testing.T) {
	got := shellArgs([]string{"-w", `%{http_code}\n`, "https://x"})
	want := `-w '%{http_code}\n' https://x`
	if got != want {
		t.Errorf("shellArgs = %q, want %q", got, want)
	}
}
