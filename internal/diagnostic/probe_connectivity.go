package diagnostic

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// portalObservation is what one connectivity endpoint answered on one pass.
// A zero value is an endpoint that never answered: code 0 is not a status any
// responder can send, so it reads as "no observation" everywhere below.
type portalObservation struct {
	// clean is true only when the endpoint answered exactly what it documents,
	// status and payload both. It is not proof of an unmodified path, since
	// this is plain HTTP and a transparent proxy could synthesize the answer.
	clean bool
	code  int
	// redirect is a valid HTTP(S) sign-in URL the response advertised, empty
	// when it advertised none.
	redirect string
	// date is the Date the responder stamped on it, the zero time when the
	// header was absent or unparsable.
	date time.Time
	// skew is this machine's clock minus date, sampled by the caller so it
	// carries the HTTP round trip and nothing else.
	skew time.Duration
}

// portalCheckWithDial fetches one endpoint and reports what it answered.
// Proxy and redirect following are both off: the direct-egress row must not
// borrow the proxy's path, and an interception usually announces itself as
// the 302 we'd otherwise chase to a sign-in page.
func portalCheckWithDial(ctx context.Context, ep portalEndpoint, dial func(context.Context, string, string) (net.Conn, error)) (portalObservation, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.url, nil)
	if err != nil {
		return portalObservation{}, err
	}
	c := &http.Client{
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            dial,
			DisableKeepAlives:      true,
			MaxResponseHeaderBytes: 64 << 10,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := c.Do(req)
	if err != nil {
		return portalObservation{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	o := portalObservation{code: resp.StatusCode}
	// http.ParseTime accepts the three date formats RFC 9110 allows. An absent
	// or unparsable Date leaves the zero time, and every caller reads that as
	// "no reading" rather than as a time.
	o.date, _ = http.ParseTime(resp.Header.Get("Date"))
	o.clean = resp.StatusCode == ep.want && ep.bodyMatches(resp.Body)
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if u, err := resp.Location(); err == nil && u.Hostname() != "" {
			switch strings.ToLower(u.Scheme) {
			case "http", "https":
				o.redirect = u.String()
			}
		}
	}
	return o, nil
}

// bodyMatches reads exactly as many bytes as the documented payload and not one
// more, so an endpoint that promises a body has to send that body and an
// intercepting page cannot be scanned for it.
func (ep portalEndpoint) bodyMatches(body io.Reader) bool {
	if ep.body == "" {
		return true
	}
	buf := make([]byte, len(ep.body))
	_, err := io.ReadFull(body, buf)
	return err == nil && string(buf) == ep.body
}

// portalNote states what the discrepant endpoints answered, for a detail
// string. It reports the observation and never names a cause for it.
func portalNote(obs []portalObservation, idx []int) string {
	parts := make([]string, 0, len(idx))
	for _, i := range idx {
		parts = append(parts, fmt.Sprintf("%s answered %d, want %d", portalEndpoints[i].url, obs[i].code, portalEndpoints[i].want))
	}
	return strings.Join(parts, "; ")
}

// portalRedirect keeps the first advertised sign-in URL in endpoint order, so
// which one a corroborated interception carries never depends on which racing
// request finished first.
func portalRedirect(obs []portalObservation, idx []int) string {
	for _, i := range idx {
		if obs[i].redirect != "" {
			return obs[i].redirect
		}
	}
	return ""
}

func (o *netops) internetProbe(ctx context.Context, _ map[ProbeID]ProbeResult) ProbeResult {
	var r ProbeResult
	type famResult struct {
		ips      []net.IP
		conn     net.Conn
		sel      net.IP
		attempts []Attempt
		rtt      time.Duration
	}
	// Each family is probed independently and in parallel: a black-holing
	// family only spends its own share of the probe deadline, and IPv4 and
	// IPv6 egress are diagnosed separately.
	var v4, v6 famResult
	// --iface binds every dial to that interface's address of the destination's
	// family, so a family it has no address for cannot be dialed at all. Drop it
	// here rather than learn it from a bind error: an impossible attempt proves
	// nothing about the network, and calling it unreachable reports an outage in
	// a family nobody tested.
	v4.ips, v6.ips = o.compatibleSourceIPs(internetEndpoints4), o.compatibleSourceIPs(internetEndpoints6)
	if len(v4.ips) == 0 && len(v6.ips) == 0 {
		return ProbeResult{Status: StatusNA, Detail: "the selected interface has no address family available for direct egress"}
	}
	routeEvidence := o.collectPathComparison(ctx, v4.ips, v6.ips)
	// obs holds one entry per fixed connectivity endpoint, in endpoint order.
	// An entry stays zero where the check is stubbed out or the endpoint never
	// answered, and an endpoint that did not answer is the absence of an
	// observation rather than an observation of trouble.
	obs := make([]portalObservation, len(portalEndpoints))
	var wg sync.WaitGroup
	wg.Go(func() {
		v4.conn, v4.sel, v4.attempts, v4.rtt = o.dialIPs(ctx, v4.ips, 443)
	})
	wg.Go(func() {
		v6.conn, v6.sel, v6.attempts, v6.rtt = o.dialIPs(ctx, v6.ips, 443)
	})
	if o.portalCheck != nil {
		// One goroutine per endpoint, all alongside the dials rather than after
		// them and never after each other: two observations cost the same wall
		// time as one, and they cost nothing at all when egress is clean.
		for i, ep := range portalEndpoints {
			wg.Go(func() {
				got, err := o.portalCheck(ctx, ep)
				if err != nil {
					return
				}
				if !got.date.IsZero() {
					got.skew = time.Since(got.date)
				}
				obs[i] = got
			})
		}
	}
	wg.Wait()
	// One endpoint answering unexpectedly is a fact about that endpoint. A
	// block aimed at one provider, that provider's own outage, a hijacked DNS
	// answer for its name, and a captive portal all look identical from here,
	// so a lone discrepancy is reported as what was seen. Only two
	// independently operated endpoints intercepted on the same pass corroborate
	// each other, and corroboration is what carries a portal claim.
	var intercepted []int
	clean := -1
	for i, ob := range obs {
		switch {
		case ob.clean:
			if clean < 0 {
				clean = i
			}
		case ob.code != 0:
			intercepted = append(intercepted, i)
		}
	}
	corroborated := len(intercepted) > 1
	if clean >= 0 {
		// Only a response that matched its endpoint's documented clean answer
		// leaves usable clock evidence: anything else was written by whatever
		// answered instead, and an interceptor's clock speaks for the
		// interceptor. Endpoint order breaks the tie, so a clean Google answer
		// still supplies the reading it always has. A clean answer is not proof
		// of an unmodified path either, since this is plain HTTP and a
		// transparent proxy could synthesize both the status and the Date. It is
		// the same heuristic the portal verdict rests on, and no stronger.
		r.clockOffset = obs[clean].skew
	}
	r.Families = &FamilyConnectivity{IPv4: familyState(v4.ips, v4.conn), IPv6: familyState(v6.ips, v6.conn)}

	// IPv4 headlines the result unless it lost and IPv6 won. Not a value
	// judgment, just a stable order for the Detail string and warnings.
	prim, sec, primName, secName := v4, v6, "IPv4", "IPv6"
	if v4.conn == nil && v6.conn != nil {
		prim, sec, primName, secName = v6, v4, "IPv6", "IPv4"
	}
	if prim.conn == nil {
		r.Attempts = append(v4.attempts, v6.attempts...)
		all := append(append([]net.IP{}, v4.ips...), v6.ips...)
		r.Detail = "no direct TCP egress to " + joinIPs(all) + " (port 443)"
		src, iface, ambiguous := o.pathIdentity(ctx, nil, all[0], 443)
		r.Status, r.Source, r.Iface, r.ifaceAmbiguous = StatusFail, src, iface, ambiguous
		// Portals commonly drop 443 outright while still intercepting plain
		// HTTP. Both endpoints intercepted is a portal even with no handshake to
		// show for it, so report that, not "check upstream".
		if corroborated {
			r.Portal = &Portal{RedirectURL: portalRedirect(obs, intercepted)}
			r.Detail += ", and HTTP is intercepted: " + portalNote(obs, intercepted)
			r.Fix = "captive portal or transparent filter: open a browser and sign in to the network"
			return r
		}
		if len(intercepted) > 0 {
			// Worth recording beside the dead path, but nothing corroborates it,
			// so it names no portal and changes no verdict: the route cause
			// below still owns this failure.
			r.Detail += ", and one connectivity endpoint answered unexpectedly: " + portalNote(obs, intercepted)
		}
		if o.routeCause != nil {
			r.Cause, r.causeFamily = failedRouteCause(o.routeCause, v4.ips, v6.ips)
		}
		if ctx.Err() != context.Canceled {
			// A timeout is useful failure evidence, but must not start more
			// kernel queries after the probe has spent its budget.
			select {
			case evidence := <-routeEvidence:
				r.Routes, r.alternateDefaults = evidence.Routes, evidence.alternateDefaults
			default:
				select {
				case evidence := <-routeEvidence:
					r.Routes, r.alternateDefaults = evidence.Routes, evidence.alternateDefaults
				case <-ctx.Done():
				}
			}
		}
		// The routing table decides the advice: a missing default route and a
		// filtered upstream are different repairs. An empty or unrecognized
		// cause keeps the generic hint.
		r.Fix = routeFix(r.Cause)
		return r
	}
	defer prim.conn.Close()
	if sec.conn != nil {
		_ = sec.conn.Close()
	}
	src, iface, ambiguous := o.pathIdentity(ctx, prim.conn, prim.sel, 443)
	// A completed handshake only proves that something answered. A captive
	// portal or transparent filter terminates the connection itself and is
	// indistinguishable from real egress at this layer; the connectivity
	// endpoints are what tell them apart, so ask before calling the network
	// online. Both of them, because one is a claim about one provider.
	if corroborated {
		r.Status, r.SelectedIP, r.Source, r.Iface, r.ifaceAmbiguous = StatusFail, prim.sel, src, iface, ambiguous
		r.Attempts = append(prim.attempts, sec.attempts...)
		r.Portal = &Portal{RedirectURL: portalRedirect(obs, intercepted)}
		r.Detail = fmt.Sprintf("TCP reaches %s but HTTP is intercepted: %s", prim.sel, portalNote(obs, intercepted))
		r.Fix = "captive portal or transparent filter: open a browser and sign in to the network"
		return r
	}
	r.Status, r.SelectedIP, r.Source, r.Iface, r.ifaceAmbiguous = StatusPass, prim.sel, src, iface, ambiguous
	r.Detail = fmt.Sprintf("%s egress via %s in %dms (src %s %s)", primName, prim.sel, Ms(prim.rtt), src, iface)
	switch {
	case sec.conn != nil:
		r.Detail += fmt.Sprintf("; %s egress via %s in %dms", secName, sec.sel, Ms(sec.rtt))
	case len(sec.ips) == 0:
		r.Detail += "; " + secName + " not tested (the selected interface has no " + secName + " address)"
	default:
		r.Detail += "; no " + secName + " egress"
	}
	// Warnings judge only the winning family: a network without the other
	// family at all is normal, not degraded. The other family's attempts are
	// appended afterwards so the details panel still shows them.
	r.Attempts = prim.attempts
	var extra []string
	if len(intercepted) > 0 {
		// The endpoints disagree, so the run has not established interception:
		// it has observed one provider treating this machine differently, which
		// is a degradation of the row's own evidence and not a diagnosis. Named
		// as what was seen, with no cause attached.
		extra = append(extra, "one connectivity endpoint answered unexpectedly ("+portalNote(obs, intercepted)+")")
	}
	// The exception: a machine that took a global IPv6 address and still can't
	// reach IPv6 is broken, not v4-only. Happy Eyeballs hides that from netdoc
	// and from browsers, but not from software that dials AAAA and waits.
	if sec.conn == nil && secName == "IPv6" && o.hasGlobalUnicast(false) {
		extra = append(extra, "IPv6 address configured but no IPv6 egress (black-holed)")
		r.Cause = FamilyCauseIPv6Unreachable
		r.causeFamily = counterfactualIPv6
		r.Fix = "check the IPv6 default route, gateway, and forwarding path"
	}
	if sec.conn == nil && secName == "IPv4" && o.hasGlobalUnicast(true) {
		extra = append(extra, "IPv4 address configured but no IPv4 egress (black-holed)")
		r.Cause = FamilyCauseIPv4Unreachable
		r.causeFamily = counterfactualIPv4
		r.Fix = "check the IPv4 default route, gateway, and forwarding path"
	}
	applyDialWarnings(&r, prim.rtt, extra...)
	r.Attempts = append(prim.attempts, sec.attempts...)
	return r
}

// failedRouteCause summarizes attempted, failed families conservatively. A local
// defect in one family cannot explain an unlocalized failure in another, so
// selection-only or unknown evidence takes precedence over localizing causes.
// When every attempted family has local evidence, prefer an unresolved gateway
// to a missing default. Unattempted families contribute nothing. Within a
// family, classifyDefaultRoutes still prefers neighbor evidence to metadata.
func failedRouteCause(classify func(net.IP) string, families ...[]net.IP) (cause, family string) {
	priority := func(cause string) int {
		switch cause {
		case RouteCauseGatewayUnreachable:
			return 2
		case RouteCausePreferredPathFailed:
			return 5
		case RouteCauseSelectedPathFailed:
			return 4
		case RouteCauseNoDefaultRoute:
			return 1
		default:
			return 3
		}
	}
	best := -1
	for _, ips := range families {
		if len(ips) == 0 {
			continue
		}
		candidate := classify(ips[0])
		rank := priority(candidate)
		switch {
		case rank > best:
			cause, family, best = candidate, routeFamily(ips[0]), rank
		case rank == best && candidate == cause:
			// The same fact held for both families, so neither alone owns it.
			family = ""
		}
	}
	if cause == "" {
		family = ""
	}
	return cause, family
}
