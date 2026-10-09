package diagnostic

import "errors"

// errRouteEventsOverflow reports that the platform dropped change notifications
// because its queue overflowed. The dropped changes are not recoverable, so the
// reader treats it as a change of unknown extent and invalidates.
var errRouteEventsOverflow = errors.New("route change notifications were dropped")

// routeEvents is one platform subscription to route, address and link changes.
// next blocks until a notification arrives, returns errRouteEventsOverflow when
// notifications were dropped, and returns any other error once the subscription
// has ended. close unblocks a pending next and may be called more than once.
type routeEvents interface {
	next() error
	close() error
}

// routeFeed is a running subscription. stop tells the reader that the stop is
// deliberate, so a read that fails because of it is not a change. done closes
// when the reader has returned.
type routeFeed struct {
	src  routeEvents
	stop chan struct{}
	done chan struct{}
}

// FollowRouteEvents subscribes the session to the platform's route, address and
// link change notifications, where the platform has them. Each notification
// calls Invalidate, so a reusable row measured before a change is measured again
// on the next pass. The subscription is bound before this returns, so a change
// made after it returns is seen. Binding also invalidates once: a change made
// while no subscription ran was not seen, so nothing cached may be reused. It
// returns an error, and changes nothing, when the platform has no source or the
// subscription cannot be made. The session then keeps watchMaxAge as its only
// bound.
//
// A subscription that fails later is not restarted. The reader invalidates once
// more and stops, and the session falls back to watchMaxAge. A subscription
// that overflows invalidates and keeps reading.
//
// Only the goroutine that owns the session may call this, Close, or
// FollowsRouteEvents: the subscription field is not synchronized.
func (s *WatchSession) FollowRouteEvents() error {
	if s.feed != nil {
		return nil
	}
	src, err := openRouteEvents()
	if err != nil {
		return err
	}
	s.followRoutes(src)
	s.Invalidate()
	return nil
}

// FollowsRouteEvents reports whether a route-event subscription is running. It
// lets the owner check that a session it replaced or closed holds none.
func (s *WatchSession) FollowsRouteEvents() bool {
	return s.feed != nil
}

// followRoutes starts the reader for src. It is the seam tests use to replay a
// scripted sequence of notifications.
func (s *WatchSession) followRoutes(src routeEvents) {
	f := &routeFeed{src: src, stop: make(chan struct{}), done: make(chan struct{})}
	s.feed = f
	go s.readRoutes(f)
}

func (s *WatchSession) readRoutes(f *routeFeed) {
	defer close(f.done)
	defer func() { _ = f.src.close() }()
	for {
		err := f.src.next()
		if err != nil {
			// Close ends a read with an error. That is the owner stopping, not a
			// change. A successful read is a change even if Close raced it.
			select {
			case <-f.stop:
				return
			default:
			}
		}
		s.Invalidate()
		if err != nil && !errors.Is(err, errRouteEventsOverflow) {
			return
		}
	}
}

// Close stops the route-event subscription, if one is running, and returns once
// its reader has exited. The session stays usable: without a subscription it
// reuses rows only within watchMaxAge. Calling Close again does nothing. The
// owner calls it when it stops using the session.
func (s *WatchSession) Close() {
	f := s.feed
	if f == nil {
		return
	}
	s.feed = nil
	close(f.stop)
	_ = f.src.close()
	<-f.done
}
