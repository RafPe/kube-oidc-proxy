// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

import "time"

// RequestObservation is everything the lifecycle filter knows about a request
// once it has ended. It is filled in one place, the deferred function of
// withRequestLifecycle, so one request produces exactly one observation.
type RequestObservation struct {
	Verb        Verb
	Scope       Scope
	Status      int
	Termination string
	Duration    time.Duration

	// LongRunning marks a request classified long-running (watch, exec,
	// attach, portforward, logs, proxy). It is excluded from the latency
	// histogram: an hour-long watch in the +Inf bucket would make every
	// quantile a lie.
	LongRunning bool
	// Established reports that LongRunningEstablished was called for this
	// request, so the gauge it incremented is decremented exactly once.
	Established bool
	// Hijacked marks a connection the handler took over; its duration is not
	// a request latency and is not observed.
	Hijacked bool
}

func (r *Recorder) RequestStarted()                               {}
func (r *Recorder) LongRunningEstablished(verb Verb, scope Scope) {}
func (r *Recorder) RequestFinished(o RequestObservation)          {}
