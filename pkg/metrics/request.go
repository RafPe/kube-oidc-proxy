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

// RequestStarted marks a request entering the handler chain. Called before
// the handler runs, so a panicking handler still reaches RequestFinished and
// the gauge cannot leak.
func (r *Recorder) RequestStarted() {
	if r == nil {
		return
	}
	r.requestsInFlight.Inc()
}

// LongRunningEstablished marks a long-running request whose response has
// begun: its headers went out, or its connection was hijacked for an
// upgrade. Only then is a stream open; a watch refused with 401 never was.
func (r *Recorder) LongRunningEstablished(verb Verb, scope Scope) {
	if r == nil {
		return
	}
	r.longRunningRequests.WithLabelValues(projectVerb(verb), projectScope(scope)).Inc()
}

// RequestFinished records the end of a request: the in-flight gauge, the
// long-running gauge when it was established, the completed-request counter,
// and the latency histogram for short requests only.
func (r *Recorder) RequestFinished(o RequestObservation) {
	if r == nil {
		return
	}
	verb, scope := projectVerb(o.Verb), projectScope(o.Scope)

	r.requestsInFlight.Dec()
	if o.Established {
		r.longRunningRequests.WithLabelValues(verb, scope).Dec()
	}
	r.requestsTotal.WithLabelValues(verb, scope, CodeFor(o.Status), projectTermination(o.Termination)).Inc()
	if !o.LongRunning && !o.Hijacked {
		r.requestDuration.WithLabelValues(verb, scope).Observe(o.Duration.Seconds())
	}
}
