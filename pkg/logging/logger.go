// Copyright Jetstack Ltd. See LICENSE for details.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
)

// SchemaVersion is stamped on every first-party record. Bump it only for a
// breaking change to the record shape, so consumers can key off one field.
const SchemaVersion = 1

// Format selects the encoding of the log stream.
type Format string

const (
	FormatJSON Format = "json"
	FormatText Format = "text"
)

// Options configures the root logger. The zero value is a JSON logger at the
// INFO floor writing to stdout.
type Options struct {
	Format    Format
	Verbosity int       // the -v value; 0 => INFO floor, >=1 => DEBUG floor
	Output    io.Writer // nil => os.Stdout
}

// Validate reports whether the options describe a logger that can be built. An
// empty Format is the JSON default, matching the --logging-format flag.
func (o Options) Validate() error {
	switch o.Format {
	case "", FormatJSON, FormatText:
		return nil
	default:
		return fmt.Errorf("logging: unknown format %q, want %q or %q", o.Format, FormatJSON, FormatText)
	}
}

// LevelFor maps the single -v verbosity knob onto a slog level. -v=0 shows
// ERROR, WARN and INFO; -v>=1 additionally shows DEBUG. WARN and ERROR are
// never hidden, so there is no level above INFO to select.
func LevelFor(verbosity int) slog.Level {
	if verbosity >= 1 {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}

// New builds the root logger. Every record it produces carries
// schema_version; component and event_type are added by ForComponent and Emit.
func New(o Options) (*slog.Logger, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	out := o.Output
	if out == nil {
		out = os.Stdout
	}
	hopts := &slog.HandlerOptions{Level: LevelFor(o.Verbosity)}
	var h slog.Handler
	if o.Format == FormatText {
		h = slog.NewTextHandler(out, hopts)
	} else {
		h = slog.NewJSONHandler(out, hopts)
	}
	return slog.New(h).With(slog.Int("schema_version", SchemaVersion)), nil
}

// ForComponent derives the logger a subsystem emits through. Every first-party
// record carries exactly one component.
func ForComponent(root *slog.Logger, c Component) *slog.Logger {
	return root.With(slog.String("component", string(c)))
}

// attrRequestID is the record field naming the per-request id, and the one
// Required key Emit can supply from the context.
const attrRequestID = "request_id"

type ctxKey struct{}

type requestIDKey struct{}

// WithRequestID returns a context carrying the id minted for the request being
// served. Emit reads it so a call site deep in the request path does not have
// to thread request_id through every signature.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFrom returns the request id carried by the context, or "" when
// there is none.
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// NewContext returns a context carrying the request-scoped logger.
func NewContext(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

// FromContext returns the logger carried by the context, or a logger that
// discards every record when there is none. It never returns nil, so call
// sites need no guard.
func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.New(slog.DiscardHandler)
}

// Emit logs one registered event at the level and with the message its
// registry entry declares. Passing an unregistered event is a programming
// error and panics: the event set is closed and checked at build time.
func Emit(ctx context.Context, l *slog.Logger, e EventType, attrs ...slog.Attr) {
	spec, ok := e.Spec()
	if !ok {
		panic("logging: unregistered event " + string(e))
	}
	EmitLevel(ctx, l, e, spec.Level, attrs...)
}

// EmitLevel is Emit with an explicit level, for the few events whose severity
// depends on the outcome (upstream.request.failed drops to DEBUG on a client
// cancellation).
func EmitLevel(ctx context.Context, l *slog.Logger, e EventType, level slog.Level, attrs ...slog.Attr) {
	spec, _ := e.Spec()
	attrs = withContextRequestID(ctx, spec, attrs)
	checkRequired(e, spec, attrs) // no-op unless built with -tags logcheck
	if !l.Enabled(ctx, level) {
		return
	}
	all := make([]slog.Attr, 0, len(attrs)+1)
	all = append(all, e.Attr())
	all = append(all, attrs...)
	l.LogAttrs(ctx, level, spec.Message, all...)
}

// withContextRequestID supplies request_id from the context for an event whose
// registry entry requires it and whose caller did not pass it. A caller that
// passes the attribute always wins, so a record never carries the key twice.
// Emit inherits this through EmitLevel.
func withContextRequestID(ctx context.Context, spec EventSpec, attrs []slog.Attr) []slog.Attr {
	if !slices.Contains(spec.Required, attrRequestID) || hasAttr(attrs, attrRequestID) {
		return attrs
	}
	id := RequestIDFrom(ctx)
	if id == "" {
		return attrs
	}
	// Full slice expression: appending must not write into the caller's array.
	return append(attrs[:len(attrs):len(attrs)], slog.String(attrRequestID, id))
}

// hasAttr reports whether attrs carries the given key, whatever its value.
func hasAttr(attrs []slog.Attr, key string) bool {
	for _, a := range attrs {
		if a.Key == key {
			return true
		}
	}
	return false
}
