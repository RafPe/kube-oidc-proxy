// Copyright Jetstack Ltd. See LICENSE for details.
package logging

// Component names the subsystem that emitted a record. It is a closed set:
// every first-party record carries exactly one value from it, and adding a
// value is a reviewed change.
type Component string

const (
	ComponentStartup     Component = "startup"
	ComponentServer      Component = "server"
	ComponentOIDC        Component = "oidc"
	ComponentReadiness   Component = "readiness"
	ComponentRequest     Component = "request"
	ComponentTokenReview Component = "tokenreview"
	ComponentSAR         Component = "sar"
	ComponentAudit       Component = "audit"
	ComponentUpstream    Component = "upstream"
	ComponentShutdown    Component = "shutdown"
	ComponentK8s         Component = "k8s"
)

// AllComponents returns every component value. ComponentK8s is the component of
// records bridged from Kubernetes libraries; those carry no event_type.
func AllComponents() []Component {
	return []Component{ComponentStartup, ComponentServer, ComponentOIDC, ComponentReadiness,
		ComponentRequest, ComponentTokenReview, ComponentSAR, ComponentAudit, ComponentUpstream,
		ComponentShutdown, ComponentK8s}
}
