# Proxy

> God node · 21 connections · `pkg/proxy/proxy.go`

**Community:** [Proxy Core: Audit & Serving](Proxy_Core-_Audit_&_Serving.md)

## Connections by Relation

### contains
- proxy.go `EXTRACTED`

### method
- .RoundTrip() `EXTRACTED`
- .Run() `EXTRACTED`
- .reviewToken() `EXTRACTED`
- .roundTripperForRestConfig() `EXTRACTED`
- .serve() `EXTRACTED`
- .OIDCTokenAuthenticator() `EXTRACTED`
- .RunPreShutdownHooks() `EXTRACTED`

### references
- SubjectAccessReview `EXTRACTED`
- Audit `EXTRACTED`
- k8s.io/apiserver/pkg/authentication/authenticator.Token `EXTRACTED`
- k8s.io/client-go/rest.Config `EXTRACTED`
- net.IPNet `EXTRACTED`
- New() `EXTRACTED`
- Hooks `EXTRACTED`
- net/http.RoundTripper `EXTRACTED`
- Config `EXTRACTED`
- k8s.io/apiserver/pkg/server.SecureServingInfo `EXTRACTED`
- k8s.io/apimachinery/pkg/util/sets.Set `EXTRACTED`
- errorHandlerFn `EXTRACTED`
- k8s.io/apiserver/pkg/authentication/request/bearertoken.Authenticator `EXTRACTED`

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*