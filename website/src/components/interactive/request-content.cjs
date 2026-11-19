// Curated explanations. Source excerpts resolve from unique function anchors.
module.exports = {
  "nodes": {
    "client": {
      "title": "Client sends a request",
      "tag": "BOUNDARY",
      "subtitle": "kubectl → proxy HTTPS listener",
      "summary": "The client sends a Kubernetes API request to the proxy HTTPS listener. The client already holds a bearer token.",
      "detail": "Proxy.Start wraps the reverse proxy with the filter chain. The listener serves this chain for each request. The reverse proxy targets restConfig.Host.",
      "input": "GET /api/v1/namespaces/default/pods\nAuthorization: Bearer <example token>",
      "output": "The request enters withRequestID.",
      "change": "Change listener options in cmd/app/options. Change request behavior in pkg/proxy.",
      "tests": "go test ./pkg/proxy -run Test",
      "refs": [
        {
          "file": "pkg/proxy/proxy.go",
          "anchor": "func (p *Proxy) Start("
        }
      ]
    },
    "requestid": {
      "title": "Establish request identity",
      "tag": "CONTEXT",
      "subtitle": "withRequestID",
      "summary": "The proxy assigns one correlation ID before authentication, audit, or logging uses the request.",
      "detail": "Only a trusted peer can supply the authoritative request ID. Other valid IDs remain client_request_id values. The proxy copies the header map and sets Audit-ID on the request and response.",
      "input": "Peer address and optional request ID headers",
      "output": "Audit-ID header and request ID in context",
      "change": "Preserve the Audit-ID header. The audit initialization filter reads this header.",
      "tests": "go test ./pkg/proxy -run \"Test.*(RequestID|Trusted)\"",
      "refs": [
        {
          "file": "pkg/proxy/requestid.go",
          "anchor": "func (p *Proxy) withRequestID("
        }
      ]
    },
    "info": {
      "title": "Resolve Kubernetes request info",
      "tag": "CONTEXT",
      "subtitle": "auditor.WithRequestInfo",
      "summary": "The proxy converts the HTTP method and path into a Kubernetes verb, resource, and namespace.",
      "detail": "WithRequestInfo resolves these fields once before lifecycle tracking. Both audit chains use this result. A GET request for a pod collection has the Kubernetes verb list.",
      "input": "GET /api/v1/namespaces/default/pods",
      "output": "Example: verb=list, resource=pods, namespace=default",
      "change": "Read RequestInfo from context. Do not add a separate URL parser.",
      "tests": "go test ./pkg/proxy/audit ./pkg/proxy -run \"Test.*(RequestInfo|Lifecycle)\"",
      "refs": [
        {
          "file": "pkg/proxy/audit/audit.go",
          "anchor": "func (a *Audit) WithRequestInfo("
        }
      ]
    },
    "lifecycle": {
      "title": "Start lifecycle tracking",
      "tag": "OBSERVABILITY",
      "subtitle": "withRequestLifecycle · enter",
      "summary": "The proxy starts timing and counts the request as active. A response recorder observes the downstream response.",
      "detail": "The deferred function records completion and releases active gauges. Successful streams produce a response-start record. The recorder preserves flushing and connection upgrades.",
      "input": "Resolved RequestInfo and request logger",
      "output": "Response recorder + start time + deferred completion callback",
      "change": "Preserve response-writer interfaces when changing this filter. Test watch streams, upgrades, cancellation, and panic handling.",
      "tests": "go test ./pkg/proxy -run \"Test.*(Lifecycle|ResponseRecorder)\"",
      "refs": [
        {
          "file": "pkg/proxy/lifecycle.go",
          "anchor": "func (p *Proxy) withRequestLifecycle("
        }
      ]
    },
    "headers": {
      "title": "Sanitize forwarding headers",
      "tag": "TRUST BOUNDARY",
      "subtitle": "withSanitizedForwardHeaders",
      "summary": "The proxy sanitizes forwarding headers before authentication and audit use the client address.",
      "detail": "clientip.Sanitize applies the trusted-proxy rules. reqctx.WithResolvedClient stores the address and sanitized headers. The filter records header changes.",
      "input": "Peer address + X-Forwarded-For + X-Real-IP",
      "output": "Sanitized forwarding headers used consistently downstream",
      "change": "Keep this filter outside authentication. Address rules belong in pkg/proxy/clientip.",
      "tests": "go test ./pkg/proxy/clientip ./pkg/proxy -run \"Test.*(Forward|Remote|Trusted)\"",
      "refs": [
        {
          "file": "pkg/proxy/handlers.go",
          "anchor": "func (p *Proxy) withSanitizedForwardHeaders("
        }
      ]
    },
    "auth": {
      "title": "Authenticate the bearer token",
      "tag": "AUTHENTICATION",
      "subtitle": "withAuthenticateRequest",
      "summary": "OIDC authentication verifies the token and returns a Kubernetes identity. This identity does not grant resource access.",
      "detail": "The router reads unverified iss and aud claims to select one issuer entry. When entries share an issuer URL, aud must match exactly one entry. Only that entry verifies the signature, expiry, audience, and configured claim rules. No other entry runs after a verification failure. Claim mappings then produce the identity. An OIDC error can enter TokenReview fallback unless the client canceled the request. A missing token returns 401 directly.",
      "input": "Authorization bearer token + configured authenticator",
      "output": "Authenticated user in context, or a branch to fallback / rejection",
      "change": "Change claim mappings in pkg/authn. Preserve the separate paths for cancellation, validation errors, and missing tokens.",
      "tests": "go test ./cmd/app ./pkg/proxy -run \"Test.*(Auth|Issuer|Token)\"",
      "refs": [
        {
          "file": "pkg/proxy/handlers.go",
          "anchor": "func (p *Proxy) withAuthenticateRequest("
        }
      ]
    },
    "guard": {
      "title": "Reject reserved identities",
      "tag": "IDENTITY GUARD",
      "subtitle": "checkReservedIdentity",
      "summary": "The proxy rejects reserved usernames and disallowed reserved groups after OIDC accepts the token.",
      "detail": "The proxy refuses usernames with the system: prefix. Groups allow system:authenticated and configured exceptions. The user already exists in context, so refusal audit records identify the caller.",
      "input": "OIDC user identity + allowedReservedGroups",
      "output": "Continue, or authenticated 403 rejection",
      "change": "Test username and group rules separately. Keep the guard before the forwarding decision.",
      "tests": "go test ./pkg/proxy -run \"Test.*Reserved\"",
      "refs": [
        {
          "file": "pkg/proxy/handlers.go",
          "anchor": "func checkReservedIdentity("
        }
      ]
    },
    "review": {
      "title": "Try TokenReview fallback",
      "tag": "ALTERNATIVE PATH",
      "subtitle": "withTokenReview → reviewToken",
      "summary": "TokenReview asks Kubernetes to authenticate a token that OIDC rejected. This fallback requires token passthrough to be enabled.",
      "detail": "A successful review supplies the identity for audit and access records. The proxy preserves the original bearer token and selects ForwardPassthrough. Rejection or a review dependency failure returns 401. Client cancellation produces no response.",
      "input": "Rejected OIDC token and TokenPassthrough setting",
      "output": "Reviewed identity and ForwardPassthrough, or refusal",
      "change": "Review behavior and caching belong in pkg/authn/tokenreview. Preserve the returned identity for audit records.",
      "tests": "go test ./pkg/authn/tokenreview ./pkg/proxy -run \"Test.*(Review|Token)\"",
      "refs": [
        {
          "file": "pkg/proxy/handlers.go",
          "anchor": "func (p *Proxy) withTokenReview("
        },
        {
          "file": "pkg/proxy/proxy.go",
          "anchor": "func (p *Proxy) reviewToken("
        }
      ]
    },
    "sar": {
      "title": "Authorize requested impersonation",
      "tag": "AUTHORIZATION",
      "subtitle": "Authorizer.ConsumeImpersonation",
      "summary": "SubjectAccessReview checks whether the authenticated caller may impersonate each identity field that the client requests.",
      "detail": "Without impersonation headers, ConsumeImpersonation returns immediately and sends no review. Otherwise it checks the requested target and removes consumed headers. The checks share a timeout and can use cached decisions. They do not authorize the resource operation.",
      "input": "Authenticated requester + client Impersonate-* headers",
      "output": "Authorized target user, or an error before forwarding",
      "change": "Keep the requester separate from the target. Test each identity field, malformed headers, cancellation, and cached decisions.",
      "tests": "go test ./pkg/authz/subjectaccessreview",
      "refs": [
        {
          "file": "pkg/authz/subjectaccessreview/subjectaccessreview.go",
          "anchor": "func (a *Authorizer) ConsumeImpersonation("
        },
        {
          "file": "pkg/authz/subjectaccessreview/subjectaccessreview.go",
          "anchor": "func (a *Authorizer) resolveImpersonation("
        }
      ]
    },
    "impersonate": {
      "title": "Build the outbound identity",
      "tag": "TRANSFORMATION",
      "subtitle": "outboundIdentity → ForwardDecisionRecord",
      "summary": "The proxy constructs the identity for the upstream request. It uses the authenticated caller or an authorized impersonation target.",
      "detail": "outboundIdentity copies groups and extras. It applies Kubernetes authenticated or anonymous group rules. Proxy-owned extras replace client values. Explicit impersonation preserves original identity fields. The filter stores the outbound identity in a forwarding decision.",
      "input": "OIDC user or approved impersonation target",
      "output": "ForwardImpersonating decision with outbound identity",
      "change": "Keep authenticator-owned collections unchanged. Test proxy-owned extras and anonymous impersonation targets.",
      "tests": "go test ./pkg/proxy -run \"Test.*Impersonat\"",
      "refs": [
        {
          "file": "pkg/proxy/impersonate.go",
          "anchor": "func (p *Proxy) outboundIdentity("
        },
        {
          "file": "pkg/proxy/impersonate.go",
          "anchor": "func (p *Proxy) withImpersonateRequest("
        }
      ]
    },
    "skip": {
      "title": "Skip identity impersonation",
      "tag": "ALTERNATIVE PATH",
      "subtitle": "withImpersonateRequest · early return",
      "summary": "The proxy selects forwarding without its own credentials. Passthrough and disabled impersonation carry different client credentials.",
      "detail": "TokenReview passthrough preserves the client bearer token. Disabled impersonation follows successful OIDC authentication, which consumes that token. That request reaches the upstream anonymously. Both paths preserve client impersonation headers for the upstream to authorize.",
      "input": "Existing ForwardPassthrough decision or DisableImpersonation",
      "output": "ForwardPassthrough with token, or ForwardDisabled without token",
      "change": "Test passthrough and disabled impersonation separately. Do not describe both paths as token forwarding.",
      "tests": "go test ./pkg/proxy -run \"Test.*(Impersonat|Token)\"",
      "refs": [
        {
          "file": "pkg/proxy/impersonate.go",
          "anchor": "func (p *Proxy) withImpersonateRequest("
        }
      ]
    },
    "audit": {
      "title": "Enter the audit chain",
      "tag": "OBSERVABILITY",
      "subtitle": "auditor.WithRequest",
      "summary": "The audit chain records authenticated requests according to the configured audit policy and backend.",
      "detail": "WithAuditInit initializes the audit context before WithAudit runs. RequestInfo already exists from the outer filter. Authenticated refusals use this same audit chain. Unauthenticated refusals use WithFailedAuthentication.",
      "input": "Identity context + Audit-ID + request metadata",
      "output": "Audit events when the configured policy and backend require them",
      "change": "Test successful requests and refusals. Both audit chains require resolved RequestInfo.",
      "tests": "go test ./pkg/proxy/audit",
      "refs": [
        {
          "file": "pkg/proxy/audit/audit.go",
          "anchor": "func (a *Audit) WithRequest("
        }
      ]
    },
    "reverse": {
      "title": "Rewrite and dispatch upstream",
      "tag": "PROXY",
      "subtitle": "httputil.ReverseProxy",
      "summary": "The Go reverse proxy forwards the request to the configured API server and copies the response.",
      "detail": "reverseProxy sets the transport to p.roundTrip and errors to p.handleUpstreamError. FlushInterval controls response flushing. Standard library code handles URL rewriting and connection upgrades.",
      "input": "Audited request targeting the proxy",
      "output": "Upstream request passed to p.roundTrip",
      "change": "Test watch and exec when changing response handling.",
      "tests": "go test ./pkg/proxy",
      "refs": [
        {
          "file": "pkg/proxy/proxy.go",
          "anchor": "func (p *Proxy) reverseProxy("
        }
      ]
    },
    "transport": {
      "title": "Apply credentials and send",
      "tag": "TRANSPORT",
      "subtitle": "Proxy.roundTrip",
      "summary": "The transport reads the forwarding decision and selects upstream credentials. It records admission before the network call.",
      "detail": "ForwardImpersonating uses proxy credentials with impersonation headers. ForwardPassthrough preserves the client token. ForwardDisabled sends no token after OIDC consumes it. Missing or invalid decisions fail before admission. Upstream errors do not create another access decision.",
      "input": "ForwardDecisionRecord",
      "output": "Upstream request and one admission record",
      "change": "Keep credential selection tied to ForwardDecisionRecord. Test all three modes.",
      "tests": "go test ./pkg/proxy -run \"Test.*(RoundTrip|Transport|Decision)\"",
      "refs": [
        {
          "file": "pkg/proxy/proxy.go",
          "anchor": "func (p *Proxy) roundTrip("
        }
      ]
    },
    "upstream": {
      "title": "Kubernetes evaluates RBAC",
      "tag": "EXTERNAL SYSTEM",
      "subtitle": "API server · outside this repository",
      "summary": "The Kubernetes API server authenticates the connection and authorizes the effective identity for the requested operation.",
      "detail": "For impersonation, Kubernetes first checks the proxy credential permission to impersonate. It then checks resource access for the effective identity. Passthrough uses the client token. Disabled impersonation supplies no credential. This external behavior is outside the repository.",
      "input": "Upstream credentials + effective identity + requested resource",
      "output": "Kubernetes response: success, RBAC denial, or another API status",
      "change": "Check the proxy impersonation grants and the effective identity RoleBindings separately.",
      "tests": "make e2e",
      "refs": [
        {
          "file": "pkg/proxy/proxy.go",
          "anchor": "func (p *Proxy) roundTrip("
        }
      ]
    },
    "response": {
      "title": "Return and finish the request",
      "tag": "RESPONSE",
      "subtitle": "Reverse proxy returns → lifecycle defer",
      "summary": "The response returns through the handlers. The lifecycle defer records completion, including early refusals.",
      "detail": "The recorder reports status, duration, and termination. It releases active request and stream gauges. Watch requests can remain open for hours. A failed stream cannot replace response headers that the proxy already sent.",
      "input": "Upstream response or local rejection",
      "output": "Client response + completion log and metrics",
      "change": "Test headers, handler completion, and connection termination separately.",
      "tests": "go test ./pkg/proxy ./pkg/metrics -run \"Test.*(Lifecycle|Request|Response)\"",
      "refs": [
        {
          "file": "pkg/proxy/lifecycle.go",
          "anchor": "func (p *Proxy) withRequestLifecycle("
        }
      ]
    },
    "unauthorized": {
      "title": "Return 401 Unauthorized",
      "tag": "EARLY EXIT",
      "subtitle": "refuse · failed authentication",
      "summary": "The proxy could not authenticate the request. It does not forward the resource request.",
      "detail": "refuse records the denial and invokes WithFailedAuthentication. The handler writes 401. A TokenReview dependency failure also returns 401 with a distinct log reason. Client cancellation produces no response.",
      "input": "errUnauthorized",
      "output": "HTTP 401 + denial record + failed-authentication audit path",
      "change": "Preserve failed-authentication auditing and separate dependency failure reasons.",
      "tests": "go test ./pkg/proxy ./pkg/proxy/audit -run \"Test.*(Unauthorized|Auth|Error)\"",
      "refs": [
        {
          "file": "pkg/proxy/errors.go",
          "anchor": "func (p *Proxy) refuse("
        }
      ]
    },
    "forbidden": {
      "title": "Return 403 Forbidden",
      "tag": "EARLY EXIT",
      "subtitle": "refuse · authenticated denial",
      "summary": "The caller authenticated, but the proxy rejects the identity or the requested impersonation.",
      "detail": "Reserved identities and denied impersonation both return 403 through the authenticated audit chain. These refusals occur before forwarding. A resource denial from the API server is a separate upstream response.",
      "input": "Reserved identity or ErrImpersonationNotAllowed",
      "output": "HTTP 403 before upstream forwarding",
      "change": "Keep typed error checks. Test the identity recorded for each refusal.",
      "tests": "go test ./pkg/proxy ./pkg/authz/subjectaccessreview",
      "refs": [
        {
          "file": "pkg/proxy/errors.go",
          "anchor": "func (p *Proxy) refuse("
        }
      ]
    },
    "badgateway": {
      "title": "Report an upstream failure",
      "tag": "ERROR PATH",
      "subtitle": "handleUpstreamError",
      "summary": "The proxy admitted the request, but its upstream connection failed before response headers.",
      "detail": "handleUpstreamError records an upstream failure and marks termination. A classified transport error returns 502. Cancellation produces no response. Internal forwarding errors use the internal failure path.",
      "input": "Classified upstream transport error before response headers",
      "output": "HTTP 502 + termination metadata for the lifecycle filter",
      "change": "Keep upstream failures separate from authentication and authorization failures.",
      "tests": "go test ./pkg/proxy -run \"Test.*(Error|Upstream|Lifecycle)\"",
      "refs": [
        {
          "file": "pkg/proxy/errors.go",
          "anchor": "func (p *Proxy) handleUpstreamError("
        }
      ]
    },
    "boot": {
      "title": "Parse and validate configuration",
      "tag": "STARTUP",
      "subtitle": "NewRunCommand → buildRunCommand",
      "summary": "The command checks options and creates the process logger before it constructs runtime components.",
      "detail": "run creates the signal context and starts optional metrics. startup constructs the proxy, auditor, and readiness server. The start method starts these components. Shutdown follows serving completion.",
      "input": "CLI flags, mounted configuration, runtime environment",
      "output": "Validated options, root logger, stop signal, cluster REST config",
      "change": "Add flags and validation in cmd/app/options. Connect options to runtime configuration in cmd/app/wiring.go.",
      "tests": "go test ./cmd/app/...",
      "refs": [
        {
          "file": "cmd/app/run.go",
          "anchor": "func run("
        }
      ]
    },
    "config": {
      "title": "Construct OIDC authenticators",
      "tag": "STARTUP",
      "subtitle": "authn.Build",
      "summary": "The authn package constructs OIDC authenticators from flags or an AuthenticationConfiguration file.",
      "detail": "The builder creates an issuer router with a shared CEL compiler. The proxy configuration kind supports named entries that share an issuer URL. Their audience sets must not overlap. Each entry has its own claim rules and mappings. The upstream configuration kind permits only one entry per issuer URL.",
      "input": "OIDC options or AuthenticationConfiguration",
      "output": "authenticator.Token + named issuers used by readiness",
      "change": "Change claim mapping and issuer validation in pkg/authn. Test flag and file configuration.",
      "tests": "go test ./pkg/authn ./cmd/app/...",
      "refs": [
        {
          "file": "pkg/authn/build.go",
          "anchor": "func Build("
        },
        {
          "file": "pkg/authn/build.go",
          "anchor": "func jwtAuthenticatorFromIssuer("
        }
      ]
    },
    "wiring": {
      "title": "Inject proxy dependencies",
      "tag": "STARTUP",
      "subtitle": "proxy.New(Dependencies)",
      "summary": "startup constructs the clients, auditor, reviewers, authenticator, proxy, and readiness server.",
      "detail": "proxy.New receives explicit dependencies and configuration. It checks them and constructs upstream transports. The command owns component startup and shutdown. The proxy owns request forwarding.",
      "input": "Constructed clients, authenticators, reviewers, and configuration",
      "output": "A validated Proxy ready for Run",
      "change": "Add a collaborator through explicit dependencies. Test construction failures before request handling.",
      "tests": "go test ./pkg/proxy ./cmd/app",
      "refs": [
        {
          "file": "cmd/app/run.go",
          "anchor": "func startup("
        }
      ]
    },
    "chain": {
      "title": "Assemble nested middleware",
      "tag": "STARTUP",
      "subtitle": "withFilterChain · outermost wrapper runs first",
      "summary": "Each assignment wraps the current handler. The last wrapper added receives the request first.",
      "detail": "The request enters request ID, request info, lifecycle, header sanitation, authentication, impersonation, audit, and reverse proxy filters. The stack returns in reverse order. The map expands selected substeps for explanation.",
      "input": "The innermost reverse proxy handler",
      "output": "Nested http.Handler passed to SecureServingInfo.Serve",
      "change": "Place a new filter after the context it requires. Place it before the refusal paths it must observe.",
      "tests": "go test ./pkg/proxy/...",
      "refs": [
        {
          "file": "pkg/proxy/handlers.go",
          "anchor": "func (p *Proxy) withFilterChain("
        }
      ]
    }
  },
  "scenarios": {
    "sharedIssuer": {
      "label": "Shared issuer URL · GitHub Actions",
      "note": "The internal and vendor entries share the GitHub issuer URL. The internal audience selects gha-internal. Its claim rule checks repository_owner_id before mapping the username. Kubernetes then checks bindings for that username. This example assumes a valid internal token and a pod-read grant.",
      "result": "Example: 200 OK"
    },
    "oidc": {
      "label": "OIDC → Kubernetes",
      "note": "A valid OIDC token maps to oidc-a:alice@example.com. This example assumes that Kubernetes allows the user to list pods.",
      "result": "Example: 200 OK"
    },
    "impersonation": {
      "label": "Explicit impersonation · --as",
      "note": "Alice requests --as=bob. SAR allows the requested target. This example assumes that Kubernetes allows Bob to list pods.",
      "result": "Example: 200 OK"
    },
    "denied": {
      "label": "Impersonation denied",
      "note": "OIDC accepts Alice, but SAR refuses her request to impersonate Bob. No resource request reaches the API server.",
      "result": "403 Forbidden"
    },
    "missing": {
      "label": "Missing bearer token",
      "note": "No parseable bearer token: !ok with no validation error. The fallback handler is not entered.",
      "result": "401 Unauthorized"
    },
    "invalid": {
      "label": "Invalid OIDC · fallback off",
      "note": "OIDC returns a validation error. The fallback handler sees that TokenReview is off and returns 401.",
      "result": "401 Unauthorized"
    },
    "reserved": {
      "label": "Reserved identity rejected",
      "note": "OIDC accepts the token but its mapped username has the reserved system: prefix.",
      "result": "403 Forbidden"
    },
    "passthrough": {
      "label": "TokenReview passthrough",
      "note": "OIDC rejects the token. TokenReview accepts it and supplies the audit identity. The proxy forwards the original token.",
      "result": "Upstream decides"
    },
    "disabled": {
      "label": "Impersonation disabled",
      "note": "OIDC accepts the token and consumes its Authorization header. DisableImpersonation sends the request upstream without a token or proxy credentials.",
      "result": "Anonymous upstream request"
    },
    "failure": {
      "label": "Upstream connection failure",
      "note": "OIDC succeeds and the proxy admits the request. The upstream connection fails before response headers.",
      "result": "502 Bad Gateway"
    },
    "watch": {
      "label": "Long-running watch",
      "note": "A valid OIDC request watches pods. ResponseStarted marks successful stream establishment. Completion occurs when the handler ends.",
      "result": "Example: 200 streaming"
    },
    "startup": {
      "label": "Startup & composition",
      "note": "Follow component construction before the first request. Readiness and metrics use separate listeners. They are outside the request filter chain.",
      "result": "Ready to serve"
    }
  }
};
