# Structured logging pipeline — TDD evidence

Evidence for the structured logging work tracked in issue #129. Every RED and
GREEN cell below comes from a real run recorded while the change was built; no
result here was written from expectation.

## Journeys

- **An on-call engineer finds every record for one request.** The proxy mints a
  `request_id` at the edge, puts it in the request context, echoes it as
  `Audit-ID`, and every record the request produces carries it — the access
  decision, the authn and impersonation events, the terminal record, and the
  Kubernetes audit events joined on the same id.
- **A SIEM analyst filters denials by reason.** Every denial is one
  `request.access.decided` record at INFO with `decision=deny` and a
  closed-set `reason`, never rate-limited and never dropped.
- **A security reviewer proves no token or claim appears at `-v=10`.** Tests
  below assert, at maximum verbosity, that a rejected bearer token, arbitrary
  claims and extras, configured extra-header values and full issuer URLs never
  reach the stream — in unit tests and, for the token, against a live cluster in
  the e2e suite. The remaining never-log items — `Cookie` values, request and
  response bodies, cache keys and the `User-Agent` header — are absent by
  construction rather than by a dedicated assertion: no log call site anywhere
  in `pkg/` or `cmd/` references them (`Cookie` and `User-Agent` appear nowhere
  in the Go sources; a token-review cache key is a hash that is never passed to
  a logger). Treat those four as reviewed-by-inspection, not test-held.
- **A maintainer adds an event and CI regenerates the docs.** A new event is
  one entry in `pkg/logging/events.go`; `make eventdoc` regenerates the table in
  `docs/logging.md`, `make verify` fails if it was not committed, and the
  per-package sweep fails if the event is emitted with the wrong component,
  level or a missing required field.

## Evidence

`Type` is `unit` (package-local, no request chain), `integration` (the real
middleware chain, a rendered chart, or a repo-level check) or `e2e` (the Kind
suite).

Every cell holds the full command that produced it — no abbreviation — and a
line copied verbatim from that run. `go test` separates the columns of its `ok`
and `FAIL` lines with tabs; those are rendered here as spaces, because a table
cell cannot hold a tab. Nothing else is altered.

- **RED** cannot be reproduced on this tree: the implementation is merged. Each
  RED cell names the task whose report recorded it, and quotes that run's
  failing line. Where a task produced RED by temporarily reverting or mutating
  code, the cell says what was changed.
- **GREEN** for every Go row was re-run on this branch at `a56e6e98` and the
  output pasted below; the e2e rows quote Task 19 and Task 20, naming the commit
  each run was taken at, because this task does not run the Kind suite.
- One row — the e2e shard gate — is a contract check with no RED, the same shape
  as the contract rows in `docs/testing/unified-release.tdd.md`.

| Guarantee | Tests | Type | RED | GREEN |
| --- | --- | --- | --- | --- |
| Every record is one JSON object with `schema_version` and `component`; `--logging-format=text` is also valid | `TestRootAddsSchemaVersionAndComponent`, `TestTextFormatIsValid` | unit | Task 4: `go test -tags logcheck ./pkg/logging/... -v`<br>→ `FAIL github.com/rafpe/kube-oidc-proxy/pkg/logging [setup failed]` — package `logtest` did not exist, so both tests failed to build | `go test -tags logcheck -count=1 -run 'TestRootAddsSchemaVersionAndComponent\|TestTextFormatIsValid' ./pkg/logging/ -v`<br>→ `--- PASS: TestRootAddsSchemaVersionAndComponent (0.00s)`; `ok  github.com/rafpe/kube-oidc-proxy/pkg/logging 0.420s` |
| `event_type` is a closed set of 39 values matching `^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*){2}$`, and `component` is a closed set | `TestEventTypeGrammar`, `TestEveryEventIsRegisteredWithValidSpec`, `TestEventAttr`, `TestAllComponentsClosedSet` | unit | Task 1: `go test ./pkg/logging/ -run 'TestEventTypeGrammar\|TestEveryEventIsRegisteredWithValidSpec\|TestEventAttr\|TestAllComponentsClosedSet' -v`<br>→ `FAIL github.com/rafpe/kube-oidc-proxy/pkg/logging [build failed]` after `pkg/logging/events_test.go:28:20: undefined: AllEventTypes` | `go test -tags logcheck -count=1 -run 'TestEventTypeGrammar\|TestEveryEventIsRegisteredWithValidSpec\|TestEventAttr\|TestAllComponentsClosedSet' ./pkg/logging/ -v`<br>→ `--- PASS: TestEventTypeGrammar (0.00s)`; `ok  github.com/rafpe/kube-oidc-proxy/pkg/logging 0.313s` |
| Every record any test emits is registered, under the right component and an allowed level, with its required fields | `logtest.AssertRegistered`, swept in `pkg/proxy` (via `TestMain`), `pkg/probe`, `pkg/proxy/audit`, `pkg/proxy/hooks`, `pkg/proxy/subjectaccessreview`, `pkg/proxy/tokenreview` | integration | Task 17: `go test ./pkg/proxy/` with `EventProxyServerStarted` temporarily emitted without `address`<br>→ `events sweep: proxy.server.started missing required address: map[component:server event_type:proxy.server.started level:INFO msg:server started schema_version:1 time:2026-09-04T17:04:43.043396+03:00]` | `go test -tags logcheck -count=1 ./pkg/probe/ ./pkg/proxy/ ./pkg/proxy/audit/ ./pkg/proxy/hooks/ ./pkg/proxy/subjectaccessreview/ ./pkg/proxy/tokenreview/`<br>→ `ok  github.com/rafpe/kube-oidc-proxy/pkg/probe 0.705s`, `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy 2.732s` (the package whose `TestMain` runs the sweep), `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy/audit 2.463s`, `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy/hooks 0.298s`, `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview 1.800s`, `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy/tokenreview 1.841s` |
| The sweep's level check is real: an event emitted at a level the registry does not allow fails | `TestLiveCheckFailureEvents` under the sweep, with `AllowedLevels` removed from `authz.sar.failed` | integration | Task 17: `go test -tags logcheck ./pkg/proxy/subjectaccessreview/`<br>→ `subjectaccessreview_test.go:972: authz.sar.failed emitted at DEBUG, registry says ERROR` | `go test -tags logcheck -count=1 ./pkg/proxy/subjectaccessreview/`<br>→ `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview 1.800s` |
| `Emit` refuses a record missing a required field, and takes `request_id` from the context when the caller did not pass one | `TestEmitPanicsOnMissingRequiredFieldUnderLogcheck`, `TestEmitTakesRequiredRequestIDFromContext`, `TestEmitKeepsAnExplicitRequestIDOverTheContext`, `TestEmitPanicsWhenRequestIDIsNeitherPassedNorInContext`, `TestRequestIDFromIsEmptyWhenAbsent` | unit | Task 4: `go test -tags logcheck -run TestEmitKeepsAnExplicitRequestIDOverTheContext ./pkg/logging/ -v`<br>→ `logger_test.go:107: request_id = "from-context", want explicit` and `logger_test.go:110: request_id appears 2 times, want 1: {"time":"2026-09-04T14:22:54.11464+03:00","level":"DEBUG","msg":"subject access review cache lookup","schema_version":1,"event_type":"cache.sar.lookup","request_id":"explicit","cache_result":"hit","request_id":"from-context"}` | `go test -tags logcheck -count=1 -run 'TestEmitPanicsOnMissingRequiredFieldUnderLogcheck\|TestEmitTakesRequiredRequestIDFromContext\|TestEmitKeepsAnExplicitRequestIDOverTheContext\|TestEmitPanicsWhenRequestIDIsNeitherPassedNorInContext\|TestRequestIDFromIsEmptyWhenAbsent' ./pkg/logging/ -v`<br>→ `--- PASS: TestEmitKeepsAnExplicitRequestIDOverTheContext (0.00s)`; `ok  github.com/rafpe/kube-oidc-proxy/pkg/logging 0.310s` |
| The access-log field contract is frozen against a committed fixture | `TestFrozenAccessContract` (`TestUpdateFixtures` regenerates the fixtures and skips otherwise) | unit | Task 7: `go test -tags logcheck ./pkg/proxy/logging/ -run TestFrozenAccessContract -v`, then the same command with one fixture value mutated<br>→ `contract_test.go:32: open testdata/access_decision_allow.json: no such file or directory`, then `contract_test.go:43: allow: frozen field inbound_user = alice, fixture alice-renamed` | `go test -tags logcheck -count=1 -run 'TestFrozenAccessContract\|TestUpdateFixtures' ./pkg/proxy/logging/ -v`<br>→ `--- PASS: TestFrozenAccessContract (0.00s)` and `--- SKIP: TestUpdateFixtures (0.00s)`; `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy/logging 0.474s` |
| One access decision per request: `AuSuccess` without a reason, `AuFail` with a closed-set reason, carrying the request id and the Kubernetes dimensions | `TestLogDecisionAllowedIsAuSuccessWithoutReason`, `TestLogDecisionDeniedCarriesReasonAndRequestID`, `TestLogDecisionCarriesRequestCorrelation`, `TestLogDecisionCarriesKubernetesDimensions`, `TestNonResourceRequestHasNoKubernetesDimensions` | unit | Task 6: `go test -tags logcheck ./pkg/proxy/... -run 'TestLogDecision\|TestGroupsAreCapped\|TestHandlers' -v`<br>→ `pkg/proxy/logging/accesslog_test.go:162:9: undefined: NewAccessLogger`; `FAIL github.com/rafpe/kube-oidc-proxy/pkg/proxy/logging [build failed]` | `go test -tags logcheck -count=1 -run 'TestLogDecisionAllowedIsAuSuccessWithoutReason\|TestLogDecisionDeniedCarriesReasonAndRequestID\|TestLogDecisionCarriesRequestCorrelation\|TestLogDecisionCarriesKubernetesDimensions\|TestNonResourceRequestHasNoKubernetesDimensions' ./pkg/proxy/logging/ -v`<br>→ `--- PASS: TestLogDecisionCarriesRequestCorrelation (0.00s)`; `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy/logging 0.345s` |
| Claims, extras, configured extra-header values and rejected tokens never reach the log | `TestOutboundExtraDoesNotLeakOriginalUserClaims`, `TestLogDecisionIsSanitizedAndOmitsClaims`, `TestImpersonationExtraHeaderValuesAreNotLogged`, `TestReviewTokenRejectedIsNotLoggedAsValid`, `TestImpersonationAppliedLogsHeaderNamesOnly` | unit, integration | Task 3: `go test ./pkg/proxy/logging/ -run TestOutboundExtraDoesNotLeakOriginalUserClaims -v` and `go test ./pkg/proxy/ -run TestImpersonationExtraHeaderValuesAreNotLogged -v`<br>→ `accesslog_test.go:262: original user extras leaked into the access log:` with `"originaluser.jetstack.io-extra":["{\"tenant\":[\"acme-secret-tenant\"]}"]` in the record; `handlers_test.go:432: configured extra header value logged:` followed by `I0904 13:51:35.174591   19290 handlers.go:239] adding impersonate extra user header tenant: acme-secret-value (192.0.2.1)` | `go test -tags logcheck -count=1 -run 'TestOutboundExtraDoesNotLeakOriginalUserClaims\|TestLogDecisionIsSanitizedAndOmitsClaims\|TestImpersonationExtraHeaderValuesAreNotLogged\|TestReviewTokenRejectedIsNotLoggedAsValid\|TestImpersonationAppliedLogsHeaderNamesOnly' ./pkg/proxy/ ./pkg/proxy/logging/ -v`<br>→ `--- PASS: TestOutboundExtraDoesNotLeakOriginalUserClaims (0.00s)`; `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy 1.279s` and `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy/logging 0.348s` |
| An issuer URL is never logged raw and never reaches an impersonation header | `TestIssuerNameNeverEmitsRawInput`, `TestIssuerNamesDerivesFromURLs`, `TestIssuerNameNeverReachesImpersonationHeaders`, `TestWithAuthenticateRequestPublishesIssuerName`, `TestWithIssuerNameAttributesOnlyAcceptedTokens`, `TestSetIssuerNameWithoutHolderIsNoOp` | unit, integration | Task 10: `go test -tags logcheck -run 'TestIssuerName\|TestReadinessServerFailed' ./pkg/probe/ -v`; Task 15: `go test -tags logcheck ./pkg/proxy/ -run TestIssuerNameNeverReachesImpersonationHeaders -v` with a leak injected into `namedIssuer.AuthenticateToken`<br>→ `probe_test.go:641: IssuerName("https://exa mple.com/%zz") = "https://exa mple.com/%zz", want "unknown"`; `issuerattr_test.go:88: issuer leaked into impersonation extra "issuer-name" = "corp.example.test"` | `go test -tags logcheck -count=1 -run 'TestIssuerNameNeverEmitsRawInput\|TestIssuerNamesDerivesFromURLs\|TestIssuerNameNeverReachesImpersonationHeaders\|TestWithAuthenticateRequestPublishesIssuerName\|TestWithIssuerNameAttributesOnlyAcceptedTokens\|TestSetIssuerNameWithoutHolderIsNoOp' ./pkg/probe/ ./pkg/proxy/ -v`<br>→ `--- PASS: TestIssuerNameNeverReachesImpersonationHeaders (0.00s)`; `ok  github.com/rafpe/kube-oidc-proxy/pkg/probe 0.434s` and `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy 0.855s` |
| Every user-influenced string is sanitized and bounded (`request_id` 64, `error_message` 512, identity 256, groups capped at 32 with `groups_omitted`) | `TestSanitize`, `TestSanitizeList`, `TestBound`, `TestBoundedList`, `TestSanitizePathNilURL`, `TestSanitizeForwardHeaders`, `TestGroupsAreCapped`, `TestUIDsAreBounded`, `TestAllowlistedExtraValuesAreNotTruncated`, `TestCheckAuthorizedForImpersonationHeaderValueCap` | unit | Task 6: `go test -tags logcheck ./pkg/proxy/logging/... -run TestUIDsAreBounded -v`<br>→ `accesslog_test.go:367: inbound_uid is 300 runes, want 256` | `go test -tags logcheck -count=1 -run 'TestSanitize\|TestSanitizeList\|TestBound\|TestBoundedList\|TestSanitizePathNilURL\|TestSanitizeForwardHeaders\|TestGroupsAreCapped\|TestUIDsAreBounded\|TestAllowlistedExtraValuesAreNotTruncated\|TestCheckAuthorizedForImpersonationHeaderValueCap' ./pkg/logging/ ./pkg/proxy/logging/ ./pkg/proxy/context/ ./pkg/proxy/subjectaccessreview/ -v`<br>→ `--- PASS: TestUIDsAreBounded (0.00s)`; `ok  github.com/rafpe/kube-oidc-proxy/pkg/logging 0.303s`, `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy/logging 0.899s`, `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy/context 0.614s`, `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview 1.244s` |
| The request id is minted at the edge, echoed as `Audit-ID`, and an inbound `Audit-ID`/`X-Request-ID` is adopted only from a trusted proxy (otherwise kept as `client_request_id`) | `TestWithRequestIDMintsAndSetsAuditIDHeader`, `TestWithRequestIDAdoptsHeaderFromTrustedProxy`, `TestWithRequestIDDoesNotTrustClientHeaderFromUntrustedPeer`, `TestWithRequestIDBoundsAndSanitisesInbound`, `TestWithRequestIDInstallsTheRequestScopedLogger`, `TestBothAuditChainsAdoptTheSameID`, `TestRequestScopedIDAccessors` | integration | Task 5: `go test ./pkg/proxy/ -run 'TestWithRequestID\|TestBothAuditChains' -v`<br>→ `pkg/proxy/requestid_test.go:36:9: p.withRequestID undefined (type *Proxy has no field or method withRequestID)`; `FAIL github.com/rafpe/kube-oidc-proxy/pkg/proxy [build failed]` | `go test -tags logcheck -count=1 -run 'TestWithRequestIDMintsAndSetsAuditIDHeader\|TestWithRequestIDAdoptsHeaderFromTrustedProxy\|TestWithRequestIDDoesNotTrustClientHeaderFromUntrustedPeer\|TestWithRequestIDBoundsAndSanitisesInbound\|TestWithRequestIDInstallsTheRequestScopedLogger\|TestBothAuditChainsAdoptTheSameID\|TestRequestScopedIDAccessors' ./pkg/proxy/ ./pkg/proxy/context/ -v`<br>→ `--- PASS: TestWithRequestIDDoesNotTrustClientHeaderFromUntrustedPeer (0.00s)`; `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy 1.112s` and `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy/context 0.323s` |
| The request path emits its authn, impersonation and upstream events | `TestOIDCFailureEmitsAuthnOIDCFailed`, `TestOIDCSuccessEmitsAuthnOIDCSucceeded`, `TestMissingBearerOnTokenReviewIsDebug`, `TestRejectedTokenReviewIsCompletedNotAuthenticated`, `TestImpersonationSkippedWhenDisabled`, `TestImpersonationSkippedOnTokenReviewPassthrough`, `TestTokenReviewDependencyFailureIsError`, `TestClientCancellationEmitsUpstreamRequestCanceled`, `TestErrorHandlerInternalFailureEmitsHandlerFailed` | integration | Task 9: `go test -tags logcheck ./pkg/proxy/ -run 'TestOIDCFailure\|TestMissingBearer\|TestRejectedTokenReview\|TestImpersonationApplied' -v`<br>→ `handlers_test.go:111: want exactly 1 authn.token.missing record, got 0:` — one of four such lines in that run, alongside `authn.oidc.failed`, `authn.tokenreview.completed` and `request.impersonation.applied` | `go test -tags logcheck -count=1 -run 'TestOIDCFailureEmitsAuthnOIDCFailed\|TestOIDCSuccessEmitsAuthnOIDCSucceeded\|TestMissingBearerOnTokenReviewIsDebug\|TestRejectedTokenReviewIsCompletedNotAuthenticated\|TestImpersonationSkippedWhenDisabled\|TestImpersonationSkippedOnTokenReviewPassthrough\|TestTokenReviewDependencyFailureIsError\|TestClientCancellationEmitsUpstreamRequestCanceled\|TestErrorHandlerInternalFailureEmitsHandlerFailed' ./pkg/proxy/ -v`<br>→ `--- PASS: TestOIDCFailureEmitsAuthnOIDCFailed (0.00s)`; `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy 0.841s` |
| Every request ends in exactly one terminal record with a status, duration, byte count and a classified `termination`; an upstream transport failure is not an access decision | `TestCompletedRecordCarriesStatusDurationBytes`, `TestImplicit200OnWrite`, `TestFlushBeforeWriteRecordsTheImplicit200`, `TestDuplicateWriteHeaderKeepsFirst`, `TestHijackedMarksTerminationAndOmitsBytes`, `TestPanicIsRecordedThenRepanicked`, `TestResponseStartedOnlyForLongRunning`, `TestFlushStartsALongRunningResponse`, `TestResponseStartedNotEmittedForAResolvedShortRequest`, `TestClientCancelTermination`, `TestErrorClassifiesEveryReason`, `TestErrorHandlerClassifiesUpstreamTransportErrors`, `TestErrorUpstreamTransportFailureIsNotAnAccessDecision`, `TestUpstreamFailureReachesTheTerminalRecord`, `TestChainResolvesRequestInfoBeforeLifecycle`, `TestChainResolvesRequestInfoBeforeTheErrorHandler` | integration | Task 14: `go test -tags logcheck ./pkg/proxy/ -run 'TestFlush' -v`; Task 6: `go test -tags logcheck ./pkg/proxy/ -run 'TestErrorUpstreamTransportFailureIsNotAnAccessDecision\|TestErrorClassifiesEveryReason' -v`<br>→ `lifecycle_test.go:246: http_status = 0, want 200`; `proxy_test.go:250: unexpected status code, exp=502 got=500` with `proxy_test.go:345: the error handler wrote 1 access records for a transport failure:` | `go test -tags logcheck -count=1 -run 'TestCompletedRecordCarriesStatusDurationBytes\|TestImplicit200OnWrite\|TestFlushBeforeWriteRecordsTheImplicit200\|TestDuplicateWriteHeaderKeepsFirst\|TestHijackedMarksTerminationAndOmitsBytes\|TestPanicIsRecordedThenRepanicked\|TestResponseStartedOnlyForLongRunning\|TestFlushStartsALongRunningResponse\|TestResponseStartedNotEmittedForAResolvedShortRequest\|TestClientCancelTermination\|TestErrorClassifiesEveryReason\|TestErrorHandlerClassifiesUpstreamTransportErrors\|TestErrorUpstreamTransportFailureIsNotAnAccessDecision\|TestUpstreamFailureReachesTheTerminalRecord\|TestChainResolvesRequestInfoBeforeLifecycle\|TestChainResolvesRequestInfoBeforeTheErrorHandler' ./pkg/proxy/ -v`<br>→ `--- PASS: TestFlushBeforeWriteRecordsTheImplicit200 (0.00s)` and `--- PASS: TestErrorUpstreamTransportFailureIsNotAnAccessDecision (0.00s)`; `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy 0.860s` |
| Denials are INFO and never rate-limited; only `request.anomaly.detected`, `request.headers.dropped` and `log.warning.suppressed` are token-bucketed, and the bucket summarises on shutdown | `TestAnomalyIsRateLimitedButAccessRecordIsNot`, `TestReservedIdentityEmitsAnomalyAndDeniedAccess`, `TestUntrustedForwardedHeadersDroppedIsWarn`, `TestRealIPOnlyDroppedCarriesNoForwardedChain`, `TestTrustedForwardedHeadersRewritten`, `TestLimiterAllowsBurstThenSummarises`, `TestLimiterRefillsAtTheConfiguredRatePerSecond`, `TestFlushWarnLimiterSummarisesOnShutdown` | unit, integration | Task 12: `go test -tags logcheck ./pkg/proxy/ -run 'TestUntrustedForwarded\|TestRealIPOnly\|TestTrustedForwarded\|TestReservedIdentityEmits\|TestAnomalyIsRateLimited' -v`<br>→ `handlers_test.go:686: anomaly records = 0, want burst 3` — with the denial record already present in the same output | `go test -tags logcheck -count=1 -run 'TestAnomalyIsRateLimitedButAccessRecordIsNot\|TestReservedIdentityEmitsAnomalyAndDeniedAccess\|TestUntrustedForwardedHeadersDroppedIsWarn\|TestRealIPOnlyDroppedCarriesNoForwardedChain\|TestTrustedForwardedHeadersRewritten\|TestLimiterAllowsBurstThenSummarises\|TestLimiterRefillsAtTheConfiguredRatePerSecond\|TestFlushWarnLimiterSummarisesOnShutdown' ./pkg/logging/ ./pkg/proxy/ -v`<br>→ `--- PASS: TestAnomalyIsRateLimitedButAccessRecordIsNot (0.00s)`; `ok  github.com/rafpe/kube-oidc-proxy/pkg/logging 0.292s` and `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy 0.871s` |
| SubjectAccessReview and TokenReview report cache hits, live checks, bypasses and failures, with a client disconnect at DEBUG and a dependency failure at ERROR | `TestCacheHitAndLiveCheckEvents`, `TestCachedDenyDecisionEvents`, `TestCacheBypassEvents`, `TestLiveCheckFailureEvents`, `TestCoalescedLiveCheckEvent`, `TestImpersonationResolvedEvent`, `TestCachedTokenReviewEvents`, `TestLiveTokenReviewCompletedEvent`, `TestCachedTokenReviewHitCarriesNoDuration`, `TestTokenReviewFailureEmitsNoCompletedEvent` | unit | Task 11: `go test -tags logcheck ./pkg/proxy/subjectaccessreview/ ./pkg/proxy/tokenreview/ -run 'TestCacheHitAndLiveCheckEvents\|TestCachedTokenReviewEvents' -v`, then `go test -tags logcheck ./pkg/proxy/subjectaccessreview/ -run 'TestLiveCheckFailureEvents' -v`<br>→ `subjectaccessreview_test.go:758: []` (no records at all), then `subjectaccessreview_test.go:956: level = "ERROR", want DEBUG: a client disconnect must not raise an ERROR` | `go test -tags logcheck -count=1 -run 'TestCacheHitAndLiveCheckEvents\|TestCachedDenyDecisionEvents\|TestCacheBypassEvents\|TestLiveCheckFailureEvents\|TestCoalescedLiveCheckEvent\|TestImpersonationResolvedEvent\|TestCachedTokenReviewEvents\|TestLiveTokenReviewCompletedEvent\|TestCachedTokenReviewHitCarriesNoDuration\|TestTokenReviewFailureEmitsNoCompletedEvent' ./pkg/proxy/subjectaccessreview/ ./pkg/proxy/tokenreview/ -v`<br>→ `--- PASS: TestLiveCheckFailureEvents (0.05s)`; `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview 0.823s` and `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy/tokenreview 0.938s` |
| Startup, readiness, audit-backend, pre-shutdown-hook and signal lifecycle each emit their registered event | `TestReadyTransitionIsInfo`, `TestIssuerPendingEmittedOnStateChangeWithReason`, `TestReadinessServerFailedOnShutdownError`, `TestHooksEmitPerHookResult`, `TestRunReportsBackendStarted`, `TestRunReportsBackendFailed`, `TestRunWithoutBackendIsSilent`, `TestShutdownReportsFlushResult`, `TestShutdownReportsFlushFailure`, `TestHandlerReportsFirstSignalThenForcedExit`, `TestSignalName`, `TestLogConfigLoaded`, `TestLogIssuersConfigured`, `TestLogIssuersConfiguredNoIssuers` | unit | Task 10: `go test -tags logcheck ./pkg/probe/ ./pkg/proxy/hooks/ ./pkg/proxy/audit/ -v`, then `go test -tags logcheck ./pkg/probe/ ./pkg/util/signals/ ./pkg/proxy/audit/ ./cmd/app/`<br>→ `probe_test.go:608: want exactly 1 readiness.proxy.ready record, got 0:`; `audit_test.go:358: Shutdown reported success for a backend that failed to flush`; then `cmd/app/run_test.go:368:2: undefined: logConfigLoaded` | `go test -tags logcheck -count=1 -run 'TestReadyTransitionIsInfo\|TestIssuerPendingEmittedOnStateChangeWithReason\|TestReadinessServerFailedOnShutdownError\|TestHooksEmitPerHookResult\|TestRunReportsBackendStarted\|TestRunReportsBackendFailed\|TestRunWithoutBackendIsSilent\|TestShutdownReportsFlushResult\|TestShutdownReportsFlushFailure\|TestHandlerReportsFirstSignalThenForcedExit\|TestSignalName\|TestLogConfigLoaded\|TestLogIssuersConfigured\|TestLogIssuersConfiguredNoIssuers' ./pkg/probe/ ./pkg/proxy/audit/ ./pkg/proxy/hooks/ ./pkg/util/signals/ ./cmd/app/ -v`<br>→ `--- PASS: TestShutdownReportsFlushFailure (0.00s)`; `ok  github.com/rafpe/kube-oidc-proxy/pkg/probe 0.417s`, `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy/audit 1.745s`, `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy/hooks 0.414s`, `ok  github.com/rafpe/kube-oidc-proxy/pkg/util/signals 0.814s`, `ok  github.com/rafpe/kube-oidc-proxy/cmd/app 2.404s` |
| `-v` is the single verbosity knob (`-v=0` shows ERROR/WARN/INFO, `-v>=1` shows DEBUG, WARN and ERROR are never hidden), and `--logging-format` defaults to `json` | `TestLevelForVerbosity`, `TestDebugHiddenAtVerbosityZero`, `TestTextFormatIsValid`, `TestLoggingOptionsDefaultsAndValidation`, `TestLoggingOptionsReadsVerbosityFromGlobalFlags`, `TestLoggingFlagsReachOptionsThroughTheCommand` | unit, integration | Task 8: `go test -tags logcheck ./cmd/app/options/ ./pkg/proxy/ -run 'TestLoggingOptions\|TestNewRequiresLogger' -v`<br>→ `cmd/app/options/logging_test.go:13:7: undefined: NewLoggingOptions`; `FAIL github.com/rafpe/kube-oidc-proxy/cmd/app/options [build failed]` | `go test -tags logcheck -count=1 -run 'TestLevelForVerbosity\|TestDebugHiddenAtVerbosityZero\|TestTextFormatIsValid\|TestLoggingOptionsDefaultsAndValidation\|TestLoggingOptionsReadsVerbosityFromGlobalFlags\|TestLoggingFlagsReachOptionsThroughTheCommand' ./pkg/logging/ ./cmd/app/options/ -v`<br>→ `--- PASS: TestDebugHiddenAtVerbosityZero (0.00s)`; `ok  github.com/rafpe/kube-oidc-proxy/pkg/logging 0.283s` and `ok  github.com/rafpe/kube-oidc-proxy/cmd/app/options 0.970s` |
| No component is constructed without a logger, and a context with no logger yields a discarding one rather than a nil panic | `TestNewRequiresLogger`, `TestNewValidatesDependencies`, `TestFromContextReturnsDiscardWhenAbsent` | unit | Task 8: `go test -tags logcheck ./cmd/app/options/ ./pkg/proxy/ -run 'TestLoggingOptions\|TestNewRequiresLogger' -v`<br>→ `pkg/proxy/new_test.go:33:3: unknown field Logger in struct literal of type Dependencies`; `FAIL github.com/rafpe/kube-oidc-proxy/pkg/proxy [build failed]` | `go test -tags logcheck -count=1 -run 'TestNewRequiresLogger\|TestNewValidatesDependencies\|TestFromContextReturnsDiscardWhenAbsent' ./pkg/logging/ ./pkg/proxy/ -v`<br>→ `--- PASS: TestNewRequiresLogger (0.00s)`; `ok  github.com/rafpe/kube-oidc-proxy/pkg/logging 0.470s` and `ok  github.com/rafpe/kube-oidc-proxy/pkg/proxy 0.853s` |
| Records bridged from Kubernetes libraries carry `component=k8s` and no `event_type`, stay reachable at `-v=10`, and installing the bridge does not move klog's own verbosity | `TestBridgeMapsKlogVerbosityToDebugAndTagsComponent`, `TestInstallKlogBridgeLeavesKlogVerbosityUnchanged` | unit | Task 13: `go test -tags logcheck ./pkg/logging/ -run TestBridge -v`, then `go test -tags logcheck ./pkg/logging/ -count=1` with the bridge's `-v` restore removed<br>→ `bridge_test.go:37: V(2) record: map[]`, then `bridge_test.go:112: klog -v leaked out of the bridge test: got "7", want "2"` and `klog -v leaked out of this package: "0" at start, "7" at end` | `go test -tags logcheck -count=1 -run 'TestBridgeMapsKlogVerbosityToDebugAndTagsComponent\|TestInstallKlogBridgeLeavesKlogVerbosityUnchanged' ./pkg/logging/ -v`<br>→ `--- PASS: TestBridgeMapsKlogVerbosityToDebugAndTagsComponent (0.00s)` and `--- PASS: TestInstallKlogBridgeLeavesKlogVerbosityUnchanged (0.00s)`; `ok  github.com/rafpe/kube-oidc-proxy/pkg/logging 0.308s` |
| The event reference in `docs/logging.md` is generated from the registry and CI fails when it is stale | `make verify_eventdoc`, which runs `go run ./hack/eventdoc -check` | integration | Task 18: `go run ./hack/eventdoc -check` with one level flipped in the committed table<br>→ `eventdoc: docs/logging.md is out of date: run 'make eventdoc' and commit the result` | `go run ./hack/eventdoc -check && echo eventdoc-stable`<br>→ `eventdoc-stable` (the check printed nothing and exited 0) |
| The chart renders `--logging-format` and `--v` from `logging.format` / `logging.verbosity` | `hack/verify-chart-logging.sh`, run by `.github/workflows/helm.yaml` | integration | Task 16: `bash hack/verify-chart-logging.sh` on the chart before the flags were added<br>→ `missing --logging-format default` (exit 1), on a chart that otherwise rendered and linted clean | `bash hack/verify-chart-logging.sh`<br>→ `chart logging values: ok` |
| Every e2e case container carries exactly one shard label | `hack/verify-e2e-shards.sh` | integration | N/A — a contract check, not a behaviour change; it has no RED, the same as the contract rows in `docs/testing/unified-release.tdd.md` | `./hack/verify-e2e-shards.sh`<br>→ `verify-e2e-shards: 11 e2e case container(s) each carry exactly one of: shard-a shard-b shard-c` |
| Against a live cluster the stream is line-delimited JSON, correlates one request across the access record, the terminal record and the `Audit-ID` response header, refuses a client-supplied `Audit-ID`, records a rejected token without the token, records an impersonation denial with reason and target, warns on dropped forwarded headers, and bridges client-go as `component=k8s` | The nine `Logging` specs in `test/e2e/suite/cases/logging/logging.go` (`shard-b`) | e2e | Task 19 at commit `997f945d`: `make e2e E2E_GOTEST_ARGS='-args --ginkgo.focus=Logging'`<br>→ `FAIL! -- 7 Passed \| 2 Failed \| 0 Pending \| 35 Skipped`, on `[FAIL] [TEST] Logging [It] forwards the request id to the upstream API server [shard-b]` | Task 19 at commit `08e7c1f2`: `make e2e E2E_GOTEST_ARGS='-args --ginkgo.focus=Logging'`<br>→ `SUCCESS! -- 9 Passed \| 0 Failed \| 0 Pending \| 35 Skipped`; `ok  github.com/rafpe/kube-oidc-proxy/test/e2e/suite 136.562s` |
| Kubernetes audit events join to proxy access records on the request id, and a reserved identity is recorded as an anomaly | The four `Audit` specs and four `Reserved identity` specs (`test/e2e/suite/cases/audit`, `test/e2e/suite/cases/reservedidentity`) | e2e | Task 20: `make e2e E2E_GOTEST_ARGS='-args --ginkgo.focus="write audit logs to file"'` with `string(ev.AuditID)` mutated to `string(ev.AuditID)+"-mutated"` in the join<br>→ `audit events whose request id has no single request.access.decided record in the proxy log` — three ids reported; `FAIL! -- 0 Passed \| 1 Failed \| 0 Pending \| 43 Skipped` | Task 20, mutation reverted: `make e2e E2E_GOTEST_ARGS='-args --ginkgo.focus="Audit\|Reserved identity"'`<br>→ `SUCCESS! -- 9 Passed \| 0 Failed \| 0 Pending \| 35 Skipped`; `ok  github.com/rafpe/kube-oidc-proxy/test/e2e/suite 181.492s` |

## Coverage

Go reports statement coverage, which is what this repository uses as its line
coverage figure. Both runs below use the identical command — same build tag,
same `-race`, same `-skip` — so the delta is comparable.

```
$ go test -tags logcheck -race \
    -skip 'TestRoundTripperForRestConfigReloadsClientCertificate|TestOIDCHTTPClientReloadsClientCertificate' \
    -coverprofile=/tmp/cover.out ./pkg/... ./cmd/...
ok  	github.com/rafpe/kube-oidc-proxy/pkg/logging	1.617s	coverage: 88.1% of statements
	github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest		coverage: 0.0% of statements
	github.com/rafpe/kube-oidc-proxy/pkg/mocks		coverage: 0.0% of statements
ok  	github.com/rafpe/kube-oidc-proxy/pkg/probe	2.166s	coverage: 96.2% of statements
ok  	github.com/rafpe/kube-oidc-proxy/pkg/proxy	2.221s	coverage: 88.4% of statements
ok  	github.com/rafpe/kube-oidc-proxy/pkg/proxy/audit	5.181s	coverage: 82.7% of statements
ok  	github.com/rafpe/kube-oidc-proxy/pkg/proxy/context	5.565s	coverage: 73.4% of statements
ok  	github.com/rafpe/kube-oidc-proxy/pkg/proxy/hooks	6.456s	coverage: 96.2% of statements
ok  	github.com/rafpe/kube-oidc-proxy/pkg/proxy/logging	2.506s	coverage: 98.8% of statements
ok  	github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview	7.294s	coverage: 97.2% of statements
ok  	github.com/rafpe/kube-oidc-proxy/pkg/proxy/tokenreview	4.097s	coverage: 89.2% of statements
ok  	github.com/rafpe/kube-oidc-proxy/pkg/util/flags	4.161s	coverage: 90.9% of statements
ok  	github.com/rafpe/kube-oidc-proxy/pkg/util/signals	3.227s	coverage: 73.7% of statements
ok  	github.com/rafpe/kube-oidc-proxy/pkg/util/token	2.874s	coverage: 66.7% of statements
ok  	github.com/rafpe/kube-oidc-proxy/cmd/app	8.365s	coverage: 34.3% of statements
ok  	github.com/rafpe/kube-oidc-proxy/cmd/app/options	7.459s	coverage: 87.0% of statements
```

Against the two targets:

- **`pkg/logging` — 88.1%**, above the 80% target.
- **`pkg/proxy` — 79.6% → 88.4%**, an increase, so the no-decrease requirement
  holds.

The repo-wide aggregate over the same package set moved 73.9% → 77.6%. That
number is not the `pkg/logging` target and should not be read against it.

Per-package, before (`origin/main`, `142c160a`) and after, with the covered and
total statement counts behind each percentage:

| Package | Before | After | Covered statements |
| --- | --- | --- | --- |
| `pkg/logging` | (new package) | 88.1% | 126/143 |
| `pkg/probe` | 96.4% | 96.2% | 80/83 → 102/106 |
| `pkg/proxy` | 79.6% | 88.4% | 203/255 → 380/430 |
| `pkg/proxy/audit` | 89.3% | 82.7% | 25/28 → 43/52 |
| `pkg/proxy/context` | 79.0% | 73.4% | 49/62 → 58/79 |
| `pkg/proxy/hooks` | 100.0% | 96.2% | 17/17 → 25/26 |
| `pkg/proxy/logging` | 89.6% | 98.8% | 69/77 → 81/82 |
| `pkg/proxy/subjectaccessreview` | 94.8% | 97.2% | 128/135 → 172/177 |
| `pkg/proxy/tokenreview` | 91.1% | 89.2% | 51/56 → 58/65 |
| `pkg/util/flags` | 90.9% | 90.9% | 30/33 |
| `pkg/util/signals` | 0.0% (no tests) | 73.7% | 0/12 → 14/19 |
| `pkg/util/token` | 66.7% | 66.7% | 12/18 |
| `cmd/app` | 35.0% | 34.3% | 48/137 → 59/172 |
| `cmd/app/options` | 87.9% | 87.0% | 138/157 → 154/177 |
| **total** | **73.9%** | **77.6%** | |

Seven packages show a lower percentage than before: `pkg/probe`,
`pkg/proxy/audit`, `pkg/proxy/context`, `pkg/proxy/hooks`,
`pkg/proxy/tokenreview`, `cmd/app` and `cmd/app/options`. In every one of them
the denominator grew faster than the numerator — the change adds emission
branches, accessors and error paths — while the number of covered statements
rose in all seven (the fourth column). Only `pkg/logging` and `pkg/proxy` carry
a coverage requirement, and both meet it.

`pkg/logging/logtest` reports 0.0% because it is a test-only helper package with
no tests of its own; it is exercised through the six packages that sweep with
`logtest.AssertRegistered`.

Function-level detail for `pkg/logging`:

```
$ go tool cover -func=/tmp/cover.out | grep pkg/logging/
bridge.go:26:	Enabled			100.0%
bridge.go:36:	Handle			100.0%
bridge.go:45:	WithAttrs		  0.0%
bridge.go:50:	WithGroup		  0.0%
bridge.go:64:	InstallKlogBridge	100.0%
component.go:25:	AllComponents		100.0%
events.go:354:	AllEventTypes		100.0%
events.go:364:	Attr			100.0%
events.go:367:	Spec			100.0%
logcheck.go:21:	checkRequired		100.0%
logcheck.go:31:	hasNonEmpty		100.0%
logger.go:35:	Validate		100.0%
logger.go:47:	LevelFor		100.0%
logger.go:56:	New			 72.7%
logger.go:76:	ForComponent		100.0%
logger.go:91:	WithRequestID		100.0%
logger.go:97:	RequestIDFrom		100.0%
logger.go:103:	NewContext		  0.0%
logger.go:110:	FromContext		 66.7%
logger.go:120:	Emit			 75.0%
logger.go:131:	EmitLevel		100.0%
logger.go:148:	withContextRequestID	100.0%
logger.go:161:	hasAttr			100.0%
ratelimit.go:51:	NewLimiter		 66.7%
ratelimit.go:66:	Allow			 91.7%
ratelimit.go:92:	Flush			 75.0%
ratelimit.go:114:	drain			 90.9%
sanitize.go:24:	Sanitize		100.0%
sanitize.go:39:	Bound			 85.7%
sanitize.go:55:	SanitizeList		100.0%
sanitize.go:71:	BoundedList		 88.9%
sanitize.go:88:	ErrAttr			  0.0%
```

`WithAttrs` and `WithGroup` on the klog bridge handler are interface methods the
bridge never calls; `NewContext` and `ErrAttr` are exported helpers used by
callers outside `pkg/logging`.

## Known gaps

- **Cache eviction is not logged.** `pkg/proxy/subjectaccessreview/cache.go`
  wraps `k8s.io/apimachinery/pkg/util/cache.LRUExpireCache`, which exposes no
  eviction callback. An entry dropped by size pressure or TTL expiry produces no
  record; the next lookup is simply a miss.
- **`audit.flush.failed` only fires when the backend exposes an error.** The
  upstream `audit.Backend` interface declares `Shutdown()` with no return value.
  `pkg/proxy/audit` emits `audit.flush.failed` only for a backend that also
  implements `ShutdownErr() error`; a backend that drops events silently is
  reported as `audit.flush.completed`.
- **`termination` is single-valued.** The terminal record carries one
  `termination` chosen by precedence (`panic`, then `hijacked`, then
  `client_cancel`, then a classified upstream reason, else `normal`). A request
  that ends for two reasons at once reports only the first in that order.

## Caveats on the evidence itself

- **`-race` excludes two pre-existing failures.** Every `-race` run above is
  executed with `-skip 'TestRoundTripperForRestConfigReloadsClientCertificate|TestOIDCHTTPClientReloadsClientCertificate'`.
  Both fail on a data race inside client-go's certificate rotation
  (`transport.(*dynamicClientCert).loadClientCert`), reproduced identically on
  the base commit before this work. They are unrelated to structured logging.
- **The shard-b e2e evidence is 20/20, not 22/22, on arm64.** The two `Upgrade`
  specs fail on an arm64 host because
  `gcr.io/google_containers/echoserver:1.10` publishes a single amd64 manifest,
  so the container never starts. CI runs amd64. The shard-b run recorded during
  Task 19 was `20 Passed | 2 Failed` with those two specs the only failures;
  all nine `Logging` specs passed.
- **`test/e2e/framework/helper/kubectl.go` drops `--kubeconfig` for namespaced
  calls.** Pre-existing, unrelated to this change, tracked as a follow-up.
- **A group-only impersonation request returns 500 today.** Observed while
  writing the e2e logging case; pre-existing behaviour, tracked as a follow-up.
