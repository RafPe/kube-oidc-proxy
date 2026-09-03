# Graph Report - kube-oidc-proxy  (2026-09-02)

## Corpus Check
- 184 files · ~136,612 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1051 nodes · 2124 edges · 100 communities (64 shown, 16 thin omitted)
- Extraction: 93% EXTRACTED · 7% INFERRED · 0% AMBIGUOUS · INFERRED: 142 edges (avg confidence: 0.85)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- Proxy Handlers & Access Logging
- Docs: Multi-Issuer & Configuration
- E2E Kind Environment
- Proxy Core: Audit & Serving
- Readiness Probe
- Options Unit Tests
- Run Command & Authenticator Wiring
- Fake OIDC Issuer Server
- Helm Chart Templates & CI Values
- TokenReview Cache & E2E Polling
- E2E Framework Config & Helpers
- E2E Framework TLS & URLs
- Contributing, Maintaining & Fork Model
- Proxy Handler Tests
- SAR Decision Cache Tests
- SubjectAccessReview Fakes
- E2E Kubectl & Image Loading
- SubjectAccessReview Tests
- GitHub Actions OIDC E2E
- Artifact Hub & Release Docs
- SubjectAccessReview Impersonation Checks
- Cherry-Pick Script
- TokenReview Cache Tests
- PR Templates & Release Approval Workflows
- Build, Sign & Publish Workflows
- Lint, Fuzz & Mocks
- Changelog: Caching & Reserved Identity
- Local Demo Run Script
- E2E & Test Workflows
- C4 Component Diagram
- Boilerplate Header Checker
- Reserved Identity Handler Tests
- E2E Proxy Deployment
- Changelog: Audit & Readiness
- App Options & Flags
- Authentication Config Options
- Command Options
- Social Card Image
- Misc Options & Version
- E2E Audit Log Cases
- Release Workflow Jobs
- Forbidden Handler Audit Tests
- Chart Metadata & Project Overview
- Client Options
- Fake TokenReview
- StringToStringSlice Flag
- E2E Namespace Utilities
- Decision Cache
- Version Ldflags Script
- Changelog: Passthrough & Trusted Proxies
- Chart Service & Ingress
- Audit Options
- E2E Auth Config Builder
- Clock Abstraction
- OIDC Authentication Options
- Secure Serving Options
- C4 Container Diagram
- C4 System Context Diagram
- Vendor Update Script
- Token Parsing Utilities
- E2E Reserved Identity Case
- E2E Shared Token Tests
- Security Scanning Workflows
- Issue Templates & Security Policy
- Proxy Constructor Tests
- Audit Webhook Options
- Issuer Command Options
- E2E Service Account Secrets
- E2E Impersonation Client
- Docker Start Wrapper
- Release Contract Check
- E2E Suite Entry
- Cleanup Script
- Release PR Approval Script
- Boilerplate Verify Script
- Dockerfile Boilerplate
- Go Boilerplate
- Makefile Boilerplate
- Python Boilerplate
- Go Module

## God Nodes (most connected - your core abstractions)
1. `Framework` - 44 edges
2. `Proxy` - 21 edges
3. `Kind` - 18 edges
4. `Options` - 17 edges
5. `newCachedSAR()` - 16 edges
6. `KeyBundle` - 16 edges
7. `values.yaml (chart defaults)` - 15 edges
8. `newTestProxy()` - 14 edges
9. `NewCached()` - 14 edges
10. `Audit` - 13 edges

## Surprising Connections (you probably didn't know these)
- `make dev_cluster_* local kind targets` --semantically_similar_to--> `demo/run.sh orchestration`  [INFERRED] [semantically similar]
  docs/operations.md → demo/README.md
- `Automatic Patch Log` --conceptually_related_to--> `docs/releases.md`  [AMBIGUOUS]
  patchlog.txt → .github/workflows/prepare-release.yml
- `Troubleshooting table` --semantically_similar_to--> `Multi-issuer demo README`  [INFERRED] [semantically similar]
  docs/operations.md → demo/README.md
- `Local multi-issuer test: kind and GitHub Actions token` --semantically_similar_to--> `Multi-issuer demo flow (two Dex issuers, one proxy)`  [INFERRED] [semantically similar]
  docs/operations.md → demo/README.md
- `Internal issuer with private CA recipe` --semantically_similar_to--> `Dex issuers dex-a / dex-b`  [INFERRED] [semantically similar]
  docs/multi-issuer.md → demo/README.md

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Sharded, version-matrixed e2e test topology** — _github_workflows_e2e, _github_workflows_e2e_shards, _github_workflows_e2e_shards_shard_partitioning, _github_workflows_e2e_kubernetes_version_matrix, test_e2e_versions_kubernetes_versions, hack_verify_e2e_shards, _github_workflows_e2e_oidc_gha, _github_workflows_test_test [EXTRACTED 1.00]
- **Label-driven release pipeline (fragments -> release/next PR -> tag -> publish)** — _github_release_drafter, _github_release_drafter_release_labels, _github_workflows_pr_release_metadata, _github_workflows_pr_release_metadata_changelog_fragment, _github_workflows_prepare_release, _github_workflows_prepare_release_release_next_branch, _github_workflows_prepare_release_autorelease_pending_label, _github_workflows_claude_review_release_approve, _github_scripts_approve_release_pr, _github_workflows_release, _github_workflows_release_image, changelog [EXTRACTED 1.00]
- **Scheduled supply-chain and security scanning** — _github_workflows_codeql, _github_workflows_scorecard, _github_workflows_security, _github_workflows_fuzz, _github_dependabot [INFERRED 0.85]
- **API-server protection: SAR cache, TokenReview cache, impersonation header cap** — changelog_max_impersonation_header_values, changelog_subject_access_review_cache, changelog_token_passthrough_cache, chart_kube_oidc_proxy_values_maximpersonationheadervalues, chart_kube_oidc_proxy_values_subjectaccessreview, chart_kube_oidc_proxy_values_tokenpassthrough, readme_subjectaccessreview, readme_tokenreview [INFERRED 0.85]
- **Impersonation RBAC contract (ServiceAccount, ClusterRole, extra keys, UID)** — readme_impersonation_not_credential_sharing, chart_kube_oidc_proxy_templates_clusterrole_clusterrole, chart_kube_oidc_proxy_templates_clusterrolebinding_clusterrolebinding, maintaining_originaluser_jetstack_extra_keys, changelog_uid_impersonation, changelog_reserved_identity_guard [INFERRED 0.85]
- **Chart authentication mode selection (single-issuer vs multi-issuer)** — chart_kube_oidc_proxy_readme_mutually_exclusive_auth_modes, chart_kube_oidc_proxy_values_oidc, chart_kube_oidc_proxy_values_authenticationconfig, chart_kube_oidc_proxy_values_oidc_tlsclient, chart_kube_oidc_proxy_templates_deployment_args_mode_switch, chart_kube_oidc_proxy_templates_notes_notes, chart_kube_oidc_proxy_ci_single_issuer_values_single_issuer_fixture, chart_kube_oidc_proxy_ci_multi_issuer_values_multi_issuer_fixture [EXTRACTED 1.00]
- **API-server protection mechanisms (caches, cap, fail-closed rules)** — docs_caching_tokenreview_result_cache, docs_caching_subjectaccessreview_decision_cache, docs_caching_impersonation_header_value_cap, docs_caching_errors_never_cached, docs_caching_bounded_lru, docs_caching_hmac_cache_keys, docs_caching_singleflight [EXTRACTED 1.00]
- **Multi-issuer jwt: entry recipes built on CEL claim mappings and validation rules** — docs_multi_issuer_github_actions_recipe, docs_multi_issuer_teamcity_recipe, docs_multi_issuer_google_service_accounts_recipe, docs_multi_issuer_gke_cluster_issuer_recipe, docs_multi_issuer_internal_issuer_recipe, docs_multi_issuer_gitlab_ci_recipe, docs_multi_issuer_cel_claim_mappings, docs_multi_issuer_claim_validation_rules, docs_multi_issuer_distinct_prefixes [EXTRACTED 1.00]
- **Review-gated release contract flow** — docs_releases_release_labels, docs_releases_changelog_fragments, docs_releases_pr_release_metadata_check, docs_releases_prepare_release_workflow, docs_releases_release_workflow, docs_releases_recovery, docs_releases_release_contract_check [EXTRACTED 1.00]
- **Headline feature badges on the social card** — assets_social_card_kube_oidc_proxy, assets_social_card_multi_issuer, assets_social_card_signed_distroless, assets_social_card_oci_helm_chart [EXTRACTED 1.00]
- **Numbered request flow: 1 authenticate, 2 resolve identity, 3 forward with Impersonate- headers, 4 emit audit events** — docs_c4_diagrams_structurizr_components_secure_serving_layer, docs_c4_diagrams_structurizr_components_authenticator, docs_c4_diagrams_structurizr_components_impersonation_handler, docs_c4_diagrams_structurizr_components_kubernetes_api_server, docs_c4_diagrams_structurizr_components_audit_backend [EXTRACTED 1.00]
- **OIDC failure fallback path: authenticator falls back to token passthrough which validates via TokenReview on the API server** — docs_c4_diagrams_structurizr_components_authenticator, docs_c4_diagrams_structurizr_components_token_passthrough, docs_c4_diagrams_structurizr_components_kubernetes_api_server [EXTRACTED 1.00]
- **OIDC bearer-token authentication flow: user obtains ID token from IdP, sends it via kubectl to kube-oidc-proxy, which validates against IdP JWKS and forwards to the Kubernetes API server for TokenReview/RBAC** — docs_c4_diagrams_structurizr_containers_platform_user, docs_c4_diagrams_structurizr_containers_oidc_issuers_idp, docs_c4_diagrams_structurizr_containers_kube_oidc_proxy, docs_c4_diagrams_structurizr_containers_kubernetes_api_server [EXTRACTED 1.00]
- **Bearer ID token authentication flow: user obtains ID token from IdP, sends it to kube-oidc-proxy, proxy validates against IdP JWKS and forwards to the Kubernetes API server with impersonation** — docs_c4_diagrams_structurizr_systemcontext_platform_user, docs_c4_diagrams_structurizr_systemcontext_oidc_issuer_idp, docs_c4_diagrams_structurizr_systemcontext_kube_oidc_proxy, docs_c4_diagrams_structurizr_systemcontext_kubernetes_api_server [EXTRACTED 1.00]

## Communities (100 total, 16 thin omitted)

### Community 0 - "Proxy Handlers & Access Logging"
Cohesion: 0.06
Nodes (61): funcHandler, ImpersonationRequest, key, bytes.Buffer, k8s.io/client-go/transport.ImpersonationConfig, log/slog.Attr, log/slog.Logger, net/http.Handler (+53 more)

### Community 1 - "Docs: Multi-Issuer & Configuration"
Cohesion: 0.07
Nodes (67): Demo Helm values (proxy-values.yaml), Demo RBAC ClusterRoleBindings, ClusterRoleBinding demo-oidc-a-alice-view, ClusterRoleBinding demo-oidc-b-bob-view, Multi-issuer demo README, Dex issuers dex-a / dex-b, Multi-issuer demo flow (two Dex issuers, one proxy), Dex password grant token minting (+59 more)

### Community 2 - "E2E Kind Environment"
Cohesion: 0.07
Nodes (24): k8s.io/client-go/kubernetes.Clientset, sigs.k8s.io/kind/pkg/apis/config/v1alpha4.Cluster, sigs.k8s.io/kind/pkg/cluster/nodes.Node, sigs.k8s.io/kind/pkg/cluster.Provider, Helper, ImageFor(), Latest(), Supported() (+16 more)

### Community 3 - "Proxy Core: Audit & Serving"
Cohesion: 0.06
Nodes (30): k8s.io/apimachinery/pkg/util/sets.Set, k8s.io/apiserver/pkg/authentication/request/bearertoken.Authenticator, k8s.io/apiserver/pkg/server.CompletedConfig, k8s.io/apiserver/pkg/server.SecureServingInfo, k8s.io/client-go/rest.Config, net/http.Client, net/http.Response, net/http.RoundTripper (+22 more)

### Community 4 - "Readiness Probe"
Cohesion: 0.07
Nodes (31): net/http.HandlerFunc, net/http.Server, sync/atomic.Bool, sync.Mutex, getOnly(), isNotInitialized(), isTransient(), NewServer() (+23 more)

### Community 5 - "Options Unit Tests"
Cohesion: 0.09
Nodes (24): TestAuthenticationConfigLoad(), TestAuthenticationConfigLoadMissingFile(), writeAuthConfig(), TestOIDCAuthenticationOptions_Validate(), TestOIDCAuthenticationOptionsValidateTLSClientCredentials(), TestOidcFlagsChanged(), TestValidate_MaxImpersonationHeaderValues(), TestValidate_MutualExclusivity() (+16 more)

### Community 6 - "Run Command & Authenticator Wiring"
Cohesion: 0.14
Nodes (23): caFromFile, buildRunCommand(), buildSingleAuther(), buildTokenAuther(), buildUnionAuther(), caContentProvider(), checkReservedIdentityPrefixes(), jwtAuthenticatorFromOIDCOptions() (+15 more)

### Community 7 - "Fake OIDC Issuer Server"
Cohesion: 0.10
Nodes (12): main(), crypto/rsa.PrivateKey, Issuer, Handler(), Server, Sink, main(), New() (+4 more)

### Community 8 - "Helm Chart Templates & CI Values"
Cohesion: 0.16
Nodes (25): CI fixture: multi-issuer values, CI fixture: single-issuer values, Hardened SecurityContext by default, kube-oidc-proxy Helm chart README, High-availability guidance (PDB + topology spread), Mutually exclusive single-issuer / multi-issuer chart modes, ClusterRoleBinding template, Deployment args: --authentication-config vs --oidc-* switch (+17 more)

### Community 9 - "TokenReview Cache & E2E Polling"
Cohesion: 0.15
Nodes (16): hash.Hash, k8s.io/api/authentication/v1.UserInfo, k8s.io/apimachinery/pkg/util/cache.LRUExpireCache, k8s.io/apiserver/pkg/authentication/authenticator.Response, k8s.io/client-go/kubernetes/typed/authentication/v1.TokenReviewInterface, sync.Pool, time.Duration, cacheKey() (+8 more)

### Community 10 - "E2E Framework Config & Helpers"
Cohesion: 0.20
Nodes (11): k8s.io/client-go/kubernetes.Interface, Config, CasesDescribe(), Framework, NewDefaultFramework(), NewFramework(), newFramework(), NewOrderedDefaultFramework() (+3 more)

### Community 11 - "E2E Framework TLS & URLs"
Cohesion: 0.17
Nodes (6): k8s.io/api/core/v1.Namespace, net.IP, net/url.URL, Helper, KeyBundle, NewTLSSelfSignedCertKey()

### Community 12 - "Contributing, Maintaining & Fork Model"
Cohesion: 0.15
Nodes (19): End-to-end UID impersonation (Impersonate-Uid), ClusterRole template (impersonation RBAC), Contributor Covenant Code of Conduct v1.4, CI gates: unit tests, e2e, govulncheck, Helm checks, Contributing guide, hack/cherry-pick-pull.sh, Fork independence model, Maintaining this fork (+11 more)

### Community 13 - "Proxy Handler Tests"
Cohesion: 0.15
Nodes (15): github.com/rafpe/kube-oidc-proxy/pkg/mocks.MockToken, go.uber.org/mock/gomock.Controller, newFakeR(), newFakeRW(), TestError(), TestHandlers(), TestHasImpersonation(), TestHeadersConfig() (+7 more)

### Community 14 - "SAR Decision Cache Tests"
Cohesion: 0.29
Nodes (17): k8s.io/apiserver/pkg/authentication/user.DefaultInfo, cacheTestRequester(), failWith(), impersonateUserRequest(), newCachedSAR(), TestCacheAllowHitAndExpiry(), TestCachedAllowNotInheritedAcrossUID(), TestCachedAllowNotLeakedAcrossNaiveCollision() (+9 more)

### Community 15 - "SubjectAccessReview Fakes"
Cohesion: 0.23
Nodes (10): context.Context, k8s.io/api/authorization/v1.SubjectAccessReview, k8s.io/apimachinery/pkg/apis/meta/v1.CreateOptions, sync/atomic.Int64, allowAll(), denyAll(), countingReviewer, fnReviewer (+2 more)

### Community 16 - "E2E Kubectl & Image Loading"
Cohesion: 0.20
Nodes (4): io.Writer, Kubectl, Helper, Kind

### Community 17 - "SubjectAccessReview Tests"
Cohesion: 0.18
Nodes (16): sync/atomic.Int32, FakeReviewer, New(), impersonationHeaders(), runTest(), TestCheckAuthorizedForImpersonationCanceled(), TestCheckAuthorizedForImpersonationConfiguredTimeout(), TestCheckAuthorizedForImpersonationDeadlineExceeded() (+8 more)

### Community 18 - "GitHub Actions OIDC E2E"
Cohesion: 0.26
Nodes (15): e2e-oidc-gha workflow, GHA_AUDIENCE Audience Matching, mint-oidc-token workflow, b64url_decode(), check_identity(), fail(), jwt_claim(), log() (+7 more)

### Community 19 - "Artifact Hub & Release Docs"
Cohesion: 0.23
Nodes (16): Publishing on Artifact Hub, Cosign keyless signing of chart and image, oras push of Artifact Hub ownership metadata to GHCR, Artifact Hub Verified Publisher ownership (artifacthub-repo.yml), Helm install (OCI registry, local checkout, raw manifests), docs/releases.md, .changes/unreleased/*.yaml changelog fragments, PR Release Metadata required check (+8 more)

### Community 20 - "SubjectAccessReview Impersonation Checks"
Cohesion: 0.21
Nodes (8): golang.org/x/sync/singleflight.Group, k8s.io/api/authorization/v1.SubjectAccessReviewSpec, k8s.io/apiserver/pkg/authentication/user.Info, k8s.io/client-go/kubernetes/typed/authorization/v1.SubjectAccessReviewInterface, countImpersonationHeaderValues(), SubjectAccessReview, impersonationReviewSpec(), ImpersonationAuthError

### Community 21 - "Cherry-Pick Script"
Cohesion: 0.15
Nodes (13): BRANCH, join(), KUBE_ROOT, make-a-pr(), NEWBRANCH, NEWBRANCHREQ, NEWBRANCHUNIQ, PULLDASH (+5 more)

### Community 22 - "TokenReview Cache Tests"
Cohesion: 0.29
Nodes (14): NewCached(), authenticatedReview(), TestAuthenticateToken(), TestCachedReviewBoundsEntryCount(), TestCachedReviewConcurrentMissesRunIndependently(), TestCachedReviewHonoursCallerCancellation(), TestCachedReviewHonoursTimeoutAboveThirtySeconds(), TestCachedReviewSendsConfiguredAudiences() (+6 more)

### Community 23 - "PR Templates & Release Approval Workflows"
Cohesion: 0.26
Nodes (14): Pull Request Template, Release Drafter Config, release/* PR Labels, .github/scripts/approve-release-pr.sh, Claude Review workflow, review:claude job, review:release-approve job, Untrusted PR Content / Fork No-Auto-Approve Guard (+6 more)

### Community 24 - "Build, Sign & Publish Workflows"
Cohesion: 0.23
Nodes (12): build workflow, build:image job, Cosign Keyless Signing and SBOM Attachment, helm-chart workflow, release-image workflow, release-image chart job, release-image image job, chart/kube-oidc-proxy/Chart.yaml (+4 more)

### Community 25 - "Lint, Fuzz & Mocks"
Cohesion: 0.22
Nodes (10): fuzz workflow, test workflow, lint:go job, golangci-lint Config, testing.F, pkg/mocks/authenticator.go (generated Token mock), FuzzParseTrustedProxies(), countFields() (+2 more)

### Community 26 - "Changelog: Caching & Reserved Identity"
Cohesion: 0.22
Nodes (13): --allow-reserved-groups (replaces --allow-reserved-identity-claims), CHANGELOG, --max-impersonation-header-values cap (HTTP 431), Reserved system: identity guard, SubjectAccessReview decision cache (allow/deny TTLs), TokenReview result cache (success/failure TTLs), Release 1.4.0 (2026-08-20), Release 1.6.0 (2026-09-01) (+5 more)

### Community 27 - "Local Demo Run Script"
Cohesion: 0.38
Nodes (12): check_identity(), cleanup_pf(), fail(), gen_cert(), log(), mint_token(), ok(), port_forward() (+4 more)

### Community 28 - "E2E & Test Workflows"
Cohesion: 0.30
Nodes (11): e2e workflow, test:e2e aggregator job, test:e2e @ <version> job, test:e2e:versions job, Kubernetes Version Matrix from Manifest, e2e-shards workflow, Ginkgo Shard Label Partitioning, test:unit job (+3 more)

### Community 29 - "C4 Component Diagram"
Cohesion: 0.36
Nodes (12): C4 Component Diagram: kube-oidc-proxy request-handling components, Audit backend (Go, k8s audit) - records authenticated and unauthenticated requests, Authenticator (Go, bearertoken + OIDC union) - validates bearer token against union of N OIDC issuers, Impersonation handler (Go) - builds impersonation config and forwards the request, kube-oidc-proxy (Container boundary), Kubernetes API server (Software System) - managed control plane running TokenReview, SubjectAccessReview and RBAC for the impersonated identity, OIDC issuer(s) / IdP (Software System) - Dex, Okta, GitHub Actions OIDC; issues ID tokens and publishes JWKS, Platform user (Person) - runs kubectl carrying an OIDC ID token (+4 more)

### Community 30 - "Boilerplate Header Checker"
Cohesion: 0.27
Nodes (9): file_extension(), file_passes(), get_files(), get_refs(), get_regexs(), main(), normalize_files(), Note: run this test from the hack/boilerplate directory. $ python -m unittest… (+1 more)

### Community 31 - "Reserved Identity Handler Tests"
Cohesion: 0.40
Nodes (10): captureKlogAtV2(), reservedIdentityRequest(), TestOverCapImpersonationRejectedBeforeSubjectAccessReview(), TestReservedIdentityRejectedBeforeSubjectAccessReview(), TestWithAuthenticateRequestAllowsAllowlistedReservedGroup(), TestWithAuthenticateRequestLogsValidationFailureAtV2(), TestWithAuthenticateRequestRejectsReservedIdentity(), TestWithImpersonateRequestDoesNotMutateAuthenticatorUser() (+2 more)

### Community 32 - "E2E Proxy Deployment"
Cohesion: 0.24
Nodes (6): k8s.io/api/core/v1.Container, k8s.io/api/core/v1.ServiceType, k8s.io/api/core/v1.Volume, k8s.io/api/core/v1.VolumeMount, ProxyExtras, nodePortFor()

### Community 33 - "Changelog: Audit & Readiness"
Cohesion: 0.31
Nodes (9): Core API group (/api) audit RequestInfo classification fix, Audit streaming requests as long-running (ResponseStarted), Readiness reports not-ready until the proxy is serving, OIDC token validation failures logged at -v=2 with remote address, Release 1.3.0 (2026-08-19), Deployment readiness probe (GET /ready on 8080), Configurable readiness (first issuer vs all issuers), Multi-issuer OIDC authentication (+1 more)

### Community 34 - "App Options & Flags"
Cohesion: 0.42
Nodes (5): NewKubeOIDCProxyOptions(), github.com/spf13/pflag.FlagSet, ExtraHeaderOptions, KubeOIDCProxyOptions, TokenPassthroughOptions

### Community 35 - "Authentication Config Options"
Cohesion: 0.28
Nodes (4): NewAuthenticationConfigOptions(), k8s.io/apiserver/pkg/apis/apiserver.AuthenticationConfiguration, k8s.io/apiserver/pkg/authentication/cel.Compiler, AuthenticationConfigOptions

### Community 36 - "Command Options"
Cohesion: 0.33
Nodes (3): Options, github.com/spf13/cobra.Command, Options

### Community 37 - "Social Card Image"
Cohesion: 0.32
Nodes (8): Social Card (repository preview image), kube-oidc-proxy, Managed Kubernetes without access to API server --oidc flags, Mascot: blue blob holding a key and a shield in front of a Kubernetes wheel, Multi-issuer (one proxy, many issuers), OCI Helm chart, OIDC Authentication Proxy for Kubernetes, Signed, distroless container image

### Community 38 - "Misc Options & Version"
Cohesion: 0.32
Nodes (4): NewMiscOptions(), New(), TestBuildUnionAutherFromV1ConfigWithCEL(), MiscOptions

### Community 39 - "E2E Audit Log Cases"
Cohesion: 0.39
Nodes (7): k8s.io/api/core/v1.Pod, deployProxyWithAuditLogFile(), newExecRestConfig(), proxyPod(), readAuditLog(), singlePod(), testAuditLogs()

### Community 40 - "Release Workflow Jobs"
Cohesion: 0.71
Nodes (7): Release workflow, release:check job, release:e2e job, release:artifact job, release:publish job, release:tag job, release:verify job

### Community 41 - "Forbidden Handler Audit Tests"
Cohesion: 0.52
Nodes (6): forbiddenAuditEvent, newForbiddenTestAudit(), readForbiddenAuditEvents(), TestNewForbiddenHandlerAuditsAuthenticatedIdentity(), TestNewForbiddenHandlerWithoutAuditor(), TestNewUnauthenticatedHandlerAuditsFailedAuthentication()

### Community 42 - "Chart Metadata & Project Overview"
Cohesion: 0.29
Nodes (7): Artifact Hub repository metadata (Verified Publisher), Artifact Hub chart annotations, Chart.yaml (kube-oidc-proxy Helm chart metadata), Chart and image share one version, Impersonation instead of credential sharing, kube-oidc-proxy (project overview), Label-driven, review-gated release process

### Community 43 - "Client Options"
Cohesion: 0.43
Nodes (4): clientOptionFlags(), NewClientOptions(), k8s.io/cli-runtime/pkg/genericclioptions.ConfigFlags, ClientOptions

### Community 44 - "Fake TokenReview"
Cohesion: 0.48
Nodes (3): k8s.io/api/authentication/v1.TokenReview, FakeReviewer, New()

### Community 45 - "StringToStringSlice Flag"
Cohesion: 0.29
Nodes (3): stringToStringSliceValue, github.com/spf13/pflag.Value, NewStringToStringSliceValue()

### Community 46 - "E2E Namespace Utilities"
Cohesion: 0.29
Nodes (3): k8s.io/apimachinery/pkg/util/wait.ConditionWithContextFunc, Framework, namespaceNotExist()

### Community 47 - "Decision Cache"
Cohesion: 0.33
Nodes (4): k8s.io/apimachinery/pkg/util/cache.Clock, newDecisionCache(), TestDecisionCacheKeyCollisionResistance(), decisionCache

### Community 48 - "Version Ldflags Script"
Cohesion: 0.43
Nodes (5): kube::version::get_version_vars(), kube::version::ldflag(), kube::version::ldflags(), kube::version::load_version_vars(), version.sh script

### Community 49 - "Changelog: Passthrough & Trusted Proxies"
Cohesion: 0.40
Nodes (6): Supported Kubernetes window in PR e2e (1.37/1.36/1.35), --token-passthrough-request-timeout, --trusted-proxies contract for audit sourceIPs, Audit events for unauthenticated (401) requests, Release 1.5.0 (2026-08-28), test/e2e/versions/kubernetes-versions.json (single source of truth)

### Community 50 - "Chart Service & Ingress"
Cohesion: 0.40
Nodes (6): Ingress template, NOTES.txt (post-install notes), Service template (https port -> 8443), Helm test pod (wget connection test), values.ingress, values.service (type, port 443, traffic policies)

### Community 51 - "Audit Options"
Cohesion: 0.47
Nodes (4): AuditOptions, NewAuditOptions(), k8s.io/apiserver/pkg/server/options.AuditOptions, k8s.io/component-base/cli/flag.NamedFlagSets

### Community 52 - "E2E Auth Config Builder"
Cohesion: 0.33
Nodes (5): k8s.io/apiserver/pkg/apis/apiserver/v1.AuthenticationConfiguration, k8s.io/apiserver/pkg/apis/apiserver/v1.JWTAuthenticator, authConfig(), configMapVolume(), jwtAuthenticator()

### Community 53 - "Clock Abstraction"
Cohesion: 0.40
Nodes (3): time.Time, fakeClock, realClock

### Community 55 - "Secure Serving Options"
Cohesion: 0.60
Nodes (3): NewSecureServingOptions(), k8s.io/apiserver/pkg/server/options.SecureServingOptions, SecureServingOptions

### Community 56 - "C4 Container Diagram"
Cohesion: 0.90
Nodes (5): C4 Container View: kube-oidc-proxy (diagram), kube-oidc-proxy (Container: Go) - reverse proxy validating OIDC tokens against the union of issuers and impersonating the mapped user to the API server, Kubernetes API server (Software System) - managed control plane running TokenReview, SubjectAccessReview and RBAC for the impersonated identity, OIDC issuer(s) / IdP (Software System) - Dex, Okta, GitHub Actions OIDC; issues ID tokens and publishes JWKS, Platform user (Person) - runs kubectl carrying an OIDC ID token

### Community 57 - "C4 System Context Diagram"
Cohesion: 0.80
Nodes (5): System Context View: kube-oidc-proxy (C4 diagram), kube-oidc-proxy (Software System) - authenticates the bearer token and impersonates the mapped user to the API server, Kubernetes API server (Software System) - managed control plane; runs TokenReview, SubjectAccessReview and RBAC for the impersonated identity, OIDC issuer(s) / IdP (Software System) - Dex, Okta, GitHub Actions OIDC; issues ID tokens and publishes JWKS, Platform user (Person) - runs kubectl carrying an OIDC ID token

### Community 58 - "Vendor Update Script"
Cohesion: 0.40
Nodes (4): GO111MODULE, GOFLAGS, GOPATH, update-vendor.sh script

### Community 59 - "Token Parsing Utilities"
Cohesion: 0.40
Nodes (3): FakeJWT(), ParseFromRequest(), TestParseFromRequest()

### Community 60 - "E2E Reserved Identity Case"
Cohesion: 0.40
Nodes (4): grantPodList(), listPods(), proxyLogs(), signedTokenFor()

### Community 61 - "E2E Shared Token Tests"
Cohesion: 0.70
Nodes (4): ExpectProxyAuthenticated(), expectUnauthorized(), proxyGetPods(), RunTokenValidationTests()

### Community 62 - "Security Scanning Workflows"
Cohesion: 0.50
Nodes (4): Dependabot Config, codeql workflow, scorecard workflow, security workflow

### Community 63 - "Issue Templates & Security Policy"
Cohesion: 0.50
Nodes (4): Bug Report Issue Template, Issue Template Config, Feature Request Issue Template, SECURITY.md

### Community 64 - "Proxy Constructor Tests"
Cohesion: 0.83
Nodes (3): TestNewCopiesExtraUserHeaders(), TestNewValidatesDependencies(), validDeps()

## Ambiguous Edges - Review These
- `docs/releases.md` → `Automatic Patch Log`  [AMBIGUOUS]
  patchlog.txt · relation: conceptually_related_to
- `Publishing on Artifact Hub` → `Release workflow (tag, publish image/chart, GitHub Release)`  [AMBIGUOUS]
  docs/artifact-hub.md · relation: references

## Knowledge Gaps
- **58 isolated node(s):** `approve-release-pr.sh script`, `cleanup.sh script`, `github.com/rafpe/kube-oidc-proxy`, `KUBE_ROOT`, `STARTINGBRANCH` (+53 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 176 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **16 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `docs/releases.md` and `Automatic Patch Log`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **What is the exact relationship between `Publishing on Artifact Hub` and `Release workflow (tag, publish image/chart, GitHub Release)`?**
  _Edge tagged AMBIGUOUS (relation: references) - confidence is low._
- **Why does `test workflow` connect `Lint, Fuzz & Mocks` to `Build, Sign & Publish Workflows`, `E2E & Test Workflows`?**
  _High betweenness centrality (0.126) - this node is a cross-community bridge._
- **Why does `Framework` connect `E2E Framework Config & Helpers` to `E2E Proxy Deployment`, `Proxy Core: Audit & Serving`, `E2E Impersonation Client`, `E2E Audit Log Cases`, `E2E Framework TLS & URLs`, `E2E Reserved Identity Case`, `E2E Shared Token Tests`?**
  _High betweenness centrality (0.121) - this node is a cross-community bridge._
- **What connects `approve-release-pr.sh script`, `cleanup.sh script`, `github.com/rafpe/kube-oidc-proxy` to the rest of the system?**
  _58 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Proxy Handlers & Access Logging` be split into smaller, more focused modules?**
  _Cohesion score 0.05721168322794339 - nodes in this community are weakly interconnected._
- **Should `Docs: Multi-Issuer & Configuration` be split into smaller, more focused modules?**
  _Cohesion score 0.07146087743102668 - nodes in this community are weakly interconnected._