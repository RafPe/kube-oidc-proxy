const repository = 'my-org/my-repo';
const ciUser = `gha:${repository}:refs/heads/main`;
const ciGroups = ['gha:org:my-org', `gha:repo:${repository}`];
export const examples = {
  alice: {label:'Dex A: Alice',username:'oidc-a:alice@example.com',groups:[],kind:'User',subject:'oidc-a:alice@example.com',binding:'demo-oidc-a-alice-view',source:'start/multi-issuer-demo/',mapping:'email = alice@example.com → username prefix oidc-a: → oidc-a:alice@example.com. The demo binds this User directly. No group membership is required.'},
  bob: {label:'Dex B: Bob',username:'oidc-b:bob@example.com',groups:[],kind:'User',subject:'oidc-b:bob@example.com',binding:'demo-oidc-b-bob-view',source:'start/multi-issuer-demo/',mapping:'email = bob@example.com → username prefix oidc-b: → oidc-b:bob@example.com. Username and group prefixes are separate configuration fields.'},
  github: {label:'GitHub Actions: repository group',username:ciUser,groups:ciGroups,kind:'Group',subject:`gha:repo:${repository}`,binding:'ci-readers',source:'start/getting-started/#5-give-one-identity-a-role',mapping:'repository + ref produce the username. repository_owner and repository produce the two groups through CEL expressions. No groups claim is required.'},
  impersonation: {label:'GitHub Actions: --as=ci-viewer',username:ciUser,groups:ciGroups,kind:'User',subject:'ci-viewer',binding:'ci-viewer-view',source:'guides/authentication/#inbound-impersonation-kubectl---as',mapping:'The GitHub Actions mapping identifies the caller. The documented gha:repo:my-org/my-repo grant permits impersonation of the user ci-viewer only.'},
};
export const defaults = {example:'alice',kind:'User',subject:examples.alice.subject,bindingScope:'cluster',namespace:'all',resource:'pods',verb:'list',proxyGrant:true,callerGrant:true,target:'ci-viewer'};
export function exampleDefaults(example) {
  const preset = examples[example];
  return {...defaults,example,kind:preset.kind,subject:preset.subject};
}

// Restricted to the documented view examples and the request choices in the form.
export function evaluateIdentity(input = {}) {
  const s = {...exampleDefaults(input.example || defaults.example),...input};
  const preset = examples[s.example];
  const inbound = {username:preset.username,groups:[...preset.groups,'system:authenticated']};
  const explicit = s.example === 'impersonation';
  const callerAllowed = !explicit || (s.callerGrant && inbound.groups.includes('gha:repo:my-org/my-repo') && s.target === 'ci-viewer');
  const username = explicit ? s.target : inbound.username;
  const groups = explicit ? ['system:authenticated'] : inbound.groups;
  const forwarded = callerAllowed;
  const subjectMatches = s.kind === 'User' ? s.subject === username : s.kind === 'Group' && groups.includes(s.subject);
  const scopeMatches = s.bindingScope === 'cluster' || s.namespace === 'development';
  const ruleMatches = s.resource === 'pods' && ['get','list','watch'].includes(s.verb);
  const bindingAllows = subjectMatches && scopeMatches && ruleMatches;
  const validRequest = s.namespace !== 'all' || ['list','watch'].includes(s.verb);
  const allowed = validRequest && forwarded && s.proxyGrant && bindingAllows;
  const checks = [
    [callerAllowed, explicit ? `Caller impersonation: the documented grant permits ci-viewer only. ${callerAllowed ? 'The caller has this grant.' : 'The grant is absent or the requested target differs.'}` : 'Caller impersonation: no --as headers. The proxy sends no SubjectAccessReview.'],
    [s.proxyGrant, 'Proxy impersonation: the API server checks the proxy credential against every outbound identity header.'],
    [subjectMatches, `${s.kind} subject ${JSON.stringify(s.subject)} ${subjectMatches ? 'matches' : 'does not match'} the effective identity.`],
    [scopeMatches, s.bindingScope === 'cluster' ? 'The ClusterRoleBinding grants view across namespaces, including an all-namespaces list.' : `The RoleBinding grants view only in development. Request scope: ${s.namespace}.`],
    [ruleMatches, `The default view role grants get, list, and watch on pods. It does not grant delete on pods or access to Secrets.`],
  ];
  const verdict = !validRequest ? 'Choose a namespace for a single-object get or delete request.' : !callerAllowed ? 'Stopped at proxy: caller cannot impersonate this target (403).' : !s.proxyGrant ? 'Rejected upstream: proxy cannot impersonate the outbound identity (403).' : bindingAllows ? 'Resource request permitted by the example RBAC.' : 'Resource request not granted by the example binding.';
  return {inbound,username,groups,forwarded,allowed,verdict,checks,subjectMatches,scopeMatches,ruleMatches};
}

export function bindingYaml(input) {
  const s = {...exampleDefaults(input.example || defaults.example),...input};
  return `apiVersion: rbac.authorization.k8s.io/v1\nkind: ${s.bindingScope === 'cluster' ? 'ClusterRoleBinding' : 'RoleBinding'}\nmetadata:\n  name: ${examples[s.example].binding}${s.bindingScope === 'cluster' ? '' : '\n  namespace: development'}\nsubjects:\n  - kind: ${s.kind}\n    name: ${JSON.stringify(s.subject)}\n    apiGroup: rbac.authorization.k8s.io\nroleRef:\n  kind: ClusterRole\n  name: view\n  apiGroup: rbac.authorization.k8s.io`;
}
