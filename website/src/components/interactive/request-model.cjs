/* Shared by the request explorer and Node's built-in test runner. */
const FlowModel = (() => {
  const entry = ['client','requestid','info','lifecycle','headers','auth'];
  const tail = ['audit','reverse','transport','upstream','response'];
  const paths = {
    oidc: [...entry,'guard','impersonate',...tail],
    impersonation: [...entry,'guard','sar','impersonate',...tail],
    denied: [...entry,'guard','sar','forbidden','response'],
    missing: [...entry,'unauthorized','response'],
    invalid: [...entry,'review','unauthorized','response'],
    reserved: [...entry,'guard','forbidden','response'],
    passthrough: [...entry,'review','skip',...tail],
    disabled: [...entry,'guard','skip',...tail],
    failure: [...entry,'guard','impersonate','audit','reverse','transport','badgateway','response'],
    watch: [...entry,'guard','impersonate',...tail],
    startup: ['boot','config','wiring','chain'],
  };
  return { paths };
})();
if (typeof module !== 'undefined') module.exports = FlowModel;
