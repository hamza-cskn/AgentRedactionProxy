const PROXY_URL = 'http://127.0.0.1:8787/v1/responses';
const DIRECT_URL = 'https://chatgpt.com/backend-api/codex/responses';
const TOKEN_URL = 'https://auth.openai.com/oauth/token';
const CLIENT_ID = 'app_EMoamEEZ73f0CkXaXp7hrann';

function claims(token) {
  try {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
  } catch {
    return {};
  }
}

function accountId(token) {
  const value = claims(token);
  return value.chatgpt_account_id
    ?? value['https://api.openai.com/auth']?.chatgpt_account_id
    ?? value.organizations?.[0]?.id;
}

export const OpenAIIPv4Proxy = async ({ client }) => {
  const bypass = process.env.ARP_BYPASS === '1';
  if (bypass) console.warn('Agent Redaction Proxy: BYPASS enabled. Requests go directly to OpenAI without redaction or marker restoration.');
  return ({
  'chat.headers': async (input, output) => {
    if (input.model.providerID !== 'openai') return;
    output.headers.originator = 'opencode';
    output.headers['session-id'] = input.sessionID;
  },
  'chat.params': async (input, output) => {
    if (input.model.providerID === 'openai') output.maxOutputTokens = undefined;
  },
  auth: {
    provider: 'openai',
    // Use OpenCode's existing login. To sign in again, temporarily remove this
    // project plugin so OpenCode's built-in OAuth login method is available.
    methods: [],
    async loader(getAuth) {
      const auth = await getAuth();
      if (auth.type !== 'oauth') throw new Error('OpenAI OAuth login is required');
      let refreshPromise;

      return {
        apiKey: 'opencode-oauth',
        async fetch(requestInput, init) {
          const current = await getAuth();
          if (current.type !== 'oauth') throw new Error('OpenAI OAuth login is required');
          let access = current.access;
          let account = current.accountId;

          if (!access || current.expires < Date.now()) {
            refreshPromise ??= (async () => {
              const response = await fetch(TOKEN_URL, {
                method: 'POST',
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({
                  grant_type: 'refresh_token',
                  refresh_token: current.refresh,
                  client_id: CLIENT_ID,
                }),
              });
              if (!response.ok) throw new Error(`OpenAI OAuth refresh failed: ${response.status}`);
              const tokens = await response.json();
              const refreshed = {
                type: 'oauth',
                refresh: tokens.refresh_token,
                access: tokens.access_token,
                expires: Date.now() + (tokens.expires_in ?? 3600) * 1000,
                accountId: accountId(tokens.id_token || tokens.access_token) ?? account,
              };
              await client.auth.set({ path: { id: 'openai' }, body: refreshed });
              return refreshed;
            })().finally(() => { refreshPromise = undefined; });
            const refreshed = await refreshPromise;
            access = refreshed.access;
            account = refreshed.accountId;
          }

          const original = new URL(requestInput instanceof URL
            ? requestInput
            : typeof requestInput === 'string' ? requestInput : requestInput.url);
          const inference = original.pathname === '/v1/responses' || original.pathname === '/responses';
          if (!inference) throw new Error('Unsupported OpenAI OAuth endpoint');
          const headers = new Headers(init?.headers);
          headers.set('authorization', `Bearer ${access}`);
          if (account) headers.set('ChatGPT-Account-Id', account);
          const accessClaims = claims(access);
          const residency = accessClaims['https://api.openai.com/auth']?.chatgpt_compute_residency
            ?? accessClaims.chatgpt_compute_residency;
          if (residency && residency !== 'no_constraint') {
            headers.set('x-openai-internal-codex-residency', residency);
          }
          const url = new URL(`${bypass ? DIRECT_URL : PROXY_URL}${original.search}`);
          return fetch(url, { ...init, headers });
        },
      };
    },
  },
  });
};
