// Finds secrets in text without asking a model, since asking one would send the secret to the API.

export const MARK = '‹secret:'

export const makeLabeler = () => {
  const labels = new Map<string, string>()
  return (secret: string) => {
    let label = labels.get(secret)
    if (label === undefined) {
      label = `${MARK}${labels.size + 1}›`
      labels.set(secret, label)
    }
    return label
  }
}

const SECRET_WORDS = new Set(['secret', 'token', 'password', 'passwd', 'pwd', 'apikey', 'credential', 'credentials'])
const KEY_OWNERS = new Set(['api', 'access', 'private', 'auth', 'secret', 'signing', 'encryption', 'master'])

// True when a name ends in a secret word: DB_PWD, apiKey, aws_secret_access_key, _authToken.
// TOKEN_ENDPOINT, AUTH_TOKEN_TYPE and API_KEY_HEADER don't.
export const isSecretName = (name: string) => {
  const words = name
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean)
  const last = words.at(-1) ?? ''
  return SECRET_WORDS.has(last) || (last === 'key' && KEY_OWNERS.has(words.at(-2) ?? ''))
}

const entropy = (v: string) => {
  const counts = new Map<string, number>()
  for (const ch of v) counts.set(ch, (counts.get(ch) ?? 0) + 1)
  let bits = 0
  for (const n of counts.values()) bits -= (n / v.length) * Math.log2(n / v.length)
  return bits
}

const looksRandom = (v: string) =>
  v.length >= 12 && /^[A-Za-z0-9+/=_-]+$/.test(v) && /\d/.test(v) && /[A-Za-z]/.test(v) && entropy(v) >= 3.5

const URL_PASSWORD = /((?<![a-z0-9+.-])[a-z][a-z0-9+.-]{0,30}:\/\/[^\s:/@'"]{1,256}:)([^\s@/'"]{1,256})(@)/i

// /Users/me/project or ./bin/run: slash-separated with at least one plain lowercase word, which
// a base64 secret that happens to start with a slash almost never has.
const isPath = (v: string) => /^(?:~|\.{1,2})?(?:\/[\w.@-]+)+\/?$/.test(v) && /\/[a-z]{3,}(?:\/|$)/.test(v)

const PLACEHOLDER = /^(?:\$|%|<|\{\{|\*{3}|x{3,}|changeme|password|example|your[_-]|dummy|test(?:ing)?$)/i
const isPlaceholder = (v: string) => PLACEHOLDER.test(v) || v.includes(MARK)

// A quoted constant in code such as "auth_token" or "X_API_KEY" names a secret; it isn't one.
const isConstantName = (v: string) => /^[a-z_.-]+$/.test(v) || /^[A-Z_.-]+$/.test(v)

// Whether a value assigned to a name could be a secret. `strict` also wants it token-shaped,
// for unquoted values where code like `token: userToken1` would otherwise match.
export const isPlausibleSecret = (v: string, { strict = false } = {}) =>
  v.length >= 8 &&
  !isPlaceholder(v) &&
  !/^\d+$/.test(v) &&
  !/^[A-Za-z_$][\w$]*(?:\.[\w$]+)+$/.test(v) &&
  !isPath(v) &&
  !(/^[a-z][a-z0-9+.-]*:\/\//i.test(v) && !URL_PASSWORD.test(v)) &&
  (!strict || looksRandom(v))

// The name a context rule's `before` group ends with, e.g. `apiKey` in `const apiKey = "`.
const nameIn = (before: string) => /([\w.-]{1,64})["']?\s*[:=]\s*["']?$/.exec(before)?.[1] ?? ''

type Rule = {
  kind: string
  // Groups: what stays before (a token's prefix stays visible), the secret, what stays after.
  re: RegExp
  accept?: (secret: string, before: string) => boolean
}

const RULES: Rule[] = [
  { kind: 'private-key', re: /(-----BEGIN [A-Z ]*PRIVATE KEY-----)([\s\S]+?)(-----END [A-Z ]*PRIVATE KEY-----)/g },
  { kind: 'anthropic', re: /(\bsk-ant-)([A-Za-z0-9_-]{20,})()/g },
  { kind: 'openai', re: /(\bsk-)((?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,})()/g },
  { kind: 'github', re: /(\b(?:ghp|gho|ghu|ghs|ghr)_|\bgithub_pat_)([A-Za-z0-9_]{36,})()/g },
  { kind: 'gitlab', re: /(\bglpat-)([A-Za-z0-9_-]{20,})()/g },
  { kind: 'aws-key-id', re: /(\b(?:AKIA|ASIA))([A-Z0-9]{16})(\b)/g },
  { kind: 'stripe', re: /(\b(?:sk|rk)_(?:live|test)_)([A-Za-z0-9]{16,})()/g },
  { kind: 'slack', re: /(\bxox[abposr]-)([A-Za-z0-9-]{10,})()/g },
  { kind: 'slack-webhook', re: /(https:\/\/hooks\.slack\.com\/services\/)([A-Za-z0-9/]{20,})()/g },
  { kind: 'google', re: /(\bAIza)([0-9A-Za-z_-]{35})()/g },
  { kind: 'npm', re: /(\bnpm_)([A-Za-z0-9]{36})()/g },
  { kind: 'sendgrid', re: /(\bSG\.)([\w-]{22}\.[\w-]{43})()/g },
  { kind: 'jwt', re: /()(\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})()/g },
  { kind: 'url-password', re: new RegExp(URL_PASSWORD.source, 'gi'), accept: v => !isPlaceholder(v) },
  {
    kind: 'auth-header',
    re: /((?:authorization|x-api-key|api-key)["']?\s*[:=]\s*["']?(?:bearer\s+|basic\s+|token\s+)?)([A-Za-z0-9._~+/=-]{16,})()/gi,
    accept: v => !isPlaceholder(v),
  },
  {
    kind: 'assigned',
    // The lookbehind starts the name at the head of a word run, keeping long runs linear.
    re: /((?<![\w.-])[\w.-]{1,64}["']?\s*[:=]\s*["'])([^"'\s]{8,})(["'])/g,
    accept: (v, before) => isSecretName(nameIn(before)) && isPlausibleSecret(v) && !isConstantName(v),
  },
  {
    kind: 'assigned',
    re: /(^[ \t]*(?:export[ \t]+)?[\w.-]{1,64}[ \t]*[:=][ \t]*)([^\s"'#,;()]{12,})()/gm,
    accept: (v, before) => isSecretName(nameIn(before)) && isPlausibleSecret(v, { strict: true }),
  },
]

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

// One pattern for all known values, longest first so a value containing another is masked whole.
export const compileKnown = (values: Iterable<string>): RegExp | undefined => {
  const sorted = [...new Set(values)].filter(v => v.length >= 4).sort((a, b) => b.length - a.length)
  return sorted.length === 0 ? undefined : new RegExp(sorted.map(escapeRe).join('|'), 'g')
}

export const redact = (text: string, known: RegExp | undefined, label: (secret: string) => string) => {
  const kinds: string[] = []
  let out = known
    ? text.replace(known, value => {
        kinds.push('known')
        return label(value)
      })
    : text

  for (const rule of RULES) {
    out = out.replace(rule.re, (whole, before: string, secret: string, after: string) => {
      if (secret.includes(MARK) || (rule.accept && !rule.accept(secret, before))) return whole
      kinds.push(rule.kind)
      return before + label(secret) + after
    })
  }
  return { text: out, kinds }
}

// Values worth masking from KEY=VALUE lines (.env, ini, `env` output): URL passwords, values of
// secret names, and token-shaped values under any name unless `namedOnly`.
export const valuesFromAssignments = (text: string, { namedOnly = false } = {}) => {
  const found = new Set<string>()
  for (const line of text.split('\n')) {
    const m = /^\s*(?:export\s+)?([\w./:-]+)\s*[=:]\s*(.*?)\s*$/.exec(line)
    if (!m || line.trim().startsWith('#')) continue
    const key = m[1] ?? ''
    const value = (m[2] ?? '').replace(/^(['"])(.*)\1$/, '$2')

    const url = URL_PASSWORD.exec(value)
    if (url) {
      const password = url[2] ?? ''
      if (!isPlaceholder(password)) found.add(password).add(safeDecode(password))
    } else if (isSecretName(key) ? isPlausibleSecret(value) : !namedOnly && isPlausibleSecret(value, { strict: true })) {
      found.add(value)
    }
  }
  return [...found]
}

// ~/.netrc: `machine host login me password secret`.
export const valuesFromNetrc = (text: string) => [...text.matchAll(/\bpassword\s+(\S+)/g)].map(m => m[1] ?? '')

// ~/.pgpass: host:port:db:user:password.
export const valuesFromPgpass = (text: string) =>
  text
    .split('\n')
    .filter(l => l.trim() !== '' && !l.startsWith('#'))
    .map(l => l.split(':').slice(4).join(':'))

const safeDecode = (v: string) => {
  try {
    return decodeURIComponent(v)
  } catch {
    return v
  }
}

// Each value plus the URL-encoded and base64 forms it may appear in.
export const withEncodings = (values: Iterable<string>) =>
  [...values].flatMap(v => {
    const forms = [v, encodeURIComponent(v)]
    try {
      if (v.length >= 12) forms.push(btoa(v))
    } catch {
      // not Latin-1, so no base64 form to match
    }
    return forms
  })
