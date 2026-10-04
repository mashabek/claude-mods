import { describe, expect, test } from 'claude-code/testing'

import { compileKnown, isSecretName, makeLabeler, redact, valuesFromAssignments, withEncodings } from '../hooks/detect'

// Fake tokens are built from pieces so secret scanners don't flag this file.
const GH = 'ghp_' + 'A1b2'.repeat(9)
const AWS = 'AKIA' + 'Z7Q2'.repeat(4)
const ANT = 'sk-ant-' + 'api03-' + 'x9Y8'.repeat(8)
const JWT = 'eyJ' + 'hbGciOiJIUzI1' + '.eyJ' + 'zdWIiOiIxMjM0' + '.' + 'SflKxwRJSMeKKF2QT4'
const SLASHED = '/k9ZpQ2' + 'xR7mT4vW8yB3n'

const mask = (text: string, known: string[] = []) => redact(text, compileKnown(known), makeLabeler()).text

describe('masks', () => {
  test('token formats, keeping the prefix', () => {
    expect(mask(`${GH} ${AWS} ${ANT}`)).toMatch(/^ghp_‹secret:\d› AKIA‹secret:\d› sk-ant-‹secret:\d›$/)
  })

  test('only the password of a connection string', () => {
    expect(mask('connection to postgres://deploy:Hx7pq2Lm@localhost:5432/app failed')).toContain(
      'postgres://deploy:‹secret:1›@localhost:5432/app',
    )
  })

  test('JWTs, bearer headers and private keys', () => {
    expect(mask(`cookie=${JWT}`)).toBe('cookie=‹secret:1›')
    expect(mask('Authorization: Bearer abcdef0123456789xyz')).toBe('Authorization: Bearer ‹secret:1›')
    const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----'
    expect(mask(pem)).toBe('-----BEGIN RSA PRIVATE KEY-----‹secret:1›-----END RSA PRIVATE KEY-----')
  })

  test('values assigned to secret names', () => {
    expect(mask('const apiKey = "Zx81kfP0qLm2"')).toBe('const apiKey = "‹secret:1›"')
    expect(mask('SESSION_SECRET=9f8Kq2LmXv7Rt5Wz')).toBe('SESSION_SECRET=‹secret:1›')
    expect(mask(`export DB_PWD=${SLASHED}`)).toBe('export DB_PWD=‹secret:1›')
  })

  test('known values anywhere, the same value under the same label', () => {
    expect(mask('hunter2hunter, again hunter2hunter', ['hunter2hunter'])).toBe('‹secret:1›, again ‹secret:1›')
  })
})

describe('leaves alone', () => {
  const untouched = [
    'commit 3f9c2a7e8b1d4f6a0c5e9b2d7a4f1c8e3b6d9a0f',
    'id 550e8400-e29b-41d4-a716-446655440000',
    'const key = process.env.API_KEY',
    'function getToken(token: string): Promise<Token>',
    'password: z.string().min(8),',
    'headers["auth_token"] = token',
    'const TOKEN_HEADER = "X_AUTH_TOKEN"',
    'TOKEN_TTL=3600',
    'DATABASE_URL=postgres://${DB_USER}:${DB_PASS}@db/app',
    'api_key: <your key here>',
    'git clone https://github.com/anthropics/claude-code.git',
  ]
  for (const line of untouched) test(line, () => expect(mask(line)).toBe(line))

  test('long dotted or base64 text stays fast', () => {
    const start = Date.now()
    mask('a.'.repeat(50_000))
    mask('Zm9vYmFy'.repeat(12_000))
    expect(Date.now() - start).toBeLessThan(300)
  })
})

describe('secret names', () => {
  test('end in a secret word', () => {
    for (const name of ['DB_PWD', 'apiKey', 'aws_secret_access_key', '_authToken', 'NEXTAUTH_SECRET', 'password']) {
      expect(isSecretName(name)).toBe(true)
    }
    for (const name of ['TOKEN_ENDPOINT', 'SECRET_MANAGER_REGION', 'AUTH_TOKEN_TYPE', 'API_KEY_HEADER', 'TOKEN_TTL', 'monkey']) {
      expect(isSecretName(name)).toBe(false)
    }
  })
})

describe('reading secret files', () => {
  test('a .env file yields secrets, not ports, modes or hosts', () => {
    const env = [
      '# local',
      'NODE_ENV=production',
      'PORT=3000',
      'DATABASE_URL="postgres://deploy:Hx7pq2Lm@localhost/app"',
      'NEXTAUTH_SECRET=correcthorsebattery',
      'SENTRY_RELEASE_ID=4f9a2c7e81b3d5f6a0',
      `AWS_SECRET_ACCESS_KEY=${SLASHED}`,
      'TOKEN_ENDPOINT=https://auth.example.com/oauth/token',
      'PUBLIC_HOST=shelfscope.io',
    ].join('\n')
    expect(valuesFromAssignments(env).sort()).toEqual([SLASHED, '4f9a2c7e81b3d5f6a0', 'Hx7pq2Lm', 'correcthorsebattery'].sort())
  })

  test('the environment counts only secret names, never paths', () => {
    const env = 'PATH=/usr/local/bin:/opt/homebrew/bin\nPWD=/Users/me/project\nOLDPWD=/Users/me\nGH_TOKEN=abc123def456\nAUTH_TOKEN_TYPE=bearer_token'
    expect(valuesFromAssignments(env, { namedOnly: true })).toEqual(['abc123def456'])
  })

  test('encodings are matched too', () => {
    expect(withEncodings(['p@ss word12'])).toContain('p%40ss%20word12')
  })
})
