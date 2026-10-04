import type { On } from 'claude-code'
import { expect, test } from 'claude-code/testing'
import type { Engine } from 'claude-code/testing'

const GH = 'ghp_' + 'A1b2'.repeat(9)

// Records the row the plugin passed down. The test engine stores nothing, so the append itself rejects.
const appendSeen = async ($: Engine, on: On, text: string) => {
  const seen: string[] = []
  on('session.append', async (_$, e, next) => {
    seen.push(JSON.stringify(e.message.content))
    return next(e)
  })
  await $.session
    .append({
      message: { type: 'user', role: 'user', content: [{ type: 'text', text }] },
      door: 'prompt',
      origin: { kind: 'composer' },
      uuid: 'row-1',
    })
    .catch(() => {})
  return seen.join('')
}

test('a row is passed on with its secrets masked', async ($, on) => {
  const seen = await appendSeen($, on, `export GH=${GH}`)
  expect(seen).toContain('ghp_‹secret:1›')
  expect(seen).not.toContain(GH)
})

test('a row with no secret is passed on unchanged', async ($, on) => {
  expect(await appendSeen($, on, 'npm test passed: 41 tests')).toContain('npm test passed: 41 tests')
})
