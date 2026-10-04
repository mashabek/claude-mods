import type { ApiContentBlock, EngineInterface, Register } from 'claude-code'

import {
  MARK,
  compileKnown,
  makeLabeler,
  redact,
  valuesFromAssignments,
  valuesFromNetrc,
  valuesFromPgpass,
  withEncodings,
} from './detect'

const PROMPT_NOTE = `Tool output in this session passes through a secret mask before you read it. A marker like
${MARK}3› (sometimes after a visible prefix, as in ghp_${MARK}3›) stands where a secret was; the same
number is the same secret. Never write a marker into a file, command or config. Refer to the
secret by its environment variable or file, or ask the user.`

const HOME_FILES: [string, (text: string) => string[]][] = [
  ['.aws/credentials', valuesFromAssignments],
  ['.npmrc', valuesFromAssignments],
  ['.netrc', valuesFromNetrc],
  ['.pgpass', valuesFromPgpass],
]

const s = {
  isOn: true,
  known: undefined as RegExp | undefined,
  sources: [] as string[],
  byKind: new Map<string, number>(),
  label: makeLabeler(),
}

const masked = () => [...s.byKind.values()].reduce((a, b) => a + b, 0)

function showStatus($: EngineInterface) {
  $.ui.status(!s.isOn ? '🔓 secret-mask off' : masked() > 0 ? `🔒 ${masked()} masked` : undefined)
}

async function findEnvFiles($: EngineInterface, root: string) {
  const r = await $.process.run(
    ['find', root, '-maxdepth', '4', '(', '-name', 'node_modules', '-o', '-name', '.git', ')', '-prune', '-o', '-type', 'f', '-name', '.env*', '-print'],
    { timeoutMs: 10_000 },
  )
  return r.stdout.split('\n').filter(p => /\/\.env(\.[^/]+)?$/.test(p) && !/\.(example|sample|template|dist|defaults?)$/.test(p))
}

async function scan($: EngineInterface) {
  const [cwd, home] = await Promise.all([$.session.cwd(), $.env.get('HOME')])
  const read = (path: string) => $.fs.read(path).catch(() => '')

  const envFiles = (await findEnvFiles($, cwd).catch(() => [])).map(async path => ({
    source: path.replace(`${cwd}/`, ''),
    values: valuesFromAssignments(await read(path)),
  }))
  const homeFiles = (home ? HOME_FILES : []).map(async ([path, parse]) => ({
    source: `~/${path}`,
    values: parse(await read(`${home}/${path}`)),
  }))
  const environment = $.process
    .run(['env'])
    .then(r => ({ source: 'environment', values: valuesFromAssignments(r.stdout, { namedOnly: true }) }))
    .catch(() => ({ source: 'environment', values: [] as string[] }))

  const found = (await Promise.all([...envFiles, ...homeFiles, environment])).filter(f => f.values.length > 0)
  s.known = compileKnown(withEncodings(found.flatMap(f => f.values)))
  s.sources = found.map(f => f.source)
}

const maskBlock = (block: ApiContentBlock, kinds: string[]): ApiContentBlock => {
  const mask = (text: string) => {
    const r = redact(text, s.known, s.label)
    kinds.push(...r.kinds)
    return r.text
  }
  if (block.type === 'text' && typeof block.text === 'string') return { ...block, text: mask(block.text) }
  if (block.type === 'tool_result' && typeof block.content === 'string') return { ...block, content: mask(block.content) }
  if (block.type === 'tool_result' && Array.isArray(block.content)) {
    return { ...block, content: block.content.map(inner => maskBlock(inner as ApiContentBlock, kinds)) }
  }
  return block
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    const [enabled] = await Promise.all([
      $.store.get('enabled'),
      $.command.register({
        name: 'secret-mask',
        description: 'Secret masking: status, on, off, or rescan for known secrets',
        argumentHint: '[on|off|rescan]',
      }),
      scan($),
    ])
    s.isOn = enabled !== false
    showStatus($)
    return next(e)
  })

  on('prompt.compose', async ($, e, next) => {
    const composed = await next(e)
    if (!s.isOn) return composed
    return { sections: [...composed.sections, { id: 'secret-mask:note', text: PROMPT_NOTE, scope: 'session' }] }
  })

  // Mask rows bound for the model. The screen draws the tool's own record and keeps the real value.
  on('session.append', async ($, e, next) => {
    if (!s.isOn || (e.message.type !== 'user' && e.message.type !== 'attachment')) return next(e)

    const kinds: string[] = []
    const content = e.message.content.map(block => maskBlock(block, kinds))
    if (kinds.length === 0) return next(e)

    for (const k of kinds) s.byKind.set(k, (s.byKind.get(k) ?? 0) + 1)
    showStatus($)
    return next({ ...e, message: { ...e.message, content } })
  })

  on('command.run', { command: 'secret-mask' }, async ($, e) => {
    const arg = (e.args ?? '').trim()
    if (arg === 'on' || arg === 'off') {
      s.isOn = arg === 'on'
      await $.store.set('enabled', s.isOn)
      showStatus($)
      return { text: `secret-mask is ${arg}.` }
    }
    if (arg === 'rescan') await scan($)

    const kinds = [...s.byKind].map(([k, n]) => `${k} ×${n}`).join(', ')
    return {
      text: [
        `secret-mask is ${s.isOn ? 'on' : 'off'}.`,
        `Read: ${s.sources.join(', ') || 'no secret files found'}.`,
        `Masked this session: ${masked()}${kinds ? ` (${kinds})` : ''}.`,
      ].join('\n'),
    }
  })
}
