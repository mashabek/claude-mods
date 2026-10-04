# claude-mods

Plugins for Claude Code built on its function-hooks API.

![secret-mask: your terminal shows the secret, Claude reads ‹secret:1›](plugins/secret-mask/demo.svg)

| Mod | |
|---|---|
| [secret-mask](plugins/secret-mask) | Masks API keys, tokens and passwords in tool output before Claude reads them. |

```bash
claude plugin marketplace add mashabek/claude-mods
claude plugin install secret-mask@claude-mods
```
