# claude-mods

Plugins for Claude Code built on its function-hooks API.

| Mod | |
|---|---|
| [secret-mask](plugins/secret-mask) | Masks API keys, tokens and passwords in tool output before Claude reads them.<br><img src="plugins/secret-mask/demo.svg" width="480" alt="Your terminal shows the secret, Claude reads ‹secret:1›"> |

```bash
claude plugin marketplace add mashabek/claude-mods
claude plugin install <mod>@claude-mods
```
