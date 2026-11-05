# h3ma REA — agents and IDEs

Install or refresh REA MCP + skill for Cursor, Claude Code, Codex, and other
supported clients from this fork.

Requires Node.js **22.23.4+**, **24.22.1+**, or **26.12.1+** (see `.nvmrc`).

## Install or update (recommended)

After the package is on npm:

```bash
npx -y h3ma-rea-agents@latest setup
```

Review the plan, approve, then restart each client named in the completion message.

Pin a version:

```bash
npx -y h3ma-rea-agents@6.8.0 setup
```

## From GitHub (no npm publish)

Run outside the binary you are analyzing (package runners read project config):

```bash
npx -y github:h3ma209/h3ma-rea#main setup
```

First run may compile the package (`prepare` → `build:cached`); allow a few minutes.

Update later by re-running the same command.

## Global CLI + setup

```bash
curl -fsSL https://raw.githubusercontent.com/h3ma209/h3ma-rea/main/install.sh | bash
```

Or:

```bash
npm install -g h3ma-rea-agents@latest
h3ma-rea setup
```

## Scoped clients

Same as upstream REA — e.g. Claude Code profile:

```bash
CLAUDE_CONFIG_DIR=~/.claude-rea npx -y h3ma-rea-agents@latest setup --client claude_code
```

Cursor: select **cursor** in the setup multi-select (or `--client cursor`).

## Check registration

```bash
npx -y h3ma-rea-agents@latest doctor --json
```

Official upstream docs still apply for Hopper, Ghidra, and provider paths:
[installation.md](installation.md).
