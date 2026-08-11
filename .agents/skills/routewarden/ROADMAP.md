# RouteWarden Future Roadmap: Native MCP Server & Go AST Pipeline Integration (Phase 2)

This document records the technical architecture, security directives, and distribution strategy for Phase 2 of RouteWarden, to be implemented when transitioning from the pure Agent Skill (`SKILL.md`) to a binary-backed **Model Context Protocol (MCP)** server.

---

## 1. Native Go MCP Server Architecture (`cmd/mcp`)

- **SDK**: `github.com/mark3labs/mcp-go`
- **Transport**: `stdio` (JSON-RPC 2.0 over standard I/O)
- **Binary entrypoint**: `cmd/mcp/main.go`

### Planned Tools (v1 MCP Scope)

1. **`routewarden_scan_local`**:
   - Executes local git diff scanning against the working directory.
   - **Default Behavior**: Diff covers uncommitted working tree changes (`git diff HEAD`).
   - **Optional Override**: `base_ref` parameter (e.g. `main`) to compare against a specific branch.
2. **`routewarden_analyze_snippet`**:
   - Accepts raw code strings (`filename`, `code`, optional `added_lines`) for instant evaluation without git diff overhead.

> Note: `routewarden_scan_pr` (GitHub PR API scan) and `routewarden_get_catalog` are reserved for Phase 3.

---

## 2. Deterministic AST Engine Integration (`pkg/pipeline`)

To allow the MCP Server to run AST scans without network calls to the GitHub API:

1. **`ScanSingleFile` Extraction**:
   - Refactor `ScanPullRequestFiles` in `pkg/pipeline/scan.go` to delegate single-file processing to a pure in-memory helper:
     `func ScanSingleFile(filename string, content []byte, diffText string, catalog *rules.Catalog) FileResult`
   - **Zero Breaking Changes**: `ScanPullRequestFiles` retains its exact signature and behavior for `cmd/server` (Webhook) and `cmd/action` (GitHub Action).

2. **Local Diff Scanning (`pkg/pipeline/local.go`)**:
   - Implement `ScanLocalDiff(repoDir string, baseRef string, catalog *rules.Catalog) ([]FileResult, error)`.
   - Executes `git diff HEAD` (or `git diff <baseRef>`) in `repoDir`, reads local file contents, and feeds `ScanSingleFile`.

---

## 3. Mandatory Security Directives

1. **Command Injection Prevention**:
   - Parameters `target_dir` and `base_ref` originate from LLM input.
   - They MUST be passed as **individual arguments in `exec.Command("git", "diff", targetRef)`**.
   - NEVER concatenate arguments inside shell execution strings (`sh -c` or `powershell -c`).

2. **No Secret Leaks via Tool Parameters**:
   - `github_token` must **NEVER** be accepted as a tool parameter (preventing leaks in LLM context windows or log files).
   - All tokens must be read strictly from environment variables (`os.Getenv("GITHUB_TOKEN")`).

---

## 4. Distribution Strategy

### Path 1: Go Direct Install (Immediate / Low Cost)
```bash
go install github.com/elicosilva/RouteWarden/cmd/mcp@latest
```
- Requires tagging a release version in the GitHub repository.

### Path 2: NPM Fast-Follow Package (`npx routewarden-mcp`)
- **Build Pipeline**: GoReleaser workflow on tag release to build binaries for `darwin-arm64`, `darwin-x64`, `linux-x64`, `windows-x64`.
- **NPM Package**: Thin `routewarden-mcp` npm wrapper with a `postinstall` script downloading the matching binary architecture from GitHub Releases.
- **Agent Config**:
  ```json
  {
    "mcpServers": {
      "routewarden": {
        "command": "npx",
        "args": ["-y", "routewarden-mcp"]
      }
    }
  }
  ```

---

## 5. Rationale for Deferring Phase 2

While the Go AST engine (using Tree-Sitter) provides strict deterministic accuracy without LLM hallucination risk, the **Skill-Only approach (`SKILL.md`)** delivers immediate value using the agent's native bash and filesystem capabilities without requiring users to install Go toolchains or pre-compiled binaries. Phase 2 will be activated when higher scanning speed or 100% deterministic parsing guarantees are required.
