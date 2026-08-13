# RFC 0032 — Context-Aware CLI

**Status:** ACCEPTED  
**Date:** 2026-07-16  
**Authors:** dotlinux26, D-O-T-Solutions

---

## Summary

This RFC defines the **Context-Aware CLI** for SMO — an interactive shell that maintains mesh, selection, execution, and session context, enabling a distributed shell experience.

---

## Motivation

Traditional orchestration tools require repeating targets:

```bash
# Tedious
smo exec --name node-1 --scope mesh hostname
smo exec --name node-1 --scope mesh uptime
smo exec --name node-1 --scope mesh df -h
```

SMO introduces **persistent context**:

```bash
smo context use production
smo select --role Storage

production(storage:12)> ls /data
production(storage:12)> put agent.bin /opt/bin/
production(storage:12)> exec "systemctl restart storage"
```

---

## Context Model

### Three-Layer Context Stack

```
┌─────────────────────────────────────────────────────────────┐
│                    GLOBAL CONTEXT                           │
│  Current Mesh: production                                   │
│  Current User: admin@company.com                            │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                   SELECTION CONTEXT                          │
│  Mesh: production                                           │
│  Role: Storage                                              │
│  Nodes: 12 selected                                         │
│  Filter: trust > 0.8                                        │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                  EXECUTION CONTEXT                           │
│  Control: safe    Scope: mesh                               │
│  Timeout: 30s    Retry: 3                                   │
│  Policy: enterprise-standard                                 │
│  Dry-run: false                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Context Layers

### 1. Mesh Context

```bash
# List available meshes
smo mesh list

# Switch mesh
smo mesh use production

# Current mesh
smo mesh current
# → production

# Create a new mesh (creates directory, sets as current)
smo mesh create staging

# Publish mesh (via smo-admin under the hood)
smo mesh publish

# Generate invite (calls smo-admin generate-invite)
smo mesh invite --role Worker --expire 1h

# Start enroll server
smo mesh serve --port 5454

# Join a mesh using a token
smo mesh join --token SMO-JOIN-<base64url>
```

### 2. Selection Context

```bash
# Select by role
smo select --role Storage

# Select by tag
smo select --tag Backup

# Select by expression
smo select --where 'trust>0.9 && os=="linux"'

# Select nearest
smo select --nearest

# Combine
smo select --role Worker --tag GPU --where 'mem>32GB'

# View current selection
smo select show

# Save/restore selections
smo select save nightly-backup
smo select load nightly-backup

# Clear
smo select clear
```

### 3. Execution Context

```bash
# Control level
smo control safe      # Read-only, no side effects
smo control normal    # Standard operations
smo control force     # Override some protections
smo control emergency # Authority only, break glass

# Scope
smo scope single      # Single node (pick_one)
smo scope mesh        # All selected nodes
smo scope quorum      # Quorum required
smo scope witness     # Witness nodes only

# Policy
smo policy use enterprise-standard
smo policy show

# Timeout/Retry
smo timeout 60000      # 60 seconds
smo retry 3
```

### 4. Session Context (Persistent Connection)

```bash
smo connect storage-01
# → Connected to storage-01 (production)
# Prompt changes:
production(storage-01)>

# Now all commands target this node
production(storage-01)> ls /var/log
production(storage-01)> put agent.bin /opt/bin/
production(storage-01)> exec "systemctl restart storage"

# Disconnect
smo disconnect
# Back to mesh prompt
production(storage:12)>
```

### 5. Session Context Stack (push/pop)

```bash
# Save current context, switch to new
smo push --role Backup
# → Backup context active

smo pop
# Restores previous context
```

---

## Context-Aware Commands

### Native Commands (Shell built-ins)

| Command | Description |
|---------|-------------|
| `help` | Show help |
| `exit` / `quit` | Exit shell |
| `mesh` | Mesh management |
| `select` | Node selection |
| `policy` | Policy management |
| `control` | Control level |
| `scope` | Execution scope |
| `context` | Context management |
| `connect` | Connect to node |
| `disconnect` | End session |
| `history` | Command history |
| `alias` | Define alias |

### Native Contracts (dispatch via Runtime)

| Command | Contract | Description |
|---------|----------|-------------|
| `ls` | `fs.list` | List directory |
| `mkdir` | `fs.mkdir` | Create directory |
| `rm` | `fs.remove` | Remove file/dir |
| `cp` | `fs.copy` | Copy file |
| `mv` | `fs.move` | Move/rename |
| `cat` | `fs.read` | Read file |
| `put` | `file.put` | Upload file |
| `get` | `file.get` | Download file |
| `sync` | `file.sync` | Sync directories |
| `exec` | `proc.exec` | Execute command |
| `ps` | `proc.ps` | List processes |
| `kill` | `proc.kill` | Kill process |
| `systemctl` | `systemd.control` | Service management |

---

## Interactive Shell (`smo shell`)

```bash
$ smo shell
SMO Runtime v1.0.0

Mesh: production
Selection: Storage (12 nodes)
Policy: enterprise-standard
Control: safe
Scope: mesh

production(storage:12)>
```

### Prompt Format

```
[mesh](selection:count)[control/scope]>
```

Examples:
```
production(storage:12)[safe/mesh]>
production(backup:3)[force/single]>
lab(none)[safe/single]>
```

### Built-in Commands

| Command | Description |
|---------|-------------|
| `help` | Show help |
| `exit` / `quit` | Exit shell |
| `mesh` | Mesh management |
| `select` | Node selection |
| `policy` | Policy management |
| `control` | Control level |
| `scope` | Execution scope |
| `discover` | Discover peers |
| `connect` | Connect to node |
| `disconnect` | End session |
| `history` | Command history |
| `alias` | Define alias |
| `push` / `pop` | Context stack |

---

## Selection Persistence

### Save/Load Selections

```bash
smo select --role Storage --tag Backup --where 'trust>0.9'
# → Selected 18 nodes

smo select save nightly-backup
# → Selection saved as "nightly-backup"

# Later...
smo select load nightly-backup
# → Restored 18 nodes
```

### Persistent Storage

```
~/.smo/
├── contexts/
│   ├── selections/
│   │   ├── nightly-backup.json
│   │   ├── incident-response.json
│   │   └── ...
│   └── execution-contexts/
│       ├── default.json
│       └── incident-response.json
```

---

## Context Stack (Push/Pop)

```bash
# Save current context, switch to incident response
smo push --role IncidentCommander --policy incident-response --control emergency
# → Incident context active

# Work...

smo pop
# Restored previous context
```

---

## Context Stack Structure

```json
{
  "stack": [
    {
      "mesh": "production",
      "selection": {"role": "Storage", "nodes": 12},
      "execution": {"control": "safe", "scope": "mesh"},
      "session": null
    },
    {
      "mesh": "production",
      "selection": {"role": "IncidentCommander", "nodes": 3},
      "execution": {"control": "emergency", "scope": "single"},
      "session": "storage-01"
    }
  ],
  "current": 1
}
```

---

## Completion & UX

### Tab Completion

```
production(storage:12)> ls <TAB>
bin/  boot/  dev/  etc/  home/  lib/  media/  mnt/  opt/  proc/  root/  run/  sbin/  srv/  sys/  tmp/  usr/  var/

production(storage:12)> connect sto<TAB>
storage-01  storage-02  storage-03

production(storage:12)> select --role <TAB>
Storage  Backup  Compute  Gateway
```

### Aliases

```bash
alias ll="ls -la"
alias cls="clear"
alias k="exec kubectl"
alias tf="exec terraform"

# Persisted in ~/.smo/aliases
```

### Scripting

```bash
# deploy.smo
use production
select --role Web
exec "systemctl status nginx"
put nginx.conf /etc/nginx/
exec "systemctl reload nginx"

# Run
smo run deploy.smo

# Or
source deploy.smo
```

---

## Configuration

```toml
# ~/.smo/runtime.toml

[cli]
prompt_template = "{mesh}({selection})[{control}/{scope}]> "
history_file = "~/.smo/history"
history_size = 10000
auto_complete = true
colors = true

[context]
auto_save_selection = true
max_saved_selections = 50
context_stack_size = 10

[mesh]
default = "production"
auto_connect = true
```

---

## Security

- **Context isolation** — Each mesh has isolated secrets, audit logs
- **Audit trail** — Every context switch, selection change, command logged
- **Privilege escalation** — `--control emergency` requires Authority cert
- **Session timeout** — Auto-disconnect after inactivity (configurable)

---

## Implementation Priority

| Phase | Feature |
|-------|---------|
| 1 | Mesh context + Selection context + Basic prompt |
| 2 | Execution context (control, scope, policy) |
| 3 | Session context (`connect`/`disconnect`) |
| 4 | Context stack (`push`/`pop`) |
| 5 | Interactive shell (`smo shell`) |
| 6 | Completion, aliases, history |
| 7 | Scripting (`smo run script.smo`) |
| 8 | Workflow DSL |

---

## C++ Implementation

### Source Files

```
cmd/smo-cli/
├── main.cpp              # CLIApplication with REPL loop + all command handlers
├── cli_context.hpp       # CLIContextManager, SelectionContext, ExecutionContext, SessionContext
├── cli_context.cpp       # Context state management, prompt generation, history
├── intent_parser.hpp     # IntentParser, Intent, ParsedCommand, IntentType enum
├── intent_parser.cpp     # Tokenization, flag parsing, help generation
└── CMakeLists.txt        # Links smo_sdk + smo_tooling + readline stub
```

### CLIContextManager (`cmd/smo-cli/cli_context.hpp`)

```cpp
class CLIContextManager {
public:
    // Mesh context
    Result<void> set_mesh(const std::string& mesh_name);
    Result<std::string> get_current_mesh() const;

    // Selection context (by role/tag/expression/name)
    Result<void> set_selection(const SelectionContext& ctx);
    Result<void> clear_selection();
    Result<SelectionContext> get_selection() const;
    Result<void> save_selection(const std::string& name);
    Result<void> load_selection(const std::string& name);

    // Execution context (control level, scope, timeout, retry)
    void set_control_level(ControlLevel level);
    ControlLevel get_control_level() const;
    void set_scope(ExecutionScope scope);
    ExecutionScope get_scope() const;
    void set_timeout(int ms);
    int get_timeout() const;
    void set_retry(int count);
    int get_retry() const;
    void set_dry_run(bool dry);
    bool get_dry_run() const;

    // Session management
    Result<void> connect(const std::string& node_address);
    Result<void> disconnect();
    bool is_connected() const;

    // Context stack (push/pop)
    void push_context();
    Result<void> pop_context();

    // Prompt generation
    std::string get_prompt() const;

    // History
    void add_history(const std::string& command);
    const std::vector<std::string>& get_history() const;
};
```

### Intent Parser (`cmd/smo-cli/intent_parser.hpp`)

Supports 22+ IntentTypes: `Execute`, `Transfer`, `Filesystem`, `Process`, `Deploy`, `Undeploy`, `Status`, `History`, `Select`, `Policy`, `Control`, `Mesh`, `Connect`, `Disconnect`, `Context`, `Help`, `Exit`, `Discover`, `Export`, `Session`, `Trace`.

Parsing features:
- Long flags (`--flag=value`, `--flag value`)
- Short flags (`-hvfd`)
- Positional args with validation against required args list
- Quoted tokenization (`"` and `'`)
- Escape sequences (`\`)
- Command aliases

### CLIApplication (`cmd/smo-cli/main.cpp`)

**Interactive REPL** — launched when running `smo-cli` without arguments:

```
  ╔══════════════════════════════════════╗
  ║    SMO Interactive Shell v0.1        ║
  ║    Type 'help' for commands          ║
  ║    Type 'exit'  or Ctrl-D to quit    ║
  ╚══════════════════════════════════════╝

[default][none][safe][single]> help
```

**Implemented command handlers:**

| Handler | Intent Types | Actions |
|---------|-------------|---------|
| `handle_help` | Help | Print help/usage for commands |
| `handle_select` | Select | Filter by name/role/tag/where/mesh/OS/arch/trust, save selections |
| `handle_exec` | Execute | Execute command on connected session (PROCESS opcode, network exec) |
| `handle_transfer` | Transfer | File transfer put/get/sync over network (FILE_OP write/read/mkdir) |
| `handle_filesystem` | Filesystem | ls/cat/mkdir/rm/cp/mv/echo — stub |
| `handle_process` | Process | ps/kill/top — stub |
| `handle_deploy` | Deploy | Deploy contract to connected node (CONTRACT_MGMT deploy) |
| `handle_undeploy` | Undeploy | Undeploy contract from connected node (CONTRACT_MGMT undeploy) |
| `handle_status` | Status | Show current context (mesh, selection, control, scope, session) or `status <id>` contract lifecycle |
| `handle_policy` | Policy | List/set policy presets: `default`, `enterprise`, `emergency`; `policy show <name>` prints real preset details |
| `handle_control` | Control | Set level/scope/timeout/retry interactively |
| `handle_context` | Context | Save/load/clear context |
| `handle_mesh` | Mesh | List/use/create/leave mesh |
| `handle_connect` | Connect | Connect/disconnect to node |
| `handle_history` | History | Show command history with optional limit |
| `handle_trace` | Trace | Show deployment lifecycle trace for a contract_id |

**Prompt format:**

```
[{mesh}][{selection}][{control}][{scope}]>
```

**Auto-complete:** Tab-completion for all 30+ commands using readline's `rl_completion_matches`.

### Readline Stub (`third_party/readline/`)

Since the system readline library headers are not available (no root access), a minimal stub provides:

```
readline(), add_history(), read_history(), write_history()
rl_completion_matches(), rl_redisplay(), rl_on_new_line()
rl_replace_line(), rl_free_line_state(), rl_cleanup_after_signal()
rl_line_buffer, rl_attempted_completion_function, rl_attempted_completion_over
```

### History Persistence

- History file: `~/.smo_history`
- Loaded on startup via `read_history()`
- Saved on exit via `write_history()`
- In-memory dedup (no consecutive duplicates, max 1000 entries)

### CMakeLists.txt

```cmake
add_executable(smo-cli main.cpp cli_context.cpp intent_parser.cpp
    ${CMAKE_SOURCE_DIR}/third_party/readline/readline.cpp)
target_include_directories(smo-cli PRIVATE ${CMAKE_SOURCE_DIR}/third_party/readline)
target_link_libraries(smo-cli PRIVATE smo_sdk smo_tooling)
```

---

## Implementation Status

| Phase | Feature | Status |
|-------|---------|--------|
| 1 | Mesh context + Selection context + Basic prompt | ✅ Done |
| 2 | Execution context (control, scope, policy) | ✅ Done |
| 3 | Session context (`connect`/`disconnect`) | ✅ Done |
| 4 | Context stack (`push`/`pop`) | ✅ Done |
| 5 | Interactive shell (`smo shell`) | ✅ Done (via `smo-cli`) |
| 6 | Completion, aliases, history | ✅ Done |
| 7 | Scripting (`smo run script.smo`) | ⏳ Planned |
| 8 | Workflow DSL | ⏳ Planned |

---

## Known Issues & Fix Log (v0.0.2 → v0.0.3)

> Policy: every bug found and fixed during implementation is recorded here so the spec
> stays the source of truth for the intended behavior.

### BUG-004 — `smo` shell-outs could not locate `smo-admin` (FIXED)

**Status:** FIXED (2026-08-12)

**Symptoms:** `mesh publish`/`serve`/`invite` invoked `smo-admin` by bare name, which failed
when `smo-admin` was not on `PATH` (typical after a staged/relocated install).

**Fix applied:** added `find_smo_admin()` — resolves `/proc/self/exe`, looks for a sibling
`smo-admin` binary next to the running `smo`, and falls back to `PATH` lookup.

### PARSER — bare subcommands (`mesh invite`, `mesh use <name>`) silently no-op'd (FIXED)

**Status:** FIXED (2026-08-12)

**Symptoms:** `smo mesh invite ...` / `smo mesh use <name>` returned nothing. The parser placed
the subcommand word into positional `intent.args` while `handle_mesh` dispatched on
`intent.flags`, so the bare form never matched.

**Fix applied:** `CommandDef` gained a `two_level` marker; the first positional subcommand word
is promoted to a flag (with an optional following value) after positional args are collected.

### JOIN — `smo mesh join --token SMO-JOIN-...` failed even with a valid token (FIXED)

**Status:** FIXED (2026-08-12)

**Symptoms:**
1. `Invalid Join Token: missing SMO-JOIN- prefix` — the handler read the token from the
   `--join` flag value instead of `--token`.
2. `unsupported crypto suite` — the join path used `CryptoRegistry` directly but suites were
   only lazily registered by `get_crypto()`; a plain `mesh join` never triggered registration.
3. `invalid transition for current state` — the CSR step re-fired `CSR_BUILT` after the identity
   step had already advanced the join FSM `TOKEN_RECEIVED → CSR_CREATED`.

**Fix applied:**
1. `handle_mesh` reads token from `--token` (falls back to `--join <value>` legacy form).
2. `mesh join` calls `get_crypto(kSuiteClassical)` before `run_join_command` so suites are
   registered.
3. `auto_enroll.cpp`: the CSR build step only fires `CSR_BUILT` when state is still
   `TOKEN_RECEIVED`; otherwise it proceeds to send without re-firing the event.

**Note:** join currently requires the authority's `smo-node --daemon` (with signed server cert)
to be listening on the token's bootstrap endpoint (TCP/CBOR + PQ handshake). The HTTP
`enroll_server` path is deprecated.

---

### CRYPTO — `HashProvider::default_provider()` threw "no HashProvider registered" (FIXED)

**Status:** FIXED (2026-08-12)

**Symptoms:** The nonce cache in `join_protocol.cpp` uses `HashProvider::default_provider()` to
compute Blake3(mesh_id || nonce). The daemon (`smo-node --daemon`) never registered a default
hash provider, causing `std::runtime_error` on first JoinRequest.

**Fix applied:** Added `Blake3Provider::register_as_default()` to `ensure_crypto()` in
`cmd/smo-node/main.cpp` (also in `cmd/smo/main.cpp` for consistency).

---

### AUTH — MeshAuthority not initialized in daemon, `sign_csr` returned "crypto not configured" (FIXED)

**Status:** FIXED (2026-08-12)

**Symptoms:** After HashProvider fix, JoinRequest signature verification passed but
`authority.sign_csr()` failed with "crypto not configured" — the daemon called `authority.open()`
but never `authority.init(*crypto, rng)` to attach the crypto provider.

**Fix applied:** In daemon startup, call `authority.init(*crypto, auth_rng)` before `authority.open()`
using the suite3 (`kSuitePurePQC`) crypto provider.

---

### JOIN — JoinRequest signature verification failed (FIXED)

**Status:** FIXED (2026-08-12)

**Symptoms:** Server verified `request_signature` against the token issuer's truncated root
fingerprint (`root:<fingerprint>`), but the client signed with its own identity secret key.
Signature never matched.

**Fix applied:** `process_join_request()` now deserializes the CSR first, then verifies
`request_signature` against `csr.new_public_key` (the joining node's key), matching the
client's signing logic in `auto_enroll.cpp`.

---

### FSM — Join resume from JOIN_SENT state re-fired MSG_SENT (invalid transition) and skipped CSR rebuild (FIXED)

**Status:** FIXED (2026-08-12)

**Symptoms:**
1. Resume from state 3 (`JOIN_SENT`) re-fired `MSG_SENT` event, but transition table only allows
   `CSR_CREATED → MSG_SENT → JOIN_SENT`. Re-firing from `JOIN_SENT` is invalid.
2. CSR build block skipped for `JOIN_SENT` state, leaving `csr_pem` empty.

**Fix applied:**
1. `MSG_SENT` only fired when `current_state() == CSR_CREATED`; resume at `JOIN_SENT` skips it.
2. CSR build condition changed to `current_state() <= JOIN_SENT` so CSR is rebuilt on resume
   (but `CSR_BUILT` event only fires from `TOKEN_RECEIVED`).

---

### SYNC — BootstrapSync failed "No active mesh" despite mesh_dir provided (FIXED)

**Status:** FIXED (2026-08-12)

**Symptoms:** `process_bootstrap_sync()` calls `mesh_mgr.get_current_mesh()` which returns empty.
The daemon opened the mesh with `open_mesh()` but didn't register it in the catalog or set it as
current.

**Fix applied:**
1. `mesh_manager.initialize()` to load catalog from `base_data_dir`.
2. Insert existing mesh into `catalog.db` (SQL `INSERT OR IGNORE INTO meshes`).
3. Call `mesh_manager.switch_mesh(mesh_id)` to set as active mesh.

---

### CERT — authority cert signature covered CSR body, not cert body; cert file omitted signature (FIXED)

**Status:** FIXED (2026-08-12)

**Symptoms:** During join, client CERT_VERIFY printed `Warning: bootstrap server cert signature
invalid` while its own freshly-issued cert verified fine. The authority's own cert (sent by the
daemon as the PQ handshake server cert) failed `Certificate::verify()`.

**Root cause:**
1. `cmd_mesh_init_authority` built the authority cert and set `authority_cert.signature =
   root_res.output`, but that output was the Root's signature over the **CSR payload** — while
   `Certificate::verify()` (certificate.cpp) checks the signature over the certificate **body**
   (`serialize()`). Mismatched signed bytes → always invalid.
2. The cert was persisted with `serialize()` (body only, signature dropped), so even a correctly
   signed cert would be written without its signature.

**Fix applied:**
1. `cmd/smo-admin/main.cpp`: the Root session now signs the serialized certificate body
   (`cert_req.payload = authority_cert.serialize()`) via a second `execute(SignBootstrapCSR)`,
   and that signature is stored in `authority_cert.signature`. The CSR signature is retained as a
   key-ownership proof.
2. Persist the cert with `serialize_full()` (body + signature).

---

### JOIN — client used unseeded `rand()` nonce: every join process reused the same nonce (FIXED)

**Status:** FIXED (2026-08-12)

**Symptoms:** Second and later `smo mesh join` attempts (even with a fresh identity/token) failed
with `JoinRequest nonce replay detected`, and first-time joins that retried a second endpoint also
hit replay. Nonce dedup cache keyed `Blake3(mesh_id || nonce)` correctly rejected the duplicates.

**Root cause:** `auto_enroll.cpp` filled the 8-byte JoinRequest nonce from `rand()` without ever
calling `srand()`. All `smo` processes therefore produced the identical nonce sequence, and the
server's replay cache (TTL = token lifetime) blocked every subsequent join.

**Fix applied:** `core/enroll/auto_enroll.cpp` — nonce is now filled from the crypto RNG
(`rng.fill()`), and nonce+signature are regenerated **per endpoint attempt** inside the retry loop
so a failed first endpoint does not poison the retry against the second.

---

### CLI — `SMO_DATA_DIR` was ignored by the join path (FIXED)

**Status:** FIXED (2026-08-12)

**Symptoms:** `smo mesh join` always wrote its node data (`identity.json`, `cert.smoc`, …) to
`~/.smo/node` even when `SMO_DATA_DIR` was set, making it impossible to run concurrent clients.

**Root cause:** `CLIContextManager::initialize(data_dir)` discarded the argument
(`(void)data_dir`), so `context_.get_data_dir()` stayed empty and `mesh join` fell back to
`<HOME>/.smo/node`.

**Fix applied:** `cmd/smo-cli/cli_context.cpp` — `initialize()` now calls `set_data_dir(data_dir)`
when non-empty; `mesh join` uses it for the node data directory.

---

### DAEMON — member daemon's seed bootstrap used raw TCP, blocking the authority (FIXED)

**Status:** FIXED (2026-08-12)

**Symptoms:** In the 3-node E2E, node-b's `smo-node --daemon --seed` connected to the authority
over raw TCP (version handshake only, PQ disabled — "Warning: no certificate at .../node.cert.smoc").
The authority serves every accepted TCP connection with a PQ handshake (it presents its signed
`node.cert.smoc`), so it blocked forever in `SecureSession::read_field()` waiting for a PQ
ClientHello that never came. Because the daemon's main loop is single-threaded
(accept → dispatch → blocking `dispatch_session`), the whole authority stalled: node-c's
`mesh join` was never accepted and failed with "version handshake: read failed".

**Spec intent (authoritative):**
- The mesh authority MUST perform a PQ handshake on every TCP connection (it presents a signed
  server certificate). The old bootstrap flow in RFC 0034 (raw HelloMsg/WelcomeMsg over a bare
  TCP connection) is therefore not usable against a certed authority.
- A member daemon connecting to a seed MUST use the same client handshake as `smo mesh join`:
  TCP connect → version handshake → PQ `SecureSession{role=Client}.handshake()` → then send
  `HelloMsg` / read `WelcomeMsg` inside the secure session.

**Fix applied:** `cmd/smo-node/main.cpp` — the seed bootstrap block no longer uses
`Bootstrap::find_seed` (raw). It now opens the TCP session, takes the raw fd via
`TcpSession::release_fd()`, performs the PQ client handshake, then exchanges
HelloMsg/WelcomeMsg over the secure session before calling `discovery_engine.handle_welcome`.

**Verification:** 3-node E2E (`/tmp/opencode/e2e-3node.sh`) now passes: node-a (authority :7777),
node-b (:7778) and node-c (:7779) all reach `IDENTITY_READY`; node-a's log shows
`Raw handler: HelloMsg` from each member; both members log `Seed responded` and
`Bootstrap complete. Peers: 1`.

---

### DISCOVERY — WelcomeMsg echoed the requester's ephemeral record instead of the seed's (FIXED)

**Status:** FIXED (2026-08-12)

**Symptoms:** Members reported `Seed responded:  (tcp://tcp://127.0.0.1:52920)` — empty display
name and the requester's own ephemeral source port. The authority answered a `HelloMsg` with
`WelcomeMsg.peer_record = membership.lookup(hello.node_id)`, i.e. the *requester's* record, so the
member only re-upserted itself and never learned the seed's identity/endpoint. The `tcp://tcp://`
double scheme came from `remote.address` already carrying the scheme.

**Spec intent (authoritative):** On `HelloMsg`, the seed MUST reply with a `WelcomeMsg` carrying the
**seed's own** `PeerRecord` (its node_id, display name, and reachable endpoint), so the joining
member can add the seed to its membership table.

**Fix applied:** `cmd/smo-node/main.cpp` — daemon builds a `self_record` (local node_id, display
name, `tcp://127.0.0.1:<port>` endpoint) at startup; the `HelloMsg` handler now sends that record.

**Verification:** members log `Seed responded: node-a (tcp://127.0.0.1:7777)` and reach
`Bootstrap complete. Peers: 1`.

---

### v0.0.5 Implementation Status — all documented gaps resolved

**Generated:** 2026-08-13 via `/tmp/opencode/e2e-full.sh` (65 PASS, 0 FAIL, 0 STUB)

All previously-stubbed CLI operations are now implemented over the connected session:

| Feature | CLI Command(s) | Implementation |
|---------|----------------|----------------|
| Contract deploy | `deploy <name> [--version] [--publisher]` | `DeploymentContract` (`system.contracts`) via `CONTRACT_MGMT` opcode 0x2D; computes deterministic `ctr_<hash>` id; persists `contracts.state` under node data dir |
| Contract undeploy | `undeploy <contract_id>` | `DeploymentContract::handle_undeploy` — lifecycle → `unloaded` |
| Contract status | `status <contract_id>` | `DeploymentContract::handle_status` — returns metadata + lifecycle state |
| Trace | `trace <contract_id>` | `DeploymentContract::handle_trace` — deployment lifecycle events |
| Remote dir sync | `sync <local> <remote>` | recursive walk, `FILE_OP mkdir/write` per entry (multi-file round-trip verified) |

The daemon registers `system.contracts` (with anonymous policy route + `CONTRACT_MGMT` handler) and routes the legacy stubs through the same network dispatch as exec/transfer. Execution-trace events (deployed/initialized/ready/undeployed) are recorded on the node and surfaced by `trace`.

**Notes:**
- All Sprint B Operations features per DISCUSSION_0045 are now implemented and covered by S4 e2e tests.
- `exec` stdout/stderr captured and returned escaped in the exec JSON result (v0.0.4).
- The 3-node E2E verifies all daemon paths: join, PQ handshake, seed bootstrap, HelloMsg/WelcomeMsg, membership sync, heartbeat, gossip, anti-entropy (BootstrapSync), CRL/policy deltas, plus network exec, transfer put/get/sync, discover, export, deploy/undeploy/status/trace, and persisted governance.

---

## References

- [RFC 0028] Contract Runtime
- [RFC 0029] Policy Engine
- [RFC 0031] Mesh Manager
- [RFC 0030] Native Contracts

---

**End of RFC 0032**