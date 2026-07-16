# RFC 0030 — Native Contracts

**Status:** ACCEPTED  
**Date:** 2026-07-16  
**Authors:** dotlinux26, D-O-T-Solutions

---

## Summary

This RFC defines the **Native Contracts** — built-in contract templates that ship with SMO Runtime. These are not user-deployable contracts but built-in primitives that the Runtime executes directly for common operations.

---

## Motivation

Every distributed system needs basic operations:
- File system operations
- Process management
- File transfer
- System control

Instead of requiring users to write and deploy these as custom contracts, SMO provides them as **Native Contracts** — built-in, pre-registered, optimized implementations that the Runtime executes directly.

---

## Design Principles

1. **Pre-registered** — No deployment needed
2. **Capability-gated** — Each opcode requires specific capability
3. **Standardized I/O** — JSON/CBOR request/response
4. **Deterministic** — Same input → same output
5. **Auditable** — Every execution logged to Event Store

---

## Contract Categories

### 1. Filesystem Contracts (`fs.*`)

| Opcode | Name | Capability | Description |
|--------|------|------------|-------------|
| 0x01 | `fs.list` | `CAP_FS_READ` | List directory |
| 0x02 | `fs.mkdir` | `CAP_FS_WRITE` | Create directory |
| 0x03 | `fs.remove` | `CAP_FS_DELETE` | Remove file/dir |
| 0x04 | `fs.copy` | `CAP_FS_READ` + `CAP_FS_WRITE` | Copy file/dir |
| 0x05 | `fs.move` | `CAP_FS_WRITE` | Move/rename |
| 0x06 | `fs.stat` | `CAP_FS_READ` | File info |
| 0x07 | `fs.read` | `CAP_FS_READ` | Read file |
| 0x08 | `fs.write` | `CAP_FS_WRITE` | Write file |
| 0x09 | `fs.chmod` | `CAP_FS_WRITE` | Change permissions |
| 0x0A | `fs.chown` | `CAP_FS_WRITE` | Change owner |
| 0x0B | `fs.symlink` | `CAP_FS_WRITE` | Create symlink |
| 0x0C | `fs.readlink` | `CAP_FS_READ` | Read symlink |
| 0x0D | `fs.realpath` | `CAP_FS_READ` | Resolve path |

---

### Filesystem Request/Response Format

**Request** (CBOR):
```cbor
{
  "opcode": 0x01,
  "params": {
    "path": "/var/log",
    "recursive": false,
    "show_hidden": false
  }
}
```

**Response** (CBOR):
```cbor
{
  "entries": [
    {
      "name": "syslog",
      "path": "/var/log/syslog",
      "is_directory": false,
      "is_symlink": false,
      "size": 1024,
      "modified_ns": 1700000000000000000,
      "permissions": "rw-r--r--",
      "owner": "root",
      "group": "root",
      "symlink_target": ""
    }
  ],
  "path": "/var/log"
}
```

---

### 2. Transfer Contracts (`file.*`)

| Opcode | Name | Capability | Description |
|--------|------|------------|-------------|
| 0x30 | `file.put` | `CAP_TRANSFER` + `CAP_FS_WRITE` | Upload file |
| 0x31 | `file.get` | `CAP_TRANSFER` + `CAP_FS_READ` | Download file |
| 0x32 | `file.sync` | `CAP_TRANSFER` + `CAP_FS_READ` + `CAP_FS_WRITE` | Sync directories |

---

### 3. Process Contracts (`proc.*`)

| Opcode | Name | Capability | Description |
|--------|------|------------|-------------|
| 0x10 | `proc.exec` | `CAP_EXEC_BASIC` | Execute command |
| 0x11 | `proc.kill` | `CAP_PROC_KILL` | Kill process |
| 0x12 | `proc.ps` | `CAP_PROC_READ` | List processes |
| 0x13 | `proc.top` | `CAP_PROC_READ` | System stats |
| 0x14 | `proc.top` | `CAP_PROC_READ` | Interactive top |
| 0x20 | `systemd.start` | `CAP_SYSTEMD_CTRL` | Start service |
| 0x21 | `systemd.stop` | `CAP_SYSTEMD_CTRL` | Stop service |
| 0x22 | `systemd.restart` | `CAP_SYSTEMD_CTRL` | Restart service |
| 0x23 | `systemd.status` | `CAP_SYSTEMD_READ` | Service status |
| 0x23 | `systemd.enable` | `CAP_SYSTEMD_CTRL` | Enable service |
| 0x23 | `systemd.disable` | `CAP_SYSTEMD_CTRL` | Disable service |

---

## Execution Model

### Request Flow

```
CLI: smo exec --scope mesh hostname
        ↓
Intent Parser → opcode: exec, args: ["hostname"]
        ↓
Selector → NodeSet {node-01, node-02}
        ↓
Policy Engine → Check CAP_EXEC_BASIC
        ↓
Scheduler → Queue (priority=Normal)
        ↓
Worker → Execute on node-01, node-02
        ↓
Event Store ← Event(ExecutionStarted)
        ↓
Result ← ExecutionResult{exit_code=0, stdout="node-01\nnode-02\n"}
```

### Native Contract Execution Flow

```
Executor
    ↓
Resolve opcode → NativeContract::exec
    ↓
Validate capabilities
        ↓
Execute (syscall / std::filesystem / fork+exec)
    ↓
Build response (CBOR)
    ↓
Return ExecutionResult
```

---

## Implementation

### Contract Registration

At startup, Runtime registers all native contracts:

```cpp
registry.register_kernel("fs.list",     KernelFSList{});
registry.register_kernel("fs.mkdir",    KernelFSMkdir{});
registry.register_kernel("fs.remove",   KernelFSRemove{});
registry.register_kernel("fs.copy",     KernelFSCopy{});
registry.register_kernel("fs.move",     KernelFSMove{});
registry.register_kernel("fs.stat",     KernelFSStat{});
registry.register_kernel("fs.read",     KernelFSRead{});
registry.register_kernel("fs.write",    KernelFSWrite{});
registry.register_kernel("fs.chmod",    KernelFSChmod{});
registry.register_kernel("fs.chown",    KernelFSChown{});
registry.register_kernel("fs.symlink",  KernelFSSymlink{});
registry.register_kernel("fs.readlink", KernelFSReadlink{});
registry.register_kernel("fs.realpath", KernelFSRealpath{});

registry.register_kernel("file.put",    KernelFilePut{});
registry.register_kernel("file.get",    KernelFileGet{});
registry.register_kernel("file.sync",   KernelFileSync{});

registry.register_kernel("exec",        KernelExec{});
registry.register_kernel("proc.kill",   KernelProcKill{});
registry.register_kernel("proc.ps",     KernelProcPS{});
registry.register_kernel("proc.top",    KernelProcTop{});
registry.register_kernel("systemd.start",   KernelSystemdStart{});
registry.register_kernel("systemd.stop",    KernelSystemdStop{});
registry.register_kernel("systemd.restart", KernelSystemdRestart{});
registry.register_kernel("systemd.status",  KernelSystemdStatus{});
registry.register_kernel("systemd.enable",  KernelSystemdEnable{});
registry.register_kernel("systemd.disable", KernelSystemdDisable{});
```

---

## Request/Response Format

All native contracts use CBOR for wire format.

### Standard Fields

**Request:**
```cbor
{
  "opcode": 0x01,
  "params": { ... }
}
```

**Response:**
```cbor
{
  "status": "ok",
  "result": { ... },
  "execution_id": "exec_abc123"
}
```

**Error:**
```cbor
{
  "status": "error",
  "error_code": 200,
  "message": "Path not found: /nonexistent",
  "execution_id": "exec_abc123"
}
```

---

## Error Codes

| Code | Name | HTTP-like | Description |
|------|------|-----------|-------------|
| 200 | PathNotFound | 404 | File/directory not found |
| 201 | MkdirFailed | 500 | Failed to create directory |
| 202 | RemoveFailed | 500 | Failed to remove |
| 203 | CopyFailed | 500 | Failed to copy |
| 204 | MoveFailed | 500 | Failed to move |
| 205 | StatFailed | 500 | Failed to stat |
| 206 | ReadFailed | 500 | Failed to read file |
| 207 | WriteFailed | 500 | Failed to write file |
| 208 | ChmodFailed | 500 | Failed to chmod |
| 209 | ChownFailed | 500 | Failed to chown |
| 210 | SymlinkFailed | 500 | Failed to create symlink |
| 211 | ReadlinkFailed | 500 | Failed to read symlink |
| 216 | RealpathFailed | 500 | Failed to resolve path |
| 220 | PutFailed | 500 | Upload failed |
| 221 | ChecksumMismatch | 400 | Checksum verification failed |
| 222 | GetFailed | 500 | Download failed |
| 223 | SyncFailed | 500 | Sync failed |
| 230 | ExecFailed | 500 | Command execution failed |
| 240 | KillFailed | 500 | Kill failed |
| 241 | PsFailed | 500 | Process listing failed |
| 242 | TopFailed | 500 | Top failed |
| 250 | SystemdFailed | 500 | Systemctl failed |

---

## Security Considerations

1. **Path traversal prevention** — All paths resolved with `realpath()`, checked against allowed roots
2. **Capability checks** — Every opcode validated against actor capabilities
3. **Resource limits** — `timeout_ns`, `max_memory_bytes`, `max_cpu_ms` enforced
4. **Audit logging** — Every execution logged to Event Store with full context
5. **Sandboxing** — Future: seccomp, namespaces, cgroups v2

---

## Testing

| Test | Description |
|------|-------------|
| `test_fs_list` | List directory, verify entries |
| `test_fs_mkdir_parents` | Create nested dirs |
| `test_fs_remove_recursive` | Remove tree |
| `test_fs_copy_preserve` | Preserve metadata |
| `test_fs_read_write_roundtrip` | Read/write/verify |
| `test_exec_simple` | `echo hello` |
| `test_exec_timeout` | Sleep 10s, timeout 1s |
| `test_proc_ps` | List processes |
| `test_systemd_status` | Query service status |

---

## Future Extensions

| Contract | Opcode | Capability | Description |
|----------|--------|------------|-------------|
| `fs.mount` | 0x0E | `CAP_FS_MOUNT` | Mount filesystem |
| `fs.umount` | 0x0F | `CAP_FS_MOUNT` | Unmount |
| `fs.quota` | 0x10 | `CAP_FS_QUOTA` | Disk quota |
| `net.listen` | 0x40 | `CAP_NET_BIND` | Listen TCP |
| `net.dial` | 0x41 | `CAP_NET_DIAL` | Connect TCP |
| `k8s.apply` | 0x50 | `CAP_K8S` | Apply K8s manifest |
| `k8s.get` | 0x51 | `CAP_K8S_READ` | Get resource |
| `docker.run` | 0x60 | `CAP_DOCKER` | Run container |

---

## References

- [RFC 0028] Contract Runtime
- [RFC 0029] Policy Engine
- [RFC 0031] Mesh Manager
- [RFC 0032] Context CLI

---

**End of RFC 0030**