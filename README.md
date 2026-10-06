# Find-RdpSavedPassword.ps1

Recover the passwords of Remote Desktop (`mstsc`) connections that were saved
with **"Remember my credentials"** on a Windows machine.

If you have ever ticked that checkbox, the password is sitting in the Windows
Credential Manager — usually recoverable in plaintext. This script finds those
entries and prints the passwords.

```
>>> RDP credentials found on THIS machine:

  Target   : TERMSRV/file-server-01
  User     : CONTOSO\administrator
  Type     : Generic   (LocalMachine)
  PASSWORD : CorrectHorseBatteryStaple
             [plain UTF-16 blob]
```

---

## ⚠️ Read this first

**The script only works on the machine that saved the password, running as the
user who saved it.**

Saved RDP credentials are protected with **DPAPI**, whose master key is derived
from *both* the machine and the Windows user account. That means:

| Scenario | Works? |
|---|---|
| Run on the PC that saved the password, as the same user | ✅ yes |
| Run on a different PC | ❌ no — nothing to find |
| Run as a different user on the same PC | ❌ no — credentials are per-user |
| Copy `%LOCALAPPDATA%\Microsoft\Credentials\*` to another PC and decrypt | ❌ no — the DPAPI key does not travel |

There is no way around this: it is the exact property that makes DPAPI useful.

---

## Requirements

- Windows 10 / 11 / Server 2016+ (or Windows 8.1 with WMF 5.1)
- Windows PowerShell 5.1+ **or** PowerShell 7+
- **No administrator rights** — everything read here already belongs to the
  calling user
- No third-party dependencies (uses only `advapi32.dll` / `crypt32.dll` / `kernel32.dll`)

---

## Quick start

1. Download both files into the **same folder**:

   ```
   Find-RdpSavedPassword.ps1
   Run-Find-RdpSavedPassword.bat
   ```

2. Log on to the machine as the user who saved the password.
3. **Double-click `Run-Find-RdpSavedPassword.bat`.**

The `.bat` launcher calls PowerShell with `-ExecutionPolicy Bypass` for that one
invocation only, so you don't have to change any system setting. It also pauses
at the end so the window doesn't vanish.

### Running it manually

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Find-RdpSavedPassword.ps1
```

Trying to run the `.ps1` directly (right-click → *Run with PowerShell*) often
fails with:

> 无法加载文件 ... 因为在此系统上禁止运行脚本
> `... cannot be loaded because running scripts is disabled on this system.`

That is the default `Restricted` execution policy. Use the `.bat`, or pass
`-ExecutionPolicy Bypass` as shown above.

---

## Parameters

| Parameter | Description |
|---|---|
| *(none)* | Show only Remote Desktop credentials |
| `-All` | Also list **every other** credential of this account (git tokens, SSO entries, application secrets…). Sensitive — see below. |
| `-IncludeReg` | Also show the RD connection history from the registry: host names, saved user names, MRU list. Passwords are not stored there. |
| `-Json` | Emit one JSON document and suppress all human-readable output, so stdout can be piped directly. Errors go to stderr. |

```powershell
.\Find-RdpSavedPassword.ps1                      # RDP credentials only
.\Find-RdpSavedPassword.ps1 -All                 # every credential
.\Find-RdpSavedPassword.ps1 -All -IncludeReg     # + connection history
.\Find-RdpSavedPassword.ps1 -Json                # machine-readable
Get-Help .\Find-RdpSavedPassword.ps1 -Full       # built-in help
```

### JSON output

```powershell
$creds = .\Find-RdpSavedPassword.ps1 -Json | ConvertFrom-Json

$creds.RdpCredentials |
    Where-Object Password |
    Select-Object Host, UserName, Password
```

```json
{
  "Computer": "WORKSTATION-01",
  "User": "WORKSTATION-01\\alice",
  "CredentialCount": 8,
  "RdpCount": 2,
  "RdpCredentials": [
    {
      "Target": "TERMSRV/file-server-01",
      "Host": "file-server-01",
      "UserName": "CONTOSO\\administrator",
      "Type": "Generic",
      "Persist": "LocalMachine",
      "Password": "CorrectHorseBatteryStaple",
      "How": "plain UTF-16 blob"
    }
  ]
}
```

---

## Understanding the output

A saved RDP credential is stored under the target name
`Domain:target=TERMSRV/<host>`. Two credential types behave very differently:

| Type | What the blob holds | Recovered? |
|---|---|---|
| **Generic** | the password itself, as UTF-16 — already plaintext | ✅ read directly |
| **DomainPassword** | a DPAPI-protected blob | ✅ via `CryptUnprotectData` |
| *(any)* with `CredentialBlobSize = 0` | nothing — no password was ever saved | ❌ genuinely absent |

The `How` column tells you which path was taken:

| `How` | Meaning |
|---|---|
| `plain UTF-16 blob` | Generic credential, password read directly |
| `DPAPI decrypted` | Domain credential, successfully unprotected |
| `DPAPI failed` | Blob present but could not be unprotected (usually wrong user/machine) |
| `no password stored` | `CredentialBlobSize` is 0 — the password was never saved |

`no password stored` is a **definitive answer**, not a failure. It means
"Remember my credentials" was not ticked for that connection, so there is
nothing to recover — no tool can help.

---

## How it works

1. `CredEnumerateW` lists every credential of the current user.
2. Entries whose target matches `TERMSRV` are selected.
3. `Generic` blobs are decoded as UTF-16.
4. Other blobs are passed to `CryptUnprotectData` (DPAPI) in the calling user's
   context.

### Implementation notes

These details cost real debugging time, so they are documented for anyone
reading or forking the code:

- **`CredEnumerate` returns an array of *pointers*, not an array of structs**
  (`PCREDENTIAL*`). Iterating it with a computed struct stride yields garbage and
  then an access violation.
- **Passing `$null` to a `[string]` P/Invoke parameter from PowerShell does not
  produce a NULL pointer** — PowerShell converts it to an empty string, i.e. a
  valid pointer to `"\0"`. `CredEnumerate` then treats it as a real filter and
  returns **0 results with no error**. The filter parameter is therefore declared
  as `IntPtr` and `[IntPtr]::Zero` is passed explicitly.
- **Field offsets must respect pointer alignment.** `4 + IntPtr.Size` is wrong:
  on x64 it gives 12 while `TargetName` actually sits at offset 8. Offsets are
  derived with alignment and cross-checked against `Marshal.OffsetOf` at runtime.
- **`Pack = 8` is set explicitly** on the interop structs so the layout matches
  what Windows actually allocated.
- Both **32-bit and 64-bit** PowerShell are supported; offsets are computed from
  `IntPtr.Size`.

---

## Troubleshooting

**`Enumerated 0 credential(s)`**
Either nothing is stored (the checkbox was never ticked), or you are running as a
different user than the one that saved the password. Try `-All` to see what this
account does have, and double-check which account used `mstsc`.

**`PASSWORD : <could not recover>` with `DPAPI failed`**
The blob exists but belongs to a different user or machine context. Re-run as the
original user on the original machine.

**"running scripts is disabled on this system"**
Use `Run-Find-RdpSavedPassword.bat`, or pass `-ExecutionPolicy Bypass`.

**The GUI alternative**
You don't strictly need this script. Open
*Control Panel → User Accounts → Credential Manager → Windows Credentials*, find
the `TERMSRV/<host>` entry, click **Show**, and enter your Windows logon password.
The script is just faster and scriptable.

---

## Security & legal notice

This tool performs **credential recovery on the machine you are already logged
into**, using documented Windows APIs. It does not bypass authentication, does
not modify the system, and requires no elevation.

It is intended for **your own machines and accounts, or systems you are
explicitly authorised to administer** — for example an administrator recovering
a password they saved for a server they manage.

Running it against accounts or machines you are not authorised to access may be
illegal in your jurisdiction (e.g. unauthorised access offences under the U.S.
CFAA, China's Criminal Law Art. 285, or the UK Computer Misuse Act).

**Handle the output as a secret.** It contains plaintext passwords. The `-All`
flag additionally dumps unrelated credentials such as git tokens and
application secrets. Do not paste it into issues, logs, or chat.

If you are publishing results anywhere, redact them, and consider deleting the
saved credentials afterwards — plaintext in the credential store is readable by
any process running as your user.

---

## License

[MIT](LICENSE)
