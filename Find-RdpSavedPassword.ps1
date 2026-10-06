#Requires -Version 5.1
<#
.SYNOPSIS
    Recover the passwords of Remote Desktop (mstsc) connections saved on this PC.

.DESCRIPTION
    Enumerates the credentials stored in the CURRENT user's Windows Credential
    Manager, picks out the ones belonging to Remote Desktop connections
    ("Domain:target=TERMSRV/<host>"), and recovers the plaintext password.

    Two credential types matter:
      * Generic        - the blob already holds the password as UTF-16; read directly.
      * DomainPassword - the blob is DPAPI-protected; decrypted via CryptUnprotectData.

    IMPORTANT: the blobs are protected with DPAPI, whose master key is bound to
    BOTH the machine and the Windows user account. Therefore this script only
    works when it runs:
      * on the machine that saved the password, and
      * as the Windows user that was logged on when the password was saved.

    Copying the .cred files (or this script's output) to another computer will
    not reveal anything, because the DPAPI master key does not travel with them.

.PARAMETER All
    Also list every other credential stored by this account (git tokens, SSO
    entries, application secrets, ...). Off by default because that output is
    sensitive.

.PARAMETER IncludeReg
    Additionally show the Remote Desktop connection history kept in the registry
    (HKCU\Software\Microsoft\Terminal Server Client): host names, saved user
    names and the MRU list. Passwords are NOT stored there.

.PARAMETER Json
    Emit a single JSON document instead of the formatted report and suppress all
    human-readable output, so stdout can be piped straight into ConvertFrom-Json.
    Errors are written to stderr.

.EXAMPLE
    .\Find-RdpSavedPassword.ps1
    Show the Remote Desktop credentials saved by the current user.

.EXAMPLE
    .\Find-RdpSavedPassword.ps1 -All -IncludeReg
    Show every saved credential plus the registry connection history.

.EXAMPLE
    $creds = .\Find-RdpSavedPassword.ps1 -Json | ConvertFrom-Json
    $creds.RdpCredentials | Where-Object Password | Select-Object Host, UserName, Password

.EXAMPLE
    .\Find-RdpSavedPassword.ps1 -Json -All > creds.json
    Write the full result as JSON to a file.

.NOTES
    Requires Windows PowerShell 5.1+ (or PowerShell 7+). No administrator rights
    are needed: everything read here already belongs to the calling user.
    Use only on machines and accounts you are authorised to access.
#>
[CmdletBinding()]
param(
    [switch]$All,
    [switch]$IncludeReg,
    [switch]$Json
)

$ErrorActionPreference = 'Continue'

# In -Json mode every human-readable line is suppressed, so stdout carries
# nothing but the JSON document. (Write-Host output lands on stdout when the
# script is invoked with "1>" redirection, which would corrupt the JSON.)
function Write-Section($t) {
    if ($Json) { return }
    Write-Host ''
    Write-Host ('=' * 76) -ForegroundColor DarkGray
    Write-Host "  $t" -ForegroundColor Cyan
    Write-Host ('=' * 76) -ForegroundColor DarkGray
}
function Show-Raw($lines) { if ($Json) { return }; foreach ($l in $lines) { Write-Host $l } }
function Write-Status($msg, $color) {
    if ($Json) { return }
    if ($color) { Write-Host $msg -ForegroundColor $color } else { Write-Host $msg }
}
function Write-Problem($msg) {
    # Problems go to stderr so they never contaminate -Json stdout.
    if ($Json) { [Console]::Error.WriteLine("[!] $msg") } else { Write-Host "[!] $msg" -ForegroundColor Red }
}

Write-Section "Environment"
Write-Status ("User      : {0}\{1}" -f $env:USERDOMAIN, $env:USERNAME)
Write-Status ("Computer  : {0}" -f $env:COMPUTERNAME)
Write-Status ("PSVersion : {0}" -f $PSVersionTable.PSVersion)

if (-not ('DshCred' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public class DshCredInfo {
    public uint Type;
    public uint Persist;
    public string Target = "";
    public string UserName = "";
    public string Comment = "";
    public byte[] Blob;
}

public class DshCred {

    public const string BuildTag = "v3-Unicode-Pack8";

    // Pack = 8 is REQUIRED. Windows uses natural (8-byte) packing for CREDENTIAL,
    // but PowerShell 5.1's Add-Type compiler lays CharSet.Unicode structs out with
    // Pack = 1, which shifts every pointer field: TargetName lands on offset 8
    // instead of 16, the out-parameters get written to the wrong place, and
    // PtrToStringUni then reads a wild pointer (access violation in wcslen).
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 8)]
    private struct CREDENTIAL {
        public UInt32 Flags;
        public UInt32 Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public UInt32 CredentialBlobSize;
        public IntPtr CredentialBlob;
        public UInt32 Persist;
        public UInt32 AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    // The filter parameter is IntPtr, NOT string. Reason: when PowerShell binds
    // $null to a [string] parameter it passes an EMPTY STRING, not a null
    // reference -- i.e. a valid pointer to "\0". CredEnumerate then treats that
    // as a real filter and matches nothing (count = 0, no error). Passing
    // IntPtr.Zero explicitly is the only reliable way to say "all credentials".
    [DllImport("advapi32.dll", EntryPoint = "CredEnumerateW", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredEnumerateW(IntPtr filter, uint flags, out uint count, out IntPtr credentials);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern void CredFree(IntPtr buffer);

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    private struct DATA_BLOB {
        public int cbData;
        public IntPtr pbData;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptUnprotectData(ref DATA_BLOB pDataIn, StringBuilder ppszDataDescr,
        IntPtr pOptionalEntropy, IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, out DATA_BLOB pDataOut);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    private static int Align(int value, int alignment) {
        return (value + alignment - 1) / alignment * alignment;
    }

    private static string ReadUniPtr(IntPtr basePtr, int offset) {
        IntPtr p = Marshal.ReadIntPtr(basePtr, offset);
        if (p == IntPtr.Zero) { return ""; }
        try { return Marshal.PtrToStringUni(p); }
        catch { return ""; }
    }

    public static DshCredInfo[] Enumerate(IntPtr filter) {
        uint count = 0;
        IntPtr pCreds = IntPtr.Zero;
        try {
            if (!CredEnumerateW(filter, 0, out count, out pCreds)) {
                int err = Marshal.GetLastWin32Error();
                if (err == 1168) { return new DshCredInfo[0]; } // ERROR_NOT_FOUND
                throw new System.ComponentModel.Win32Exception(err);
            }
            List<DshCredInfo> list = new List<DshCredInfo>();
            int ptrSize = IntPtr.Size;

            // IMPORTANT: CredEnumerate returns an array of POINTERS to CREDENTIAL
            // (i.e. PCREDENTIAL*), NOT a contiguous array of CREDENTIAL structs.
            // Reading it as a struct array with a computed stride yields garbage
            // and eventually an access violation.
            //
            // Offsets come from Marshal.OffsetOf on the struct declared above, so
            // x86 and x64 are both handled by the CLR's own field layout. It is
            // cross-checked against the two fields whose absolute position is known
            // for certain (Type is always at 4, Persist always at 48 on x64 / 32 on x86).
            int offTarget   = Align(4, ptrSize);
            int offComment  = offTarget + ptrSize;
            int offBlobSize = Align(offComment + ptrSize + 8, ptrSize);
            int offBlob     = offBlobSize + ptrSize;
            int offPersist  = offBlob + ptrSize;
            int offUserName = offPersist + 8 + (ptrSize * 2);

            bool layoutOk;
            try {
                layoutOk = ((int)Marshal.OffsetOf(typeof(CREDENTIAL), "TargetName") == offTarget)
                        && ((int)Marshal.OffsetOf(typeof(CREDENTIAL), "CredentialBlobSize") == offBlobSize)
                        && ((int)Marshal.OffsetOf(typeof(CREDENTIAL), "CredentialBlob") == offBlob)
                        && ((int)Marshal.OffsetOf(typeof(CREDENTIAL), "Persist") == offPersist)
                        && ((int)Marshal.OffsetOf(typeof(CREDENTIAL), "UserName") == offUserName);
            } catch { layoutOk = false; }

            if (!layoutOk) {
                // Trust the CLR if the hand-derived table disagrees.
                offTarget   = (int)Marshal.OffsetOf(typeof(CREDENTIAL), "TargetName");
                offComment  = (int)Marshal.OffsetOf(typeof(CREDENTIAL), "Comment");
                offBlobSize = (int)Marshal.OffsetOf(typeof(CREDENTIAL), "CredentialBlobSize");
                offBlob     = (int)Marshal.OffsetOf(typeof(CREDENTIAL), "CredentialBlob");
                offPersist  = (int)Marshal.OffsetOf(typeof(CREDENTIAL), "Persist");
                offUserName = (int)Marshal.OffsetOf(typeof(CREDENTIAL), "UserName");
            }

            for (uint i = 0; i < count; i++) {
                IntPtr p = Marshal.ReadIntPtr(pCreds, (int)i * ptrSize);
                if (p == IntPtr.Zero) { continue; }

                DshCredInfo info = new DshCredInfo();
                info.Type     = (uint)Marshal.ReadInt32(p, 4);
                info.Persist  = (uint)Marshal.ReadInt32(p, offPersist);
                long blobSize = (long)(uint)Marshal.ReadInt32(p, offBlobSize);
                info.Target   = ReadUniPtr(p, offTarget);
                info.Comment  = ReadUniPtr(p, offComment);
                info.UserName = ReadUniPtr(p, offUserName);

                IntPtr blobPtr = Marshal.ReadIntPtr(p, offBlob);
                if (blobPtr != IntPtr.Zero && blobSize > 0 && blobSize <= 1024 * 1024) {
                    info.Blob = new byte[(int)blobSize];
                    Marshal.Copy(blobPtr, info.Blob, 0, (int)blobSize);
                }
                list.Add(info);
            }
            return list.ToArray();
        } finally {
            if (pCreds != IntPtr.Zero) { CredFree(pCreds); }
        }
    }

    public static string GenericPlain(byte[] blob) {
        if (blob == null || blob.Length == 0) { return ""; }
        string s = Encoding.Unicode.GetString(blob).TrimEnd('\0');
        if (s.Length == 0) { s = Encoding.UTF8.GetString(blob).TrimEnd('\0'); }
        return s;
    }

    public static string DpapiUnprotect(byte[] blob) {
        if (blob == null || blob.Length == 0) { return ""; }
        DATA_BLOB inBlob = new DATA_BLOB();
        DATA_BLOB outBlob = new DATA_BLOB();
        IntPtr p = Marshal.AllocHGlobal(blob.Length);
        try {
            Marshal.Copy(blob, 0, p, blob.Length);
            inBlob.cbData = blob.Length;
            inBlob.pbData = p;
            StringBuilder descr = new StringBuilder(512);
            if (!CryptUnprotectData(ref inBlob, descr, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, out outBlob)) {
                return "";
            }
            byte[] outBytes = new byte[outBlob.cbData];
            Marshal.Copy(outBlob.pbData, outBytes, 0, outBlob.cbData);
            LocalFree(outBlob.pbData);
            string s = Encoding.Unicode.GetString(outBytes).TrimEnd('\0');
            if (s.Length == 0) { s = Encoding.UTF8.GetString(outBytes).TrimEnd('\0'); }
            return s;
        } finally {
            Marshal.FreeHGlobal(p);
        }
    }
}
"@ -ErrorAction Stop
}

function Get-TypeName($t) {
    switch ($t) {
        1 { 'Generic' } 2 { 'DomainPassword' } 3 { 'DomainCertificate' }
        4 { 'DomainVisiblePassword' } 5 { 'GenericCertificate' } 6 { 'DomainExtended' }
        default { "Type$t" }
    }
}
function Get-PersistName($p) {
    switch ($p) { 1 { 'Session' } 2 { 'LocalMachine' } 3 { 'Enterprise' } default { "Persist$p" } }
}

# --------------------------------------------------------------- enumerate
Write-Section "Saved credentials + password recovery attempt"

$items = @()
try { $items = @([DshCred]::Enumerate([IntPtr]::Zero)) }
catch { Write-Problem "CredEnumerate failed: $($_.Exception.Message)" }

Write-Status ("Enumerated {0} credential(s) for this account." -f $items.Count) DarkGray

$rows = @()
foreach ($it in $items) {
    $isRdp = ($it.Target -match 'TERMSRV')

    $plain = ''
    $how   = ''
    if ($it.Blob -and $it.Blob.Length -gt 0) {
        if ($it.Type -eq 1) {
            $plain = [DshCred]::GenericPlain($it.Blob)
            $how   = 'plain UTF-16 blob'
        }
        else {
            $plain = [DshCred]::DpapiUnprotect($it.Blob)
            $how   = if ($plain) { 'DPAPI decrypted' } else { 'DPAPI failed' }
        }
    }
    else {
        $plain = ''
        $how   = 'no password stored'
    }

    $rows += [pscustomobject]@{
        RDP      = $(if ($isRdp) { 'YES' } else { '' })
        Type     = (Get-TypeName $it.Type)
        Persist  = (Get-PersistName $it.Persist)
        Target   = $it.Target
        UserName = $it.UserName
        Password = $plain
        How      = $how
    }
}

$rdp = @($rows | Where-Object { $_.RDP -eq 'YES' })

# ------------------------------------------------------------- JSON output mode
if ($Json) {
    $payload = [ordered]@{
        Computer        = $env:COMPUTERNAME
        User            = ("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME)
        CredentialCount = $items.Count
        RdpCount        = $rdp.Count
        RdpCredentials  = @($rdp | ForEach-Object {
            [ordered]@{
                Target   = $_.Target
                Host     = ($_.Target -replace '^.*TERMSRV/', '')
                UserName = $_.UserName
                Type     = $_.Type
                Persist  = $_.Persist
                Password = $_.Password
                How      = $_.How
            }
        })
    }
    if ($All) {
        $payload['AllCredentials'] = @($rows | ForEach-Object {
            [ordered]@{
                Target   = $_.Target
                UserName = $_.UserName
                Type     = $_.Type
                Persist  = $_.Persist
                Password = $_.Password
                How      = $_.How
            }
        })
    }
    # Write straight to stdout so the human-readable banner on the information
    # stream does not pollute redirected / piped output.
    [Console]::Out.WriteLine(($payload | ConvertTo-Json -Depth 4))
    return
}

if ($rdp.Count -gt 0) {
    Write-Host ''
    Write-Host ">>> RDP credentials found on THIS machine:" -ForegroundColor Green
    Write-Host ''
    foreach ($r in $rdp) {
        Write-Host ("  Target   : " + $r.Target) -ForegroundColor White
        Write-Host ("  User     : " + $r.UserName)
        Write-Host ("  Type     : " + $r.Type + "   (" + $r.Persist + ")")
        if ($r.Password) {
            Write-Host ("  PASSWORD : " + $r.Password) -ForegroundColor Yellow
            Write-Host ("             [" + $r.How + "]") -ForegroundColor DarkGray
        } else {
            Write-Host "  PASSWORD : <could not recover>" -ForegroundColor Red
            Write-Host ("             [" + $r.How + "]") -ForegroundColor DarkGray
        }
        Write-Host ''
    }
}
else {
    Write-Host ''
    Write-Host "No credential whose target contains 'TERMSRV' was found." -ForegroundColor Yellow
    Write-Host "  -> The RDP password was probably never saved (no 'Remember my credentials')." -ForegroundColor Yellow
    Write-Host "  -> Or it lives under a different Windows user account." -ForegroundColor Yellow
}

if ($All) {
    Write-Host ">>> All credentials of this account:" -ForegroundColor Green
    $rows | Format-Table -AutoSize -Property RDP, Type, Target, UserName, Password, How |
        Out-String -Width 400 | Write-Host
}
elseif ($rows.Count -gt $rdp.Count) {
    Write-Host ("({0} non-RDP credential(s) hidden - rerun with -All to see them)" -f ($rows.Count - $rdp.Count)) -ForegroundColor DarkGray
}

# ----------------------------------------------------------------- registry
if ($IncludeReg) {
    Write-Section "RDP connection traces (host / user only, no password)"
    $srvKey = 'HKCU:\Software\Microsoft\Terminal Server Client\Servers'
    Write-Host "--- $srvKey" -ForegroundColor DarkCyan
    if (Test-Path $srvKey) {
        Get-ChildItem $srvKey | ForEach-Object {
            $u = (Get-ItemProperty -Path $_.PSPath -Name Username -ErrorAction SilentlyContinue).Username
            Write-Host ("    Host: {0,-45} User: {1}" -f $_.PSChildName, $u)
        }
    } else { Write-Host "    (none)" }

    $defKey = 'HKCU:\Software\Microsoft\Terminal Server Client\Default'
    Write-Host "--- $defKey" -ForegroundColor DarkCyan
    if (Test-Path $defKey) {
        $props = Get-ItemProperty $defKey -ErrorAction SilentlyContinue
        $shown = $false
        if ($props) {
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -like 'PS*') { continue }
                Write-Host ("    {0,-12}: {1}" -f $p.Name, $p.Value)
                $shown = $true
            }
        }
        if (-not $shown) { Write-Host "    (no MRU entries)" }
    } else { Write-Host "    (none)" }

    Write-Host "--- .rdp files" -ForegroundColor DarkCyan
    $found = @()
    $dflt = Join-Path $env:USERPROFILE 'Documents\Default.rdp'
    $dfltItem = Get-Item $dflt -ErrorAction SilentlyContinue
    if ($dfltItem) { $found += $dfltItem.FullName }
    foreach ($d in @((Join-Path $env:USERPROFILE 'Desktop'), (Join-Path $env:USERPROFILE 'Documents'), (Join-Path $env:USERPROFILE 'Downloads'))) {
        if (Test-Path $d) { $found += @(Get-ChildItem $d -Filter '*.rdp' -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName) }
    }
    $found = @($found | Select-Object -Unique)
    if ($found.Count -gt 0) { $found | ForEach-Object { Write-Host "    $_" } } else { Write-Host "    (none)" }
}

# ---------------------------------------------------------------- next steps
Write-Section "Notes"
Write-Host @"
* Run this on the OLD computer, logged in as the SAME Windows user that used mstsc.
  Saved RDP credentials are per-user AND per-machine (protected by DPAPI).
  Copying the .cred files to another PC will NOT decrypt them.

* GUI equivalent: Control Panel -> Credential Manager -> Windows Credentials
  find "TERMSRV/<host>", click Show, then enter this Windows user's logon password.

* If the target account is a Microsoft account, just reset it online.
  If it is a domain account, ask the domain administrator.
  If it is a local account and you have physical access, reset it from WinRE.
"@
