# Print check (`--print`)

**This performs a real print.** Every time the worker starts with `--print`, a
page comes out of a physical printer. It is not a connectivity test that stops
at "the spooler answered": the first cycle's own diagnostic lines are submitted
to the Windows spooler as a real job. Point it at a low-cost or disposable
printer.

It fires **once**, after the first cycle and before the first tick — never on
the 30s loop.

`--print` is an imperative, not an optional stage. If it is set and anything it
needs is missing, the binary exits `2` at startup with the specific problem
rather than starting and skipping it.

## What it does

| # | stage | proves |
|---|---|---|
| P1 | `krb5` | the keytab is valid, the realm is right, a KDC answered, the clock is inside the skew |
| P2 | `spn` | `cifs/<fqdn>` is registered in Active Directory |
| P3 | `smb` | the print server accepted our ticket |
| P4 | `share` | the printer is shared under that name |
| P5 | `submit` | a real job reached the spooler and printed |

The print server has no Internet Printing role, so there is no IPP path.
Windows clients submit jobs over MS-RPRN on the `\pipe\spoolss` named pipe, and
MS-RPRN carries no authentication of its own (MS-RPRN §2.1) — the SMB session
*is* the authentication.

Kerberos or nothing. There is no NTLM path and no password path anywhere in
this binary, under any branch.

## Active Directory prerequisites

* The print server must be domain-joined and reachable by its **FQDN**.
  Kerberos maps an SPN from a name; an IP address or short name is rejected at
  startup.
* The probe account needs AES keys — `msDS-SupportedEncryptionTypes = 24`.
  Server 2025 domain controllers no longer issue RC4 TGTs.
* **Recommended:** join the host to AD and create a managed service account:

  ```sh
  adcli create-msa --domain=corp.example.com
  ```

  SSSD rotates its password every 30 days and no human ever knows it.

* **Fallback**, if the host may not be joined: a keytab exported for a
  dedicated service account.

## Keytab from a service-account password

There is no password path in this binary (see above) — a `svc-user` +
password credential is used exactly once, offline, to derive a keytab. The
password itself is never stored or run by the worker.

On the Linux host, with `krb5-user`/`krb5-workstation` installed:

```sh
ktutil
addent -password -p svc-print@CORP.EXAMPLE.COM -k 1 -e aes256-cts-hmac-sha1-96
addent -password -p svc-print@CORP.EXAMPLE.COM -k 1 -e aes128-cts-hmac-sha1-96
wkt svc.keytab
quit
```

Each `addent -password` prompts for the account's password interactively; it
is never written to disk or shell history. `-k 1` is a nominal kvno — gokrb5
requests kvno 0, which matches any entry, so it does not need to track AD's
actual key version.

The principal must match the account's `sAMAccountName` **case-exactly**:
AD derives the AES salt from `REALM+username`, and a case mismatch fails
Kerberos pre-auth (`KDC_ERR_PREAUTH_FAILED`) even though the password is
correct. The account also needs `msDS-SupportedEncryptionTypes = 24` (AES
only), as above.

Alternatively, from a domain-joined Windows host with `ktpass`:

```
ktpass /princ svc-print@CORP.EXAMPLE.COM /mapuser CORP\svc-print /pass * /crypto AES256-SHA1 /ptype KRB5_NT_PRINCIPAL /out svc.keytab
```

`/pass *` prompts for the password interactively. Caution: `ktpass` *sets*
the account's password to whatever is entered and rewrites its UPN — safe
only if the password entered is the account's current one. Prefer `ktutil`
when there's a choice.

Before sealing the keytab, verify it actually authenticates:

```sh
kinit -kt svc.keytab svc-print@CORP.EXAMPLE.COM && klist
```

Then feed it into the credential storage step below, and `shred -u` the
plaintext keytab afterward either way.

If the password rotates, regenerate the keytab the same way and restart the
unit — this is the same rotation trap as the managed-service-account case.

## Credential (RHEL 9)

One storage mechanism: systemd encrypted credentials, sealed to the TPM2 and/or
the host key, decrypted into non-swappable memory only while the unit runs and
readable only by the unit's UID.

```sh
systemd-creds encrypt --name=krb5-keytab svc.keytab /etc/credstore.encrypted/krb5-keytab
shred -u svc.keytab
```

Use `--with-key=host` on VMs with no vTPM; the default `auto` fails there.

Never put a keytab path with secrets, a password, or key material in
`Environment=`, in the unit file, or on the command line. `/proc/<pid>/cmdline`
is world-readable, and the binary refuses secret-bearing flags outright.

### Apply the drop-in

`LoadCredentialEncrypted=` has no optional form, so it ships as a drop-in
rather than in the base unit — otherwise every non-printing instance would fail
to start.

```sh
sudo mkdir -p /etc/systemd/system/pyck-debug-worker@.service.d
sudo install -m 0644 ../systemd/pyck-debug-worker@.service.d/kerberos.conf \
     /etc/systemd/system/pyck-debug-worker@.service.d/kerberos.conf
sudo systemctl daemon-reload
sudo systemctl restart pyck-debug-worker@test.service
```

Edit the `Environment=` lines in the drop-in for your server, share and
principal.

**Rotation trap:** credentials are snapshotted at unit start. After SSSD
rotates the managed service account's key, the **next** login fails with
`KDC_ERR_PREAUTH_FAILED` until the unit is restarted. Restart it, do not debug
it.

## Configuration

| variable | meaning |
|---|---|
| `PYCK_PRINT_SERVER` | print server **FQDN**; required with `--print` |
| `PYCK_PRINT_SHARE` | printer share name; required with `--print` |
| `PYCK_KRB5_PRINCIPAL` | principal the keytab holds a key for, `user` or `user@REALM` |
| `PYCK_KRB5_KEYTAB` | keytab path; defaults to `$CREDENTIALS_DIRECTORY/krb5-keytab` |
| `KRB5_CONFIG` | defaults to `/etc/krb5.conf` |

The realm comes from the principal's `@REALM` suffix, or from `default_realm`
in `krb5.conf` when the principal has none.

Refuse RC4 in `krb5.conf`:

```ini
[libdefaults]
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    allow_weak_crypto = false
```

## Error taxonomy

| signal | verdict |
|---|---|
| `failed to communicate with KDC` | no KDC reachable — DNS/firewall to the DC |
| `KDC_ERR_PREAUTH_FAILED` | wrong or **stale** keytab (key rotated → restart the unit) |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | account missing or disabled |
| `KRB_AP_ERR_SKEW` | clock skew > 300s — check `chronyc tracking` |
| `KDC_ERR_ETYPE_NOSUPP` | account has no AES keys (RC4-only) |
| `KDC_ERR_S_PRINCIPAL_UNKNOWN` | `cifs/<fqdn>` unknown — wrong FQDN or server not domain-joined |
| `KDC did not respond appropriately to FAST` | AD quirk — `DisablePAFXFAST(true)` missing |
| SMB session rejected after a valid ticket | server-side: account not permitted, or SMB policy |
| share absent from list | printer not shared under that name |
| `RpcOpenPrinter`/spooler RPC fault | share exists but is not a printer, or the spooler service is down |
| job accepted but never leaves the queue | driver/paper/offline issue on the printer itself — outside this tool |
