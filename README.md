# Identity Stack Scanner

**v0.1 — zero-privilege external fingerprinting for Microsoft Entra estates.**

Answers one question per domain, in under a second, without credentials:
**who actually authenticates this organisation's users, and is the identity layer theirs to fix?**

---

## Business problem

Qualifying an identity engagement normally means a discovery call. Before that call, the
only honest answer to "what are they running?" is a guess — so effort gets spent on
organisations whose identity layer belongs to somebody else entirely.

Four public lookups settle it. The decisive one, `getuserrealm.srf`, is unauthenticated,
returns in milliseconds, and is almost never used.

- **Managed** — Entra authenticates directly. The identity layer is theirs, and the gap is real.
- **Federated** — someone else owns it. The `AuthURL` names who.

Everything else in this tool is the supporting evidence around that one field.

---

## Architecture

Four unauthenticated lookups, in order, per domain:

| # | Lookup | Settles |
|---|--------|---------|
| 1 | `MX` records | Which mail platform sits behind the domain — or which gateway is hiding it |
| 2 | `SPF` (TXT) | Which platform is authorised to send as the domain; reveals the platform behind a gateway |
| 3 | `…/v2.0/.well-known/openid-configuration` | Whether an Entra tenant exists, and its GUID |
| 4 | `getuserrealm.srf?…&json=1` | **Decisive.** `NameSpaceType` = Managed or Federated, plus brand and `AuthURL` |

A gateway in MX hides the real platform, so the tool resolves MX against SPF and reports an
`EffectiveMail` platform. Where a gateway delegates via a macro include that resolves
per-sender, four public lookups genuinely cannot settle it — the tool reports `Unknown` and
raises `PLATFORM_OPAQUE` rather than guessing.

### Signals

| Code | Meaning |
|------|---------|
| `MANAGED_ENTRA` | Managed namespace with a resolvable tenant — Entra is the identity backbone |
| `FOREIGN_IDP` | Federated, `AuthURL` names Okta, Ping, OneLogin, Duo, Google or CyberArk |
| `LEGACY_FEDERATION` | Federated to on-premises AD FS — a migration candidate, not a competitor |
| `SHELL_TENANT` | `FederationBrandName` is "Default Directory" — the tenant was never configured |
| `BRAND_MISMATCH` | Tenant brand does not match the domain — an estate grown by acquisition, or a parent company holding decision authority |
| `SPLIT_ESTATE` | Entra identity but non-Microsoft mail — identity and productivity split across vendors |
| `MIXED_ESTATE` | SPF authorises two or more platforms — a reconciliation problem in miniature |
| `UNGOVERNED_DNS` | SPF is IP literals with no includes — DNS grew without governance |
| `SECURITY_SPEND` | KnowBe4, Proofpoint, Mimecast or Barracuda in SPF — an existing budget line |
| `HRIS_SELF_PUBLISHED` | Dayforce, Workday, ADP or UKG in SPF — self-published proof of production use |
| `GATEWAY_HIDING` | A security gateway sits in MX |
| `PLATFORM_OPAQUE` | Gateway present and SPF will not name the platform |
| `SPF_DUPLICATE` / `SPF_OVER_LIMIT` / `NO_SPF` | RFC 7208 defects |

### Verdicts

`Qualified` · `Opportunity` · `Requalify` · `Disqualified` · `Review`

---

## Implementation

Requires PowerShell 5.1 or later. No modules, no credentials, no installation.

```powershell
# One domain
.\Invoke-IdentityStackScan.ps1 -Domain contoso.com

# A list, to CSV
.\Invoke-IdentityStackScan.ps1 -Path .\domains.txt -CsvPath .\results.csv

# Pipeline
'contoso.com','fabrikam.com' | .\Invoke-IdentityStackScan.ps1 |
    Format-Table Domain,Verdict,NameSpaceType,SignalCodes
```

| Parameter | Default | Notes |
|-----------|---------|-------|
| `-DnsMethod` | `Auto` | `Native` uses `Resolve-DnsName` (Windows). `Doh` uses DNS-over-HTTPS, so the tool runs on Linux and macOS too. `Auto` picks one. |
| `-DelayMs` | `250` | Pause between domains. Deliberate. Do not set to 0 for large batches. |
| `-TimeoutSec` | `15` | Per-request HTTP timeout |
| `-CheckSpfLimit` | off | Also resolves nested includes to count DNS lookups against the RFC 7208 limit of 10. Off by default because it multiplies query volume. |
| `-CsvPath` / `-JsonPath` | — | CSV is flat and filterable; JSON carries full signal detail |

---

## Verification

Validated against a set of domains whose identity stacks were independently confirmed
beforehand. All classifications matched, including three organisations federated to Okta,
one shell tenant caught solely by `FederationBrandName`, and one split estate with Entra
identity on Google mail. Tenant GUIDs reproduced exactly.

Edge cases exercised: non-existent domain (degrades to `Disqualified` / `Low` confidence,
no crash), malformed input (skipped with a warning), gateway-obscured platform (reports
`Unknown` rather than guessing), single-record DNS responses (the array-context bug this
caught is why `Set-StrictMode -Version Latest` stays on).

Results are not published here. See Responsible use.

---

## Responsible use

**v0.1 reads only public DNS and Microsoft's public endpoints.** No authentication, no
tenant access, no writes, and nothing that is not already available to any member of the
public. It is safe to run against any domain.

That is a deliberate boundary, not an accident of scope:

- **No mass-scan or crawl mode, and none will be added.** The tool takes a list you supply.
  It does not discover targets, and it rate-limits by default.
- **Later versions will not inherit this licence to run anywhere.** v0.5 reads a tenant via
  Microsoft Graph and therefore runs *only where the owner has asked for it.*
- **Aggregate findings, not named ones.** "Of 28 organisations checked, 3 federate to Okta"
  is a finding worth publishing. The same list with names and weaknesses attached is not.
  The bundled `.gitignore` excludes `_verify-*` output for this reason — keep it that way.

---

## Licence

MIT. See `LICENSE`.
