# DDM Software Update Visibility for Jamf Pro

Reports whether Macs are actually meeting the macOS versions their Jamf Pro Software Update blueprints enforce, and explains why when they are not.

Software Update blueprints are set-and-forget by design. You scope a blueprint, pick a deadline, and trust that Macs update. Jamf Pro inventory shows the current OS version, which tells you a Mac is behind but not what version it was told to install, when the deadline was, or whether anything is blocking it.

This fills that gap with one policy script and two extension attributes.

---

## Contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Setup](#setup)
- [Example output](#example-output)
- [Reading the values](#reading-the-values)
- [Smart groups](#smart-groups)
- [Advanced search](#advanced-search)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [Repository layout](#repository-layout)

---

## How it works

A policy runs once daily, reads enforcement state from the local system, and writes two values into Jamf Pro via the API:

```
Daily policy (Recurring Check-in, Once every day)
  └─ ddm-update-report.sh
       reads  /var/log/install.log
              /Library/Preferences/com.apple.SoftwareUpdate
              managed preference domains
       POST   /api/v1/oauth/token                      get access token
       GET    /api/v1/computers-inventory?filter=...    resolve own computer ID
       PATCH  /api/v2/computers-inventory-detail/{id}   write both EAs, one call
       POST   /api/v1/auth/invalidate-token             discard the token
```

Four HTTP requests per Mac per day. Both extension attribute values travel in a single `PATCH`, since the payload accepts an array.

### Where the data comes from

macOS logs the enforced target version on the same `install.log` line as the deadline:

```
2026-08-30 15:23:36-04 host softwareupdated[754]: -[SUOSUManagedServiceDaemon
declarationFromKeys]: Falling back to default applicable declaration:
SUCoreDDMDeclaration (DeclarationKey:...|EnforcedInstallDate:2026-08-21T13:00:00
|VersionString:26.6.2|BuildVersionString:(null)|DetailsURL:(null)
|companyName:(null)|NotificationsEnabled:YES)
```

| Field | Purpose |
|---|---|
| `EnforcedInstallDate` | The deadline. Local time, no timezone suffix. |
| `VersionString` | The enforced target version. |

Compliance is a version comparison between the installed version and the highest enforced target found in the log. That is deliberate: `softwareupdated` re-logs old declarations indefinitely, so timestamps cannot distinguish a satisfied declaration from a live one. A version comparison is also self-correcting, since a Mac already past a stale target still reports compliant.

### Why a policy instead of extension attribute scripts

Script-type extension attributes run on every inventory submission. Collecting this data requires reading a large log and calling `profiles`, which can take several seconds per attribute, on data that changes once a day. Jamf's documentation notes that extension attributes "may add time and network traffic to the inventory collection process."

Text Field extension attributes execute nothing at recon, so inventory cost is zero. The tradeoff is that they can only be populated through the API, which is what the policy does.

---

## Requirements

- Jamf Pro 10.49 or later, for API Roles and Clients
- macOS 14 or later on target Macs, since DDM software update enforcement does not exist before that
- Supervised Macs, which DDM enforcement requires
- Policy runs as root, which the jamf binary does by default

---

## Setup

### 1. Create an API Role

**Settings → System → API roles and clients → API Roles → New**

| Setting | Value |
|---|---|
| Display name | `DDM Update Reporter` |
| Privileges | `Read Computers`, `Update Computers` |

Those two privileges are the entire permission set. Nothing else is needed, and nothing else should be granted: the credential is distributed to clients, so the role defines the blast radius if it is ever extracted.

### 2. Create an API Client

**Settings → System → API roles and clients → API Clients → New**

| Setting | Value |
|---|---|
| Display name | `DDM Update Reporter` |
| API Roles | `DDM Update Reporter` |
| Access token lifetime | `300` seconds |

Enable the client, then click **Generate client secret**. Record the Client ID and Client Secret. The secret is displayed only once.

### 3. Create two extension attributes

**Settings → Computer management → Extension attributes → New**, twice.

| Display name | Data Type | Input Type | Inventory Display |
|---|---|---|---|
| `DDM Update Summary` | String | **Text Field** | Operating System |
| `DDM Update Blocker` | String | **Text Field** | Operating System |

> **Input Type must be Text Field.** A script-type extension attribute is recalculated at every recon and would overwrite whatever the policy writes. The API also refuses writes to script-typed attributes.

Record each attribute's ID, visible in the URL when you open it:

```
https://your.jamfcloud.com/computerExtensionAttributes.html?id=42&o=r
                                                               ^^ ID is 42
```

### 4. Add the script

**Settings → Computer management → Scripts → New**, and paste in [`policy/ddm-update-report.sh`](policy/ddm-update-report.sh).

Under the **Options** tab, label the parameters:

| Parameter | Label | Required |
|---|---|---|
| 4 | Summary EA ID | Yes |
| 5 | Blocker EA ID | Yes |
| 6 | API Client ID | Yes |
| 7 | API Client Secret | Yes |
| 8 | Jamf Pro URL (override) | No |

Parameter 8 is an override only. The script reads the Jamf Pro URL from `/Library/Preferences/com.jamfsoftware.jamf.plist`, so nothing needs editing between environments.

### 5. Create the daily policy

**Computers → Policies → New**

| Setting | Value |
|---|---|
| Display name | `DDM Update Report (Daily)` |
| Trigger | Recurring Check-in |
| Execution Frequency | Once every day |
| Scope | Managed Macs running macOS 14 or later |
| Scripts | `ddm-update-report.sh` with parameters 4 through 7 populated |

Jamf Pro enforces the once-daily limit. Flushing the policy log forces a re-run on the next check-in.

### 6. Create a Self Service policy (optional)

Duplicate the daily policy and change:

| Setting | Value |
|---|---|
| Trigger | None |
| Execution Frequency | Ongoing |
| Self Service | Enabled, display name `Refresh Update Status` |

Gives admins and users an on-demand refresh without touching policy logs.

---

## Example output

### DDM Update Summary

```
Compliant | Device target: 26.6.2 by 2026-08-21 13:00 | Installed: 26.6.2 | as of 2026-09-14 08:15
Pending | Device target: 26.7 by 2026-10-01 13:00 | Installed: 26.6.2 | as of 2026-09-14 08:15
Overdue | Device target: 26.6.2 by 2026-08-21 13:00 | Retrying 2026-09-14 11:06 | Installed: 26.5.1 | as of 2026-09-14 08:15
No Enforcement Recorded | Installed: 26.6.2 | as of 2026-09-14 08:15
Not Supported - macOS Too Old | Installed: 13.6 | as of 2026-09-14 08:15
PARSE FAIL | raw: <sanitized log text> | as of 2026-09-14 08:15
```

| Status | Meaning |
|---|---|
| `Compliant` | Installed version is at or above the enforced target. |
| `Pending` | Behind target, deadline not yet reached. |
| `Overdue` | Behind target, deadline passed. |
| `No Enforcement Recorded` | No declaration found. Usually means no blueprint is scoped. |
| `Not Supported - macOS Too Old` | macOS 13 or earlier. |
| `PARSE FAIL` | A declaration was found but could not be read. Carries the raw log text. |

### DDM Update Blocker

```
Not Applicable - Compliant
Awaiting Restart | staged 26.6.2, running 26.6.1
Low Disk Space | 8 GB free, ~15 GB needed
Bootstrap Token Not Escrowed | Apple Silicon, blocks unattended install
Update Deferral Active | enforcedSoftwareUpdateDelay = 30 days
Past Due - Forced Install Pending | 1 scheduled attempt, up 2d, forcing in 7m, set for 2026-09-14 11:06
Update Scan Stale | up 3d with no scan since boot, last 84d ago
Not Supervised | DDM enforcement requires supervision
No Local Blocker Found | 200 GB free, check Jamf Pro plan state
```

Checks run in a fixed order and the first match wins. Hard blockers are evaluated before in-progress states, because a hard blocker is usually the reason a forced install keeps failing:

1. `Awaiting Restart` the work is done, only a reboot is missing
2. `Low Disk Space` the update cannot install
3. `Bootstrap Token Not Escrowed` the install cannot be authorized unattended
4. `Update Deferral Active` the update is hidden by policy
5. `Past Due - Forced Install Pending` no hard blocker, macOS is actively retrying
6. `Update Scan Stale` the Mac has not scanned since it booted
7. `Not Supervised` enforcement does not apply

`No Local Blocker Found` is a real result, not a failure. It means the device looks healthy and the problem is server side, which is when the Jamf Pro managed software update plan state is worth checking:

```
GET /api/v1/managed-software-updates/plans?filter=device.deviceId=="<computer id>"
GET /api/v1/managed-software-updates/plans/<planUuid>
```

That returns `status.state` and an `errorReasons` array with values such as `NO_UPDATES_AVAILABLE`, `NOT_SUPERVISED`, `NO_DISK_SPACE`, and `APPLE_SILICON_NO_ESCROW_KEY`.

---

## Reading the values

### Two dates, and why both appear

`EnforcedInstallDate` never moves. It is the original deadline from the declaration and stays fixed indefinitely.

Once that deadline lapses, macOS schedules its own retry, tells the user the update will install automatically at a specific time, and pushes that time forward until the install succeeds. It is logged as `setPastDuePaddedEnforcementDate`.

So on an overdue Mac the enforced deadline is history and the retry is the live date. The summary reports both: the deadline shows how far behind the Mac is, the retry shows what happens next.

### "Device target" wording

The summary reports the declaration the Mac actually holds, which is not always what the Jamf Pro console shows as scheduled. When they disagree, the device has not received the newer declaration, and that disagreement is useful information rather than a defect.

To confirm what a specific Mac holds:

```bash
sudo grep -o 'EnforcedInstallDate:[^|]*|VersionString:[^|]*' /var/log/install.log | sort -u
```

### Scheduled attempts

The count in `Past Due - Forced Install Pending` is how many times macOS has scheduled the forced install for the current past-due deadline. It counts **distinct scheduled times, not log entries**, because macOS re-logs the same unchanged retry repeatedly. Seventy log lines commonly represent a single scheduled attempt.

| Reading | Interpretation |
|---|---|
| 1 to 2 attempts | Normal past-due handling. An install is likely in progress. |
| Window upcoming | macOS is waiting to force the install. No action needed. |
| Window elapsed, count static across runs | Stalled. Worth investigating. |
| Roughly one attempt per hour of uptime | A failure loop. The install starts and never completes. |

### The `as of` stamp

Text Field extension attributes retain their values indefinitely. If the policy stops running, the record keeps showing its last result with no indication that it is old. The timestamp makes staleness visible.

---

## Smart groups

All of these use the `like` operator, which is a substring match. Status prefixes were chosen so that none is a substring of another.

| Group name | Criteria | Purpose |
|---|---|---|
| Update Enforcement Failures | `DDM Update Summary` like `Overdue` | Macs behind their enforced target with the deadline passed. |
| Never Enforced | `DDM Update Summary` like `No Enforcement Recorded` | A scoping problem rather than an update problem. |
| Just Needs a Reboot | `DDM Update Blocker` like `Awaiting Restart` | Updates already staged. A restart clears the whole group. |
| Out of Space | `DDM Update Blocker` like `Low Disk Space` | Fixable without touching update configuration. |
| Bootstrap Token Missing | `DDM Update Blocker` like `Bootstrap Token Not Escrowed` | Often a fleet-wide enrollment issue, not per-Mac. |
| Forced Install Looping | `DDM Update Blocker` like `Past Due - Forced Install Pending` | Read the attempt count against the uptime in the same string. |
| Scanning Broken | `DDM Update Blocker` like `Update Scan Stale` | Usually a network or proxy problem affecting many Macs. |
| Parser Needs Attention | `DDM Update Summary` like `PARSE FAIL` | Should be empty. The value carries the raw log text. |

Two worth combining:

**Server-side failures.** Healthy devices that still are not updating. This is the only group that needs the plan-state lookup, and narrowing to it first means running that lookup on a handful of Macs rather than the whole fleet.

```
DDM Update Blocker  like  No Local Blocker Found
    AND
DDM Update Summary  like  Overdue
```

**Aged failures.** Filters out Macs that only just missed a deadline.

```
DDM Update Summary  like  Overdue
    AND
Operating System Version  is not  <your current target version>
```

### Scanning-broken follow-up

If that group is not empty, check egress to Apple's update endpoints from the affected network:

```
gdmf.apple.com
swscan.apple.com
swdist.apple.com
updates.cdn-apple.com
```

A proxy, SSL inspection, or a broken content caching server produces the same symptom. Note that the check is gated on uptime, so Macs returning from an extended period powered off do not appear here.

---

## Advanced search

For account reviews and exports, one saved search with these display columns:

```
Computer Name
Last Inventory Update
Operating System Version
DDM Update Summary
DDM Update Blocker
```

Summary and Blocker side by side read as what and why on a single row, which exports cleanly to CSV.

---

## Troubleshooting

The script writes to `/var/log/ddm-update-report.log` on the client, and its output is captured in the Jamf Pro policy log.

| Exit code | Meaning | First thing to check |
|---|---|---|
| 0 | Values written | |
| 1 | Configuration problem | A missing parameter, or a non-numeric EA ID in parameter 4 or 5 |
| 2 | Authentication failed | Client ID, client secret, and that the API client is enabled |
| 3 | Could not resolve computer record | The `Read Computers` privilege on the API role |
| 4 | The write failed | HTTP code and response body are logged |

**HTTP 400 on the PATCH** almost always means an extension attribute is still Input Type `Script`, or a parameter holds the wrong ID. The script logs this hint explicitly.

The authentication response body is never logged, only whether a token was obtained.

### Diagnostic scripts

Three read-only scripts are included for investigating individual Macs. None makes changes.

| Script | Use |
|---|---|
| `discovery/probe-target-version.sh` | Dumps every enforcement declaration and the surrounding log context. Run first when a Mac reports `PARSE FAIL`. |
| `discovery/probe-failing-mac.sh` | Run on a Mac reporting `Overdue` with `No Local Blocker Found`. Sweeps the unified log for failure wording. |
| `discovery/ddm-su-discovery.sh` | Broad dump of every local software update data source. |

Each writes a report to the console user's Desktop.

```bash
sudo /bin/bash discovery/probe-target-version.sh
```

---

## Limitations

**A credential is distributed to clients.** Unavoidable for an API write from a policy. The two-privilege API role limits what an extracted credential could do to writing inventory data on computer records.

**Log rotation.** If `install.log` and all its `.gz` archives rotate past every declaration, the summary reports `No Enforcement Recorded`. In practice logs retain many months of enforcement cycles, and version comparison means a rotated-away declaration is usually harmless.

**Values persist when the policy fails.** Inherent to Text Field extension attributes. The `as of` stamp is the mitigation.

**Version-only scope.** Only `VersionString` is evaluated, not `BuildVersionString`. Environments enforcing specific builds during a seeding period will need this extended.

**Unsupervised Macs** produce no declarations at all and report `No Enforcement Recorded`, which reads as a scoping problem rather than the supervision problem it is.

**Disk space thresholds are heuristics.** 15 GB for a minor update, 45 GB for a major upgrade. Adjust `needGB` in the script for your environment.

---

## Repository layout

```
policy/
  ddm-update-report.sh          the policy script: collects and writes
discovery/
  probe-target-version.sh       enforcement declarations and log context
  probe-failing-mac.sh          failure sweep for a stuck Mac
  ddm-su-discovery.sh           broad local data source dump
```
