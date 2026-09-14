#!/bin/bash
#
# ddm-update-report.sh
#
# Collects DDM software update enforcement status and writes it to two Jamf Pro
# extension attributes via the API. Designed to run once daily from a policy
# rather than on every recon.
#
# ===========================================================================
# WHY THIS IS A POLICY AND NOT EXTENSION ATTRIBUTE SCRIPTS
#
# The earlier version of this project used three script-type extension
# attributes. Every recon ran all three, and one of them made two `profiles`
# calls capped at six seconds each. That is potentially 12+ seconds added to
# every inventory submission on every Mac, for data that changes once a day.
#
# Jamf's own documentation notes that extension attributes "may add time and
# network traffic to the inventory collection process."
#
# This script does the work once daily and writes the results straight into
# Jamf Pro. The extension attributes become Text Field type, which execute
# nothing at recon. Inventory cost drops to zero.
# ===========================================================================
#
# ---------------------------------------------------------------------------
# JAMF PRO SETUP
#
# 1. API ROLE
#    Settings > System > API roles and clients > API Roles > New
#    Name: DDM Update Reporter
#    Privileges, exactly these two and nothing more:
#      - Read Computers
#      - Update Computers
#
# 2. API CLIENT
#    Same page > API Clients > New
#    Name: DDM Update Reporter
#    API Roles: DDM Update Reporter
#    Access token lifetime: 300 seconds is plenty
#    Enable, then Generate client secret. Record both values.
#
# 3. TWO EXTENSION ATTRIBUTES
#    Settings > Computer management > Extension attributes > New, twice.
#      Name: DDM Update Summary     Data Type: String   Input Type: Text Field
#      Name: DDM Update Blocker     Data Type: String   Input Type: Text Field
#
#    Input Type MUST be Text Field. A script-type EA is recalculated at every
#    recon and would immediately overwrite whatever this script writes.
#
#    Note the ID of each. It is in the URL when you open the EA:
#      .../computerExtensionAttributes.html?id=42&o=r   ->  ID is 42
#
# 4. THIS SCRIPT
#    Settings > Computer management > Scripts > New. Paste this in.
#    Label the parameters:
#      Parameter 4: Summary EA ID
#      Parameter 5: Blocker EA ID
#      Parameter 6: API Client ID
#      Parameter 7: API Client Secret
#
# 5. DAILY POLICY
#    Computers > Policies > New
#    Name: DDM Update Report (Daily)
#    Trigger: Recurring Check-in
#    Execution Frequency: Once every day
#    Scope: all managed Macs on macOS 14 or later
#    Scripts: this one, with the four parameters filled in
#
#    Jamf enforces the once-daily limit. Flushing the policy log forces a
#    re-run on the next check-in, exactly as you would expect.
#
# 6. SELF SERVICE POLICY, optional but recommended
#    Duplicate the policy above. Change:
#      Trigger: none
#      Execution Frequency: Ongoing
#      Self Service: enabled, name it something like "Refresh Update Status"
#    Gives you and the user an on-demand refresh without touching logs.
# ---------------------------------------------------------------------------
#
# PARAMETERS
#   $4  Summary EA ID    numeric, required
#   $5  Blocker EA ID    numeric, required
#   $6  API Client ID    required
#   $7  API Client Secret required
#   $8  Jamf Pro URL     optional. Read from the jamf plist when omitted.
#
# The Jamf Pro URL is normally discovered from
# /Library/Preferences/com.jamfsoftware.jamf.plist, so it does not need to be
# passed and does not need editing between organizations.
#
# EXIT CODES
#   0  values written successfully
#   1  configuration problem, a missing parameter or unreadable EA ID
#   2  authentication failed
#   3  could not resolve this computer's record in Jamf Pro
#   4  the write itself failed
#
# API CALLS PER RUN
#   POST /api/v1/oauth/token                        get access token
#   GET  /api/v1/computers-inventory?filter=...     resolve own computer ID
#   PATCH /api/v2/computers-inventory-detail/{id}   write BOTH EAs, one call
#   POST /api/v1/auth/invalidate-token              discard the token
#
# Four HTTP requests, one of which is the write. Both EA values go in a single
# PATCH because the payload takes an array.
#
# Reads only local files for its data. No network access except Jamf Pro.
# ---------------------------------------------------------------------------

set -u

SU_PREFS="/Library/Preferences/com.apple.SoftwareUpdate"
JAMF_PLIST="/Library/Preferences/com.jamfsoftware.jamf.plist"
LOG="/var/log/ddm-update-report.log"
STALE_SCAN_DAYS=14

# ---------------------------------------------------------------------------
# Logging. Policy output is captured in the Jamf policy log, and a local file
# keeps history for troubleshooting a Mac that is not reporting.
# ---------------------------------------------------------------------------
log() {
    printf '%s  %s\n' "$(/bin/date '+%Y-%m-%d %H:%M:%S')" "$1" | /usr/bin/tee -a "${LOG}"
}

bail() {
    log "FAILED: $2"
    exit "$1"
}

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

# Strip anything that would break the result string or the JSON payload,
# then cap the length so one pathological log line cannot flood the record.
sanitize() {
    printf '%s' "$1" \
        | /usr/bin/tr -d '\n\r\t' \
        | /usr/bin/tr '<>&' '[]+' \
        | /usr/bin/cut -c1-200
}

# Escape for embedding in a JSON string. Backslash first, then quote.
json_escape() {
    printf '%s' "$1" | /usr/bin/sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

# True when version $1 is greater than or equal to version $2.
# Field-wise numeric sort, so 26.10 correctly outranks 26.9. Avoids sort -V,
# which is not dependable across macOS releases.
versionAtLeast() {
    [ "$1" = "$2" ] && return 0
    lowest=$(printf '%s\n%s\n' "$1" "$2" | /usr/bin/sort -t. -k1,1n -k2,2n -k3,3n -k4,4n | /usr/bin/head -n 1)
    [ "${lowest}" = "$2" ]
}

# defaults returns plist dates as "2026-06-22 14:39:12 +0000". Always UTC.
prefDateToEpoch() {
    clean=$(printf '%s' "$1" | /usr/bin/sed -E 's/^([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}).*/\1/')
    printf '%s' "${clean}" | /usr/bin/grep -qE '^[0-9]{4}-' || return 1
    /bin/date -j -u -f "%Y-%m-%d %H:%M:%S" "${clean}" "+%s" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------

eaSummaryId="${4:-}"
eaBlockerId="${5:-}"
apiClientId="${6:-}"
apiClientSecret="${7:-}"
jamfUrlParam="${8:-}"

case "${eaSummaryId}" in
    ''|*[!0-9]*) bail 1 "Parameter 4 must be the numeric Summary EA ID, got '${eaSummaryId}'" ;;
esac
case "${eaBlockerId}" in
    ''|*[!0-9]*) bail 1 "Parameter 5 must be the numeric Blocker EA ID, got '${eaBlockerId}'" ;;
esac
[ -n "${apiClientId}" ]     || bail 1 "Parameter 6 (API Client ID) is empty"
[ -n "${apiClientSecret}" ] || bail 1 "Parameter 7 (API Client Secret) is empty"

# Discover the Jamf Pro URL locally so it never needs hardcoding.
if [ -n "${jamfUrlParam}" ]; then
    jamfUrl="${jamfUrlParam}"
else
    jamfUrl=$(/usr/bin/defaults read "${JAMF_PLIST}" jss_url 2>/dev/null)
fi
jamfUrl="${jamfUrl%/}"
case "${jamfUrl}" in
    https://*) : ;;
    *) bail 1 "Could not determine a valid Jamf Pro URL (got '${jamfUrl}')" ;;
esac

log "=== DDM Update Report starting, target ${jamfUrl} ==="

# ===========================================================================
# PART 1: COLLECT
#
# Logic is carried over unchanged from the validated extension attributes.
# See README.md for why each decision is what it is, especially why
# compliance is a version comparison and not date arithmetic.
# ===========================================================================

now=$(/bin/date "+%s")

installed=$(/usr/bin/sw_vers -productVersion 2>/dev/null)
[ -n "${installed}" ] || bail 1 "Could not read sw_vers productVersion"

osMajor=$(printf '%s' "${installed}" | /usr/bin/cut -d. -f1)
case "${osMajor}" in
    ''|*[!0-9]*) bail 1 "Unreadable major version in '${installed}'" ;;
esac

# --- Uptime, which the scan check is meaningless without -------------------
# The pattern is anchored on purpose. sysctl returns:
#   { sec = 1757800000, usec = 123456 } Mon Sep 14 08:00:00 2026
# An unanchored '.*sec *= *' matches greedily into "usec" and captures the
# MICROSECONDS field, which reads as an epoch in 1970 and yields an uptime of
# roughly 56 years.
bootEpoch=$(/usr/sbin/sysctl -n kern.boottime 2>/dev/null \
    | /usr/bin/sed -E 's/^\{ *sec *= *([0-9]+).*/\1/')
case "${bootEpoch}" in
    ''|*[!0-9]*) bootEpoch="" ;;
esac
if [ -n "${bootEpoch}" ] && [ "${bootEpoch}" -lt 1600000000 ]; then
    bootEpoch=""
fi
uptimeDays=""
if [ -n "${bootEpoch}" ] && [ "${now}" -gt "${bootEpoch}" ]; then
    uptimeDays=$(( ( now - bootEpoch ) / 86400 ))
fi

# --- Every logged enforcement declaration ----------------------------------
# Live log first. Archives only if it holds nothing, since the highest version
# in the live log is always at least as new as anything archived.
pairs=$(/usr/bin/grep -o 'EnforcedInstallDate:[^|]*|VersionString:[^|]*' /var/log/install.log 2>/dev/null \
    | /usr/bin/sort -u)

if [ -z "${pairs}" ]; then
    for archive in $(/bin/ls -t /var/log/install.log.*.gz 2>/dev/null); do
        pairs=$(/usr/bin/gzcat "${archive}" 2>/dev/null \
            | /usr/bin/grep -o 'EnforcedInstallDate:[^|]*|VersionString:[^|]*' \
            | /usr/bin/sort -u)
        [ -n "${pairs}" ] && break
    done
fi

# --- Highest enforced target version ---------------------------------------
target=""
if [ -n "${pairs}" ]; then
    target=$(printf '%s\n' "${pairs}" \
        | /usr/bin/sed -E 's/.*\|VersionString:(.*)/\1/' \
        | /usr/bin/grep -E '^[0-9]+(\.[0-9]+)*$' \
        | /usr/bin/sort -t. -k1,1n -k2,2n -k3,3n -k4,4n \
        | /usr/bin/tail -n 1)
fi

# --- Latest deadline for that target ---------------------------------------
# Jamf Pro re-issues a plan when one fails or is rescheduled, so the same
# version routinely appears with several deadlines. Take the newest.
deadlineRaw=""
deadlineEpoch=""
if [ -n "${target}" ]; then
    deadlineRaw=$(printf '%s\n' "${pairs}" \
        | /usr/bin/grep -F "|VersionString:${target}" \
        | /usr/bin/sort \
        | /usr/bin/tail -n 1 \
        | /usr/bin/sed -E 's/EnforcedInstallDate:([^|]*)\|.*/\1/' \
        | /usr/bin/tr 'T' ' ')

    if printf '%s' "${deadlineRaw}" | /usr/bin/grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}'; then
        # UTC only when the value carries an explicit offset or trailing Z.
        # Observed format on macOS 26 is local time with no suffix.
        if printf '%s' "${deadlineRaw}" | /usr/bin/grep -qE '(\+0000|Z)$'; then
            deadlineEpoch=$(/bin/date -j -u -f "%Y-%m-%d %H:%M:%S" "${deadlineRaw}" "+%s" 2>/dev/null)
        else
            deadlineEpoch=$(/bin/date -j -f "%Y-%m-%d %H:%M:%S" "${deadlineRaw}" "+%s" 2>/dev/null)
        fi
    fi
    case "${deadlineEpoch}" in
        ''|*[!0-9]*) deadlineEpoch="" ;;
    esac
fi

# --- macOS past-due retry --------------------------------------------------
# EnforcedInstallDate never moves. Once it lapses macOS sets its own
# short-notice retry, logged as setPastDuePaddedEnforcementDate in the format
# "Sun Aug 30 16:16:59 2026", and pushes it forward until the install lands.
#
# Counts DISTINCT scheduled times, not log lines. macOS re-logs the same
# unchanged retry relentlessly: one validated Mac had 70 lines for a single
# scheduled attempt.
paddedLines=$(/usr/bin/grep 'setPastDuePaddedEnforcementDate is set' /var/log/install.log 2>/dev/null)
paddedEpoch=""
attemptCount=""

if [ -n "${paddedLines}" ]; then
    if [ -n "${deadlineRaw}" ] \
        && printf '%s' "${deadlineRaw}" | /usr/bin/grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}'; then
        attemptCount=$(printf '%s\n' "${paddedLines}" | /usr/bin/awk -v cutoff="${deadlineRaw}" '
            {
                ts = $1 " " $2
                sub(/[-+][0-9][0-9]([0-9][0-9])?$/, "", ts)
                if (ts < cutoff) next
                v = $0
                sub(/.*is set: */, "", v)
                print v
            }
        ' | /usr/bin/sort -u | /usr/bin/wc -l | /usr/bin/tr -d ' ')
    fi
    if [ -z "${attemptCount}" ] || [ "${attemptCount}" = "0" ]; then
        attemptCount="$(printf '%s\n' "${paddedLines}" \
            | /usr/bin/sed -E 's/.*is set: *//' \
            | /usr/bin/sort -u | /usr/bin/wc -l | /usr/bin/tr -d ' ') all-time"
    fi

    paddedRaw=$(printf '%s\n' "${paddedLines}" \
        | /usr/bin/tail -n 1 \
        | /usr/bin/sed -E 's/.*is set: *([A-Za-z]{3} [A-Za-z]{3} +[0-9]+ [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4}).*/\1/')
    if printf '%s' "${paddedRaw}" | /usr/bin/grep -qE '^[A-Za-z]{3} [A-Za-z]{3}'; then
        paddedEpoch=$(/bin/date -j -f "%a %b %d %H:%M:%S %Y" \
            "$(printf '%s' "${paddedRaw}" | /usr/bin/tr -s ' ')" "+%s" 2>/dev/null)
        case "${paddedEpoch}" in
            ''|*[!0-9]*) paddedEpoch="" ;;
        esac
    fi
fi

# --- Build the summary value -----------------------------------------------
# "as of" is deliberate. Text Field EAs persist forever, so a policy that
# stops running leaves confidently stale data on the record with nothing to
# indicate it. The stamp makes that visible at a glance.
asOf="as of $(/bin/date '+%Y-%m-%d %H:%M')"

if [ "${osMajor}" -lt 14 ]; then
    summary="Not Supported - macOS Too Old | Installed: ${installed} | ${asOf}"
elif [ -z "${pairs}" ]; then
    summary="No Enforcement Recorded | Installed: ${installed} | ${asOf}"
elif [ -z "${target}" ]; then
    summary="PARSE FAIL | raw: $(sanitize "${pairs}") | ${asOf}"
elif versionAtLeast "${installed}" "${target}"; then
    if [ -n "${deadlineEpoch}" ]; then
        summary="Compliant | Device target: ${target} by $(/bin/date -r "${deadlineEpoch}" '+%Y-%m-%d %H:%M') | Installed: ${installed} | ${asOf}"
    else
        summary="Compliant | Device target: ${target} | Installed: ${installed} | ${asOf}"
    fi
else
    if [ -n "${deadlineEpoch}" ]; then
        targetDisplay="Device target: ${target} by $(/bin/date -r "${deadlineEpoch}" '+%Y-%m-%d %H:%M')"
    else
        targetDisplay="Device target: ${target} by unknown date"
    fi

    retryDisplay=""
    [ -n "${paddedEpoch}" ] && retryDisplay=" | Retrying $(/bin/date -r "${paddedEpoch}" '+%Y-%m-%d %H:%M')"

    if [ -n "${deadlineEpoch}" ] && [ "${now}" -lt "${deadlineEpoch}" ]; then
        summary="Pending | ${targetDisplay} | Installed: ${installed} | ${asOf}"
    else
        summary="Overdue | ${targetDisplay}${retryDisplay} | Installed: ${installed} | ${asOf}"
    fi
fi

# --- Build the blocker value -----------------------------------------------
# Check order is a causal chain, most fundamental first. Hard blockers before
# in-progress states, because a hard blocker is the reason a forced install
# keeps failing.
#
# There is deliberately NO "target not offered" check. An earlier version
# tested whether the target appeared in RecommendedUpdates and fired on a Mac
# that was simultaneously telling its user the update was ready to install.
# RecommendedUpdates reflects the user-facing scan catalog, while DDM fetches
# its target through a separate path, so a DDM-enforced version need not
# appear there at all. Do not reintroduce it.

blocker=""

if [ "${osMajor}" -lt 14 ]; then
    blocker="Not Applicable - macOS Too Old"
elif [ -z "${target}" ]; then
    blocker="Not Applicable - No Enforcement Recorded"
elif versionAtLeast "${installed}" "${target}"; then
    blocker="Not Applicable - Compliant"
fi

if [ -z "${blocker}" ]; then
    # 1. Already staged, only a restart is missing. Completely different
    #    remediation from "nothing is happening", so it is checked first.
    lastAttempt=$(/usr/bin/defaults read "${SU_PREFS}" LastAttemptSystemVersion 2>/dev/null \
        | /usr/bin/sed -E 's/^([0-9][0-9.]*).*/\1/')
    if [ -n "${lastAttempt}" ] && versionAtLeast "${lastAttempt}" "${target}"; then
        blocker="Awaiting Restart | staged ${lastAttempt}, running ${installed}"
    fi
fi

if [ -z "${blocker}" ]; then
    # 2. Disk space. Thresholds are heuristics: roughly 15 GB for a minor
    #    update, 45 GB for a major upgrade.
    freeGB=$(/bin/df -g /System/Volumes/Data 2>/dev/null | /usr/bin/awk 'NR==2 {print $4}')
    [ -n "${freeGB}" ] || freeGB=$(/bin/df -g / 2>/dev/null | /usr/bin/awk 'NR==2 {print $4}')
    case "${freeGB}" in
        ''|*[!0-9]*) freeGB="" ;;
    esac
    if [ -n "${freeGB}" ]; then
        targetMajor=$(printf '%s' "${target}" | /usr/bin/cut -d. -f1)
        if [ "${targetMajor}" -gt "${osMajor}" ] 2>/dev/null; then
            needGB=45
        else
            needGB=15
        fi
        if [ "${freeGB}" -lt "${needGB}" ]; then
            blocker="Low Disk Space | ${freeGB} GB free, ~${needGB} GB needed"
        fi
    fi
fi

if [ -z "${blocker}" ] && [ "$(/usr/bin/uname -m 2>/dev/null)" = "arm64" ]; then
    # 3. Without an escrowed bootstrap token an Apple Silicon Mac cannot
    #    authorize an unattended OS install. Jamf calls this
    #    APPLE_SILICON_NO_ESCROW_KEY.
    #
    #    No timeout wrapper is needed here, unlike in the old extension
    #    attribute. A policy script can afford to wait; a recon cannot.
    if /usr/bin/profiles status -type bootstraptoken 2>&1 | /usr/bin/grep -qi 'escrowed to server: NO'; then
        blocker="Bootstrap Token Not Escrowed | Apple Silicon, blocks unattended install"
    fi
fi

if [ -z "${blocker}" ]; then
    # 4. A deferral profile can hide the target entirely, which looks like a
    #    device failure but is configuration.
    for domain in \
        "/Library/Managed Preferences/com.apple.applicationaccess" \
        "/Library/Managed Preferences/com.apple.SoftwareUpdate"
    do
        for key in \
            enforcedSoftwareUpdateDelay \
            enforcedSoftwareUpdateMajorOSDeferredInstallDelay \
            enforcedSoftwareUpdateMinorOSDeferredInstallDelay
        do
            val=$(/usr/bin/defaults read "${domain}" "${key}" 2>/dev/null)
            case "${val}" in
                ''|*[!0-9]*) continue ;;
            esac
            if [ "${val}" -gt 0 ]; then
                blocker="Update Deferral Active | ${key} = ${val} days"
                break 2
            fi
        done
    done
fi

if [ -z "${blocker}" ] && [ -n "${paddedEpoch}" ]; then
    # 5. No hard blocker and macOS is still actively trying. Good news and
    #    bad news at once: enforcement is alive, and it is not succeeding.
    upNote=""
    [ -n "${uptimeDays}" ] && upNote=", up ${uptimeDays}d"

    if [ "${paddedEpoch}" -gt "${now}" ]; then
        mins=$(( ( paddedEpoch - now ) / 60 ))
        if [ "${mins}" -lt 60 ]; then
            whenNote=", forcing in ${mins}m"
        else
            whenNote=", forcing in $(( mins / 60 ))h"
        fi
    else
        mins=$(( ( now - paddedEpoch ) / 60 ))
        if [ "${mins}" -lt 60 ]; then
            whenNote=", window elapsed ${mins}m ago"
        else
            whenNote=", window elapsed $(( mins / 60 ))h ago"
        fi
    fi

    if [ "${attemptCount}" = "1" ]; then
        countNote="1 scheduled attempt"
    else
        countNote="${attemptCount} scheduled attempts"
    fi
    blocker="Past Due - Forced Install Pending | ${countNote}${upNote}${whenNote}, set for $(/bin/date -r "${paddedEpoch}" '+%Y-%m-%d %H:%M')"
fi

if [ -z "${blocker}" ]; then
    # 6. Scan health, advisory and uptime-gated.
    #
    #    The gate is the entire value of this check. A Mac powered off for
    #    three months always shows a three-month-old scan, which is
    #    arithmetic, not a fault. Ungated, this flagged every laptop
    #    returning from leave. The real fault condition is narrow: powered on
    #    at least a day and STILL no scan since boot.
    newestScan=0
    for key in LastSuccessfulDate LastFullSuccessfulDate \
               LastSuccessfulBackgroundMSUScanDate LastBackgroundSuccessfulDate
    do
        raw=$(/usr/bin/defaults read "${SU_PREFS}" "${key}" 2>/dev/null)
        [ -n "${raw}" ] || continue
        e=$(prefDateToEpoch "${raw}") || continue
        case "${e}" in
            ''|*[!0-9]*) continue ;;
        esac
        [ "${e}" -gt "${newestScan}" ] && newestScan="${e}"
    done

    if [ -n "${uptimeDays}" ] && [ "${uptimeDays}" -ge 1 ]; then
        if [ "${newestScan}" -eq 0 ]; then
            blocker="Update Scan Stale | up ${uptimeDays}d, no successful scan on record"
        elif [ "${newestScan}" -lt "${bootEpoch}" ]; then
            blocker="Update Scan Stale | up ${uptimeDays}d with no scan since boot, last $(( ( now - newestScan ) / 86400 ))d ago"
        fi
    elif [ -z "${uptimeDays}" ] && [ "${newestScan}" -gt 0 ]; then
        scanAgeDays=$(( ( now - newestScan ) / 86400 ))
        if [ "${scanAgeDays}" -ge "${STALE_SCAN_DAYS}" ]; then
            blocker="Update Scan Stale | last scan $(/bin/date -r "${newestScan}" '+%Y-%m-%d'), ${scanAgeDays}d ago, uptime unknown"
        fi
    fi
fi

if [ -z "${blocker}" ]; then
    if /usr/bin/profiles status -type enrollment 2>&1 | /usr/bin/grep -qi 'MDM enrollment: No'; then
        blocker="Not Supervised | DDM enforcement requires supervision"
    fi
fi

if [ -z "${blocker}" ]; then
    # Nothing local explains it. A real and useful answer: the device looks
    # healthy, so look up the plan state in Jamf Pro for the real reason.
    if [ -n "${freeGB:-}" ]; then
        blocker="No Local Blocker Found | ${freeGB} GB free, check Jamf Pro plan state"
    else
        blocker="No Local Blocker Found | check Jamf Pro plan state"
    fi
fi

summary=$(sanitize "${summary}")
blocker=$(sanitize "${blocker}")

log "Summary: ${summary}"
log "Blocker: ${blocker}"

# ===========================================================================
# PART 2: WRITE TO JAMF PRO
# ===========================================================================

# --- Access token ----------------------------------------------------------
# Field extraction uses grep -o rather than a greedy sed capture. A pattern
# like '.*"access_token" *: *"\(...\)"' works until the response shape
# changes; grep -o isolates the field first and cannot overrun into a
# neighbouring key.
tokenResponse=$(/usr/bin/curl -sS -m 30 \
    -X POST "${jamfUrl}/api/v1/oauth/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=client_credentials" \
    --data-urlencode "client_id=${apiClientId}" \
    --data-urlencode "client_secret=${apiClientSecret}" 2>&1)

token=$(printf '%s' "${tokenResponse}" \
    | /usr/bin/grep -o '"access_token"[[:space:]]*:[[:space:]]*"[^"]*"' \
    | /usr/bin/head -n 1 \
    | /usr/bin/sed -e 's/.*:[[:space:]]*"//' -e 's/"$//')

if [ -z "${token}" ]; then
    # Never log the response body. It is an auth exchange.
    bail 2 "Could not obtain an access token. Check the API client ID, secret, and that the client is enabled."
fi
log "Access token obtained"

cleanup() {
    [ -n "${token:-}" ] || return 0
    /usr/bin/curl -sS -m 15 -o /dev/null \
        -X POST "${jamfUrl}/api/v1/auth/invalidate-token" \
        -H "Authorization: Bearer ${token}" 2>/dev/null
}
trap cleanup EXIT

# --- Resolve this computer's record ----------------------------------------
serial=$(/usr/sbin/ioreg -c IOPlatformExpertDevice -d 2 2>/dev/null \
    | /usr/bin/awk -F'"' '/IOPlatformSerialNumber/ {print $4; exit}')
[ -n "${serial}" ] || bail 3 "Could not read this Mac's serial number"

idResponse=$(/usr/bin/curl -sS -m 30 -G \
    "${jamfUrl}/api/v1/computers-inventory" \
    -H "Authorization: Bearer ${token}" \
    -H "Accept: application/json" \
    --data-urlencode "filter=hardware.serialNumber==\"${serial}\"" \
    --data-urlencode "section=GENERAL" \
    --data-urlencode "page-size=1" 2>&1)

computerId=$(printf '%s' "${idResponse}" \
    | /usr/bin/grep -o '"id"[[:space:]]*:[[:space:]]*"\{0,1\}[0-9]\{1,\}' \
    | /usr/bin/head -n 1 \
    | /usr/bin/grep -o '[0-9]\{1,\}$')

case "${computerId}" in
    ''|*[!0-9]*)
        bail 3 "Could not resolve a Jamf Pro computer record for serial ${serial}. Confirm the API role has Read Computers."
        ;;
esac
log "Resolved computer ID ${computerId} for serial ${serial}"

# --- Write both extension attributes in one call ---------------------------
# Both values go in a single PATCH because extensionAttributes takes an array.
payload=$(/bin/cat <<JSON
{"extensionAttributes":[{"definitionId":"${eaSummaryId}","values":["$(json_escape "${summary}")"]},{"definitionId":"${eaBlockerId}","values":["$(json_escape "${blocker}")"]}]}
JSON
)

httpCode=$(/usr/bin/curl -sS -m 30 -o /tmp/.ddmwrite.$$ -w '%{http_code}' \
    -X PATCH "${jamfUrl}/api/v2/computers-inventory-detail/${computerId}" \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    -d "${payload}" 2>&1)

writeBody=$(/bin/cat /tmp/.ddmwrite.$$ 2>/dev/null)
/bin/rm -f /tmp/.ddmwrite.$$ 2>/dev/null

if [ "${httpCode}" != "204" ] && [ "${httpCode}" != "200" ]; then
    log "HTTP ${httpCode} from PATCH"
    log "Response: $(printf '%s' "${writeBody}" | /usr/bin/cut -c1-400)"
    log "If this is a 400, confirm both EAs are Input Type 'Text Field'."
    log "A script-type EA cannot be written to, and the IDs in parameters 4"
    log "and 5 must match the EA URLs in Jamf Pro."
    bail 4 "Extension attribute write failed with HTTP ${httpCode}"
fi

log "Wrote EA ${eaSummaryId} and EA ${eaBlockerId} successfully (HTTP ${httpCode})"
log "=== DDM Update Report complete ==="
exit 0
