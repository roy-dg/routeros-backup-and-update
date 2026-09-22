#!rsc by RouterOS
# =============================================================================
# RouterOS 7.x - Delayed RouterOS Update Installer
#   + pre-update backup to Cloudflare R2 (via a presigned-URL Worker)
#   + post-update RouterBOARD firmware upgrade
#   + secrets kept out of this script's text via a /ppp secret-backed vault
#
# Checks for a RouterOS update on the configured release channel and installs
# it ONLY once that release has been publicly available for at least
# $MinDaysSinceRelease days. Immediately before installing, it takes a backup
# and uploads it to Cloudflare R2 using a short-lived presigned PUT URL that
# a small Cloudflare Worker hands out. After a RouterOS install (which
# reboots the router), a self-provisioned startup task upgrades the
# RouterBOARD firmware if a new one shipped with the package, then reboots
# once more to apply it.
#
# COMPANION FILES: worker.js + wrangler.toml (deploy these to Cloudflare
# first - see the setup notes below and in worker.js).
#
# SECRETS
#   Nothing sensitive is hardcoded here. This script gets secrets from the
#   shared $SECRET vault defined in the companion script secret-vault.rsc -
#   deploy and schedule that FIRST (see its header for setup). This router
#   also needs its OWN credential registered with the Worker before it can
#   back anything up - each router now has its own secret, not a shared one
#   (see worker.js for why, and how to revoke just one router if needed).
#   From another machine (not this router):
#     curl -X POST https://<worker-url>/admin/routers \
#       -H "Authorization: Bearer <ADMIN_SECRET>" -H "Content-Type: application/json" \
#       -d "{\"device_id\":\"<this router's identity>\",\"label\":\"...\"}"
#   That returns a secret once. Store it on THIS router with:
#     $SECRET "set" "R2_BACKUP_SECRET" password="<the secret from the curl response>"
#     $SECRET "set" "ROUTER_BACKUP_PASSWORD" password="<a strong password>"   ;# optional, only if $BackupPasswordName below is non-empty
#   The device_id you register MUST match this router's identity ($Identity,
#   used below) - that's how the Worker knows which row in D1 to check.
#
# IMPORTANT - READ BEFORE USING
#   * RouterOS itself does not expose a release date via check-for-updates,
#     so release age comes from MikroTik's own CHANGELOG file for the
#     candidate version. If it can't be fetched/parsed, the script fails
#     safe and skips installing.
#   * RouterOS cannot stream an arbitrary-size local file into an HTTPS PUT
#     body - the file has to be read into a script variable first, and that
#     read is undocumented/capped at roughly 60-64KB in practice (MikroTik
#     has stated there's no supported way to read a larger file this way).
#     $MaxBackupBytes guards against this: if the backup is bigger, the
#     script logs an error and skips the update run rather than sending a
#     truncated backup. If your backups routinely exceed this, this
#     presigned-URL approach is the wrong transport for you - a native
#     (S)FTP upload (RouterOS streams straight from disk for that, no size
#     cap) to something like an `rclone serve sftp` bridge in front of R2
#     would be the robust alternative.
#   * A presigned URL can't be "revoked" early once issued - so the Worker
#     keeps it valid only for $PresignTtlHint seconds (must match the
#     Worker's own PRESIGN_TTL_SECONDS). Separately, each router now has its
#     own credential in the Worker's D1 database, so if THIS router is
#     compromised, disabling just its row (POST /admin/routers/<id>/disable)
#     stops it getting any NEW presigned URLs, without touching other
#     routers or rotating anything shared.
#   * /system/package/update/install reboots the router automatically once
#     the download finishes - there's no confirmation step here by design.
#   * For real certificate validation on the fetch calls below, run this
#     once first: /certificate/settings/set builtin-trust-store=fetch
#   * The saved script's Policy (System > Scripts) needs at least:
#     read, write, test, ftp, sensitive, reboot.
#     ("sensitive" is for reading secrets back out via $SECRET get - policy
#     is enforced per the script that's actually running, not the script
#     that originally defined the function.)
#
# USAGE
#   Paste into a new script (System > Scripts) and run it on a schedule, e.g.:
#     /system scheduler add name=routeros-delayed-update interval=1d \
#         on-event="/system script run routeros-delayed-update"
# =============================================================================

# --------------------------- CONFIGURATION ----------------------------------
:local Channel                      "stable";  # long-term | stable | testing | development
:local MinDaysSinceRelease          30;        # minimum age, in days, before a release gets installed
:local LogPrefix                    "DelayedUpdate:";
:local ChangelogBaseUrl             "https://download.mikrotik.com/routeros/";
:local StatusPollAttempts           15;        # max number of 1s polls while waiting on check-for-updates

# -- Cloudflare R2 backup (presigned URL via Worker) --
:local R2PresignWorkerUrl           "https://your-worker.your-subdomain.workers.dev/presign";
:local R2RouterSecretName           "R2_BACKUP_SECRET";  # THIS router's own credential, looked up via $SECRET - see setup notes above
:local PresignTtlHint                120;      # informational only - actual TTL is enforced by the Worker
:local BackupPasswordName           "";        # leave "" for an unencrypted backup, else a $SECRET name
:local MaxBackupBytes                60000;    # safety ceiling - see notes above
:local RequireBackupBeforeUpdate     true;     # if backup/upload fails, skip installing this run
:local DeleteLocalBackupAfterUpload  true;

# -- RouterBOARD firmware --
:local AutoUpgradeRouterboard       true;
:local RouterboardSchedulerName     "auto-upgrade-routerboard-firmware";
# ------------------------------------------------------------------------------

:local Identity [/system/identity/get name]

# ---- wait for the shared secret vault (see secret-vault.rsc) ----------------
:global SecretVaultReady
:global SECRET
:local VaultWait 0
:while ($SecretVaultReady != true && $VaultWait < 20) do={
    :delay 500ms
    :set VaultWait ($VaultWait + 1)
}
:if ($SecretVaultReady != true) do={
    :log error ($LogPrefix . " secret-vault isn't ready - is secret-vault.rsc deployed and scheduled at start-time=startup?")
    :error ($LogPrefix . " aborting: secret-vault not ready.")
}

# ---- resolve secrets up front; abort cleanly if the vault isn't seeded yet --
:local R2RouterSecret ""
:local BackupPassword ""
:local SecretsOk true

:do {
    :set R2RouterSecret [$SECRET "get" $R2RouterSecretName]
    :if ($BackupPasswordName != "") do={ :set BackupPassword [$SECRET "get" $BackupPasswordName] }
} on-error={
    :set SecretsOk false
    :log error ($LogPrefix . " missing secret(s) in the \$SECRET vault - see the setup notes at the top of this script.")
}
:if ($SecretsOk = false) do={ :error ($LogPrefix . " aborting: secrets not configured yet.") }

# ---- helper: days since 1970-01-01 for a given civil y/m/d ------------------
# Well-known "days_from_civil" algorithm (Howard Hinnant, public domain) -
# avoids needing a leap-year lookup table. Verified against 1970-01-01 -> 0.
:local DaysFromCivil do={
    :local y $year
    :local m $month
    :local d $day
    :if ($m <= 2) do={ :set y ($y - 1) }
    :local mm 0
    :if ($m > 2) do={ :set mm ($m - 3) } else={ :set mm ($m + 9) }
    :local era ($y / 400)
    :local yoe ($y - ($era * 400))
    :local doy ((153 * $mm + 2) / 5 + $d - 1)
    :local doe (($yoe * 365) + ($yoe / 4) - ($yoe / 100) + $doy)
    :return (($era * 146097) + $doe - 719468)
}

# ---- helper: 3-letter month abbreviation (any case) -> 1-12 -----------------
:local MonthAbbrevToNum do={
    :local names {"jan";"feb";"mar";"apr";"may";"jun";"jul";"aug";"sep";"oct";"nov";"dec"}
    :return ([:find $names [:tolower $name]] + 1)
}

# ---- helper: pull a top-level string field out of a small flat JSON object --
# Only good for our own Worker's simple {"key":"value",...} responses.
:local JsonStringField do={
    :local marker ("\"" . $field . "\":\"")
    :local start [:find $json $marker]
    :if ([:typeof $start] = "nil") do={ :return "" }
    :set start ($start + [:len $marker])
    :local finish [:find $json "\"" $start]
    :if ([:typeof $finish] = "nil") do={ :return "" }
    :return [:pick $json $start $finish]
}

# ---- make sure the post-update RouterBOARD firmware task exists -------------
:if ($AutoUpgradeRouterboard = true) do={
    :if ([:len [/system/scheduler/find name=$RouterboardSchedulerName]] = 0) do={
        :local RbScript (
            ":if ([/system/routerboard/get current-firmware] != [/system/routerboard/get upgrade-firmware]) do={" .
            " :log info \"" . $RouterboardSchedulerName . ": new RouterBOARD firmware available, upgrading and rebooting.\";" .
            " /system/routerboard/upgrade; :delay 3s; /system/reboot" .
            "} else={ :log info \"" . $RouterboardSchedulerName . ": RouterBOARD firmware already up to date.\" }"
        )
        /system/scheduler/add name=$RouterboardSchedulerName start-time=startup on-event=$RbScript
        :log info ($LogPrefix . " created startup task \"" . $RouterboardSchedulerName . "\" for RouterBOARD firmware upgrades.")
    }
} else={
    :if ([:len [/system/scheduler/find name=$RouterboardSchedulerName]] > 0) do={
        /system/scheduler/remove [/system/scheduler/find name=$RouterboardSchedulerName]
        :log info ($LogPrefix . " removed startup task \"" . $RouterboardSchedulerName . "\" (AutoUpgradeRouterboard=no).")
    }
}

# ---- figure out today's date as an epoch day number --------------------------
:local TodayRaw [/system/clock/get date]
:local TodayYear 0
:local TodayMonth 0
:local TodayDay 0

:if ($TodayRaw ~ "....-..-..") do={
    # RouterOS >= 7.10 default clock format: yyyy-mm-dd
    :set TodayYear  [:tonum [:pick $TodayRaw 0 4]]
    :set TodayMonth [:tonum [:pick $TodayRaw 5 7]]
    :set TodayDay   [:tonum [:pick $TodayRaw 8 10]]
} else={
    # RouterOS < 7.10, or clock format manually reverted: mmm/dd/yyyy
    :set TodayMonth [$MonthAbbrevToNum name=[:pick $TodayRaw 0 3]]
    :set TodayDay   [:tonum [:pick $TodayRaw 4 6]]
    :set TodayYear  [:tonum [:pick $TodayRaw 7 11]]
}
:local TodayEpochDay [$DaysFromCivil year=$TodayYear month=$TodayMonth day=$TodayDay]

# ---- check for updates on the configured channel -----------------------------
/system/package/update/set channel=$Channel
/system/package/update/check-for-updates

:local UpdStatus ""
:local PollCount 0
:while ($PollCount < $StatusPollAttempts) do={
    :set UpdStatus [/system/package/update/get status]
    :if (($UpdStatus != "") && ($UpdStatus != "Checking for updates...")) do={
        :set PollCount $StatusPollAttempts
    } else={
        :delay 1s
        :set PollCount ($PollCount + 1)
    }
}
:log info ($LogPrefix . " channel=" . $Channel . " status=\"" . $UpdStatus . "\"")

:if ($UpdStatus = "New version is available") do={
    :local LatestVersion    [/system/package/update/get latest-version]
    :local InstalledVersion [/system/package/update/get installed-version]
    :log info ($LogPrefix . " update available: " . $InstalledVersion . " -> " . $LatestVersion)

    :local ChangelogOk true
    :local DaysSinceRelease -1

    :do {
        :local ChangelogUrl ($ChangelogBaseUrl . $LatestVersion . "/CHANGELOG")
        :local ChangelogText ([/tool/fetch url=$ChangelogUrl check-certificate=yes output=user as-value] -> "data")

        # First line looks like: What's new in 7.18.1 (2025-Feb-28 13:31):
        :local OpenParen  [:find $ChangelogText "("]
        :local CloseParen [:find $ChangelogText ")"]
        :local RelStr     [:pick $ChangelogText ($OpenParen + 1) $CloseParen]

        :local RelYear  [:tonum [:pick $RelStr 0 4]]
        :local RelMonth [$MonthAbbrevToNum name=[:pick $RelStr 5 8]]
        :local RelDay   [:tonum [:pick $RelStr 9 11]]

        :local ReleaseEpochDay [$DaysFromCivil year=$RelYear month=$RelMonth day=$RelDay]
        :set DaysSinceRelease ($TodayEpochDay - $ReleaseEpochDay)
    } on-error={
        :set ChangelogOk false
        :log warning ($LogPrefix . " could not read/parse the changelog for " . $LatestVersion . " -- skipping install this run (fail-safe).")
    }

    :if ($ChangelogOk = true) do={
        :log info ($LogPrefix . " " . $LatestVersion . " was released " . $DaysSinceRelease . " day(s) ago.")

        :if ($DaysSinceRelease >= $MinDaysSinceRelease) do={

            # ---- pre-update backup: create it, then upload to R2 via a presigned URL ----
            :local BackupOk false
            :local BackupBaseName ($Identity . "-pre-update-" . $LatestVersion)
            :local BackupFileName ($BackupBaseName . ".backup")

            :do {
                :if ($BackupPassword != "") do={
                    /system/backup/save name=$BackupBaseName password=$BackupPassword
                } else={
                    /system/backup/save name=$BackupBaseName dont-encrypt=yes
                }

                :local BackupSize [/file/get [/file/find name=$BackupFileName] size]
                :log info ($LogPrefix . " backup file " . $BackupFileName . " is " . $BackupSize . " bytes")
                :if ($BackupSize > $MaxBackupBytes) do={
                    :error ("backup is " . $BackupSize . " bytes, over the " . $MaxBackupBytes . "-byte ceiling for a variable-based PUT")
                }

                :local BackupData [/file/get [/file/find name=$BackupFileName] contents]

                # ask the Worker for a one-shot presigned PUT URL - identity and
                # secret both travel in one header; the Worker verifies them as
                # a pair against D1 and derives the R2 key from the verified
                # device_id, not from anything this script asserts
                :local PresignResp ([/tool/fetch \
                    url=$R2PresignWorkerUrl \
                    http-method=get \
                    http-header-field=("X-Router-Auth: " . $Identity . ":" . $R2RouterSecret) \
                    check-certificate=yes output=user as-value] -> "data")
                :local PresignUrl [$JsonStringField json=$PresignResp field="url"]
                :if ($PresignUrl = "") do={ :error ("worker did not return a presigned url: " . $PresignResp) }

                # upload straight to R2 with the one-shot URL, then confirm it was accepted
                :local PutResult [/tool/fetch url=$PresignUrl http-method=put http-data=$BackupData \
                    check-certificate=yes output=user-with-headers as-value]
                :local PutHeaders ($PutResult -> "data")
                :if (!($PutHeaders ~ "200")) do={ :error ("R2 did not return HTTP 200: " . $PutHeaders) }

                :set BackupOk true
                :log info ($LogPrefix . " backup uploaded to R2 successfully.")

                :if ($DeleteLocalBackupAfterUpload = true) do={ /file/remove [/file/find name=$BackupFileName] }
            } on-error={
                :log error ($LogPrefix . " backup/upload to R2 failed - see the log line above for detail.")
            }

            :local ProceedWithInstall true
            :if ($BackupOk = false) do={
                :if ($RequireBackupBeforeUpdate = true) do={
                    :log error ($LogPrefix . " skipping install this run: no verified backup and RequireBackupBeforeUpdate=yes.")
                    :set ProceedWithInstall false
                } else={
                    :log warning ($LogPrefix . " proceeding without a verified backup (RequireBackupBeforeUpdate=no).")
                }
            }

            :if ($ProceedWithInstall = true) do={
                :log info ($LogPrefix . " release age meets the " . $MinDaysSinceRelease . "-day threshold -- installing now. The router will reboot automatically once the download finishes.")
                /system/package/update/install
            }

        } else={
            :log info ($LogPrefix . " release is too new (needs " . $MinDaysSinceRelease . " days) -- not installing yet.")
        }
    }
} else={
    :log info ($LogPrefix . " nothing to do (" . $UpdStatus . ")")
}
