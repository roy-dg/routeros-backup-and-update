#!rsc by RouterOS
# =============================================================================
# RouterOS 7.x - Delayed RouterOS Update Installer
#   + backup to Cloudflare R2 (via a presigned-URL Worker) - both a binary
#     .backup and a plain-text .rsc export, on a schedule you control
#   + post-update RouterBOARD firmware upgrade
#   + secrets kept out of this script's text via a /ppp secret-backed vault
#
# Checks for a RouterOS update on the configured release channel and installs
# it ONLY once that release has been publicly available for at least
# $MinDaysSinceRelease days. By default a backup only happens immediately
# before installing; set $AlwaysBackup=true to back up (and upload) on every
# run instead, so there's always a recent backup even on days nothing gets
# installed. After a RouterOS install (which reboots the router), a
# self-provisioned startup task upgrades the RouterBOARD firmware if a new
# one shipped with the package, then reboots once more to apply it.
#
# COMPANION FILES: worker.js + wrangler.toml (deploy to Cloudflare first -
# see worker.js). worker.js MUST be the version that understands the ?ext=
# query param (backup|rsc) - an older deployed Worker will still accept the
# .rsc upload, it'll just mislabel it with a .backup-extension key in R2.
#
# SECRETS
#   Nothing sensitive is hardcoded here. This script gets secrets from the
#   shared $SECRET vault defined in the companion script secret-vault.rsc -
#   deploy and schedule that FIRST (see its header for setup). This router
#   also needs its OWN credential registered with the Worker before it can
#   back anything up - each router has its own secret, not a shared one.
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
#     body - each file has to be read into a script variable first, and on
#     at least some RouterOS versions/devices that read silently returns 0
#     bytes above some undocumented size, with no error - see the empirical
#     test in the chat history that found this on this exact router. This
#     script does NOT guess a safe byte ceiling; instead it checks the
#     actual bytes read against the file's real size right after the read,
#     and refuses to upload if they don't match (rather than silently
#     sending a short/empty file that would report "success"). If you hit
#     this in practice, the real fix is a different transport for that file
#     - RouterOS streams straight from disk for an (S)FTP upload, with no
#     variable involved and no size ceiling at all (e.g. an `rclone serve
#     sftp` bridge in front of R2), unlike this presigned-URL-over-HTTP
#     approach.
#   * The .rsc export deliberately does NOT use show-sensitive by default,
#     so it will NOT contain the plaintext $SECRET-vault passwords - that's
#     the same masking /ppp/secret gives you elsewhere, and a plaintext
#     export would otherwise undo it. Set $ExportShowSensitive=true only if
#     you understand and accept that tradeoff. The binary .backup always
#     contains full recoverable config regardless (encrypt it with
#     $BackupPasswordName if that concerns you).
#   * A presigned URL can't be "revoked" early once issued - so the Worker
#     keeps it valid only for $PresignTtlHint seconds (must match the
#     Worker's own PRESIGN_TTL_SECONDS). Separately, each router has its own
#     credential in the Worker's D1 database, so if THIS router is
#     compromised, disabling just its row (POST /admin/routers/<id>/disable)
#     stops it getting any NEW presigned URLs, without touching other
#     routers or rotating anything shared.
#   * /system/package/update/install reboots the router automatically once
#     the download finishes - there's no confirmation step here by design.
#   * For real certificate validation on the fetch calls below, run this
#     once first: /certificate/settings/set builtin-trust-store=fetch
#   * The saved script's Policy (System > Scripts) needs at least:
#     read, write, test, ftp, sensitive, reboot.
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

# -- Backups --
:local AlwaysBackup                  true;    # false (default) = back up only right before installing
                                                # true = back up (and upload) on every run, update or not
:local ExportShowSensitive           false;    # see IMPORTANT notes above before flipping this on

# -- Cloudflare R2 backup (presigned URL via Worker) --
:local R2PresignWorkerUrl           "[URL HERE]";
:local R2RouterSecretName           "R2_BACKUP_SECRET";  # THIS router's own credential, looked up via $SECRET - see setup notes above
:local PresignTtlHint                120;      # informational only - actual TTL is enforced by the Worker
:local BackupPasswordName           "";        # leave "" for an unencrypted .backup, else a $SECRET name
:local RequireBackupBeforeUpdate     true;     # if the backup/upload fails, skip installing this run
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

# ---- helper: create + upload BOTH a .backup and a .rsc export to R2 ---------
# Self-contained on purpose (only reads its own named parameters and its own
# internal locals) so it's safe to call from more than one place in this
# script - RouterOS closures don't automatically see the calling script's
# other local variables, only globals and whatever is passed in explicitly.
# Returns true only if BOTH files uploaded successfully.
:local DoBackupAndUpload do={
    # nested helper, only ever called from within this same function body
    :local ExtractJsonField do={
        :local marker ("\"" . $field . "\":\"")
        :local start [:find $json $marker]
        :if ([:typeof $start] = "nil") do={ :return "" }
        :set start ($start + [:len $marker])
        :local finish [:find $json "\"" $start]
        :if ([:typeof $finish] = "nil") do={ :return "" }
        :return [:pick $json $start $finish]
    }

    :local today [/system/clock/get date]
    :local baseName ($identity . "-" . $today)
    :local backupFile ($baseName . ".backup")
    :local rscFile ($baseName . ".rsc")

    :local backupOk false
    :local rscOk false

    # -------- binary backup --------
    :do {
        :if ($backupPassword != "") do={
            /system/backup/save name=$baseName password=$backupPassword
        } else={
            /system/backup/save name=$baseName dont-encrypt=yes
        }

        :local sz [/file/get [/file/find name=$backupFile] size]
        :log info ($logPrefix . " " . $backupFile . " is " . $sz . " bytes")

        :local data [/file/get [/file/find name=$backupFile] contents]
        :if ([:len $data] != $sz) do={ :error ("read " . [:len $data] . " bytes but " . $backupFile . " is " . $sz . " bytes - refusing to upload a short/empty read") }

        :local presignResp ([/tool/fetch url=($workerUrl . "?ext=backup") http-method=get \
            http-header-field=("X-Router-Auth: " . $identity . ":" . $routerSecret) \
            check-certificate=yes output=user as-value] -> "data")
        :local presignUrl [$ExtractJsonField json=$presignResp field="url"]
        :if ($presignUrl = "") do={ :error ("worker did not return a presigned url for .backup: " . $presignResp) }

        :local putResult [/tool/fetch url=$presignUrl http-method=put http-data=$data check-certificate=yes output=user as-value]
        :local putStatus ($putResult -> "status")
        :local putBody ($putResult -> "data")
        :if ($putStatus != "finished") do={ :error (".backup upload did not complete, status=" . $putStatus) }
        :if ([:len $putBody] > 0) do={ :error (".backup upload rejected by R2: " . $putBody) }

        :set backupOk true
        :log info ($logPrefix . " " . $backupFile . " uploaded to R2.")

        :if ($deleteAfterUpload = true) do={ /file/remove [/file/find name=$backupFile] }
    } on-error={
        :log error ($logPrefix . " .backup create/upload failed - see the log line above for detail.")
    }

    # -------- plain-text config export --------
    :do {
        :if ($showSensitive = true) do={
            /export terse show-sensitive file=$baseName
        } else={
            /export terse file=$baseName
        }

        :local sz [/file/get [/file/find name=$rscFile] size]
        :log info ($logPrefix . " " . $rscFile . " is " . $sz . " bytes")

        :local data [/file/get [/file/find name=$rscFile] contents]
        :if ([:len $data] != $sz) do={ :error ("read " . [:len $data] . " bytes but " . $rscFile . " is " . $sz . " bytes - refusing to upload a short/empty read") }

        :local presignResp ([/tool/fetch url=($workerUrl . "?ext=rsc") http-method=get \
            http-header-field=("X-Router-Auth: " . $identity . ":" . $routerSecret) \
            check-certificate=yes output=user as-value] -> "data")
        :local presignUrl [$ExtractJsonField json=$presignResp field="url"]
        :if ($presignUrl = "") do={ :error ("worker did not return a presigned url for .rsc: " . $presignResp) }

        :local putResult [/tool/fetch url=$presignUrl http-method=put http-data=$data check-certificate=yes output=user as-value]
        :local putStatus ($putResult -> "status")
        :local putBody ($putResult -> "data")
        :if ($putStatus != "finished") do={ :error (".rsc upload did not complete, status=" . $putStatus) }
        :if ([:len $putBody] > 0) do={ :error (".rsc upload rejected by R2: " . $putBody) }

        :set rscOk true
        :log info ($logPrefix . " " . $rscFile . " uploaded to R2.")

        :if ($deleteAfterUpload = true) do={ /file/remove [/file/find name=$rscFile] }
    } on-error={
        :log error ($logPrefix . " .rsc export/upload failed - see the log line above for detail.")
    }

    :return ($backupOk && $rscOk)
}

# ---- make sure the post-update RouterBOARD firmware task exists -------------
:if ($AutoUpgradeRouterboard = true) do={
    :if ([:len [/system/scheduler/find name=$RouterboardSchedulerName]] = 0) do={
        :local RbScript (":if ([/system/routerboard/get current-firmware] != [/system/routerboard/get upgrade-firmware]) do={" . " :log info \"" . $RouterboardSchedulerName . ": new RouterBOARD firmware available, upgrading and rebooting.\";" . " /system/routerboard/upgrade; :delay 3s; /system/reboot" . "} else={ :log info \"" . $RouterboardSchedulerName . ": RouterBOARD firmware already up to date.\" }")
        /system/scheduler/add name=$RouterboardSchedulerName start-time=startup on-event=$RbScript
        :log info ($LogPrefix . " created startup task \"" . $RouterboardSchedulerName . "\" for RouterBOARD firmware upgrades.")
    }
} else={
    :if ([:len [/system/scheduler/find name=$RouterboardSchedulerName]] > 0) do={
        /system/scheduler/remove [/system/scheduler/find name=$RouterboardSchedulerName]
        :log info ($LogPrefix . " removed startup task \"" . $RouterboardSchedulerName . "\" (AutoUpgradeRouterboard=no).")
    }
}

# ---- routine backup, if configured to happen every run -----------------------
:local BackupOk false
:local BackupAttempted false
:if ($AlwaysBackup = true) do={
    :set BackupAttempted true
    :set BackupOk [$DoBackupAndUpload identity=$Identity backupPassword=$BackupPassword \
        workerUrl=$R2PresignWorkerUrl routerSecret=$R2RouterSecret deleteAfterUpload=$DeleteLocalBackupAfterUpload \
        logPrefix=$LogPrefix showSensitive=$ExportShowSensitive]
    :if ($BackupOk = true) do={
        :log info ($LogPrefix . " routine backup completed.")
    } else={
        :log error ($LogPrefix . " routine backup failed - see log lines above. Continuing to check for updates anyway.")
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

            :if ($BackupAttempted = false) do={
                :set BackupOk [$DoBackupAndUpload identity=$Identity backupPassword=$BackupPassword \
                    workerUrl=$R2PresignWorkerUrl routerSecret=$R2RouterSecret deleteAfterUpload=$DeleteLocalBackupAfterUpload \
                    logPrefix=$LogPrefix showSensitive=$ExportShowSensitive]
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

