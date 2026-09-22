#!rsc by RouterOS
# =============================================================================
# RouterOS 7.x - Secret Vault (shared by other scripts)
#
# Defines a global $SECRET function that repurposes /ppp/secret as a masked
# password store - it's the one RouterOS field type that's actually hidden
# in `/print`, `/export` and config backups (unless show-sensitive is used),
# unlike a plain variable, file, comment or note. This is obscurity backed by
# RouterOS's own "sensitive" policy, not encryption: any script or user with
# that policy can still read a secret back out with $SECRET get. It keeps
# credentials out of script text and off-router backups; it is not a
# substitute for real access control on the router itself.
#
# Technique: park each secret's value in a /ppp/secret entry pointed at a
# deliberately unusable ("null") PPP profile, so it's never actually usable
# for real dial-in auth - it's purely a hidden key/value slot. As described
# by MikroTik forum user Amm0 and written up at
# https://alikhil.dev/posts/saving-and-using-secrets-in-mikrotik-routeros/
# (this is an independent implementation of the same idea, not a copy).
#
# This script only DEFINES the function and a readiness flag - it doesn't
# read or write any particular secret itself, and it's the only script that
# should define $SECRET. Run it once at every boot (see setup below) so it's
# available to any other script without each of them redefining it.
#
# USAGE FROM OTHER SCRIPTS
#   :global SecretVaultReady
#   :global SECRET
#   :local waited 0
#   :while ($SecretVaultReady != true && $waited < 20) do={ :delay 500ms; :set waited ($waited + 1) }
#   :if ($SecretVaultReady != true) do={ :error "secret-vault not ready" }
#   ... then, e.g.: [$SECRET "get" "SOME_NAME"] ...
#
# ONE-TIME SETUP
#   1. Paste this file into a new script named "secret-vault" (System > Scripts).
#      Policy needs at least: read, write, test.
#   2. /system scheduler add name=secret-vault start-time=startup \
#          on-event="/system script run secret-vault"
#   3. Run it once right now too, so $SECRET exists without waiting for a reboot:
#        /system script run secret-vault
#   4. Seed secrets from the terminal (runs under your own admin permissions,
#      not this script's policy), e.g.:
#        $SECRET "set" "R2_SHARED_SECRET" password="..."
#
# Any OTHER script that calls $SECRET "get"/"set"/"remove" needs "sensitive"
# (and "write" for set/remove) in its own Policy - policy is enforced per the
# script that's actually running, not the script that defined the function.
# =============================================================================

:global SecretVaultReady false
:global SECRET
:set SECRET do={
    :global SECRET
    :local action     [:tostr $1]
    :local secretName [:tostr $2]
    :local nullProfile "routeros-secret-store-null"

    :if ($action = "print") do={
        /ppp/secret/print where comment="routeros-secret-store"
        :return [:nothing]
    }

    :if ($action = "get") do={
        :local found [/ppp/secret/find name=$secretName]
        :if ([:len $found] = 0) do={ :error ("SECRET: \"" . $secretName . "\" not found - use \$SECRET \"set\" \"" . $secretName . "\" password=\"...\" first") }
        :return [/ppp/secret/get $found password]
    }

    :if ($action = "set") do={
        :local pass [:tostr $password]
        :if ($pass = "") do={ :error "SECRET: set requires password=..." }

        :if ([:len [/ppp/profile/find name=$nullProfile]] = 0) do={ /ppp/profile/add name=$nullProfile only-one=yes use-encryption=no use-compression=no use-mpls=no use-upnp=no session-timeout=1s change-tcp-mss=no local-address=0.0.0.0 remote-address=0.0.0.0 }

        :local found [/ppp/secret/find name=$secretName]
        :if ([:len $found] = 0) do={
            /ppp/secret/add name=$secretName password=$pass profile=$nullProfile service=async comment="routeros-secret-store"
        } else={
            /ppp/secret/set $found password=$pass profile=$nullProfile service=async comment="routeros-secret-store"
        }
        :return true
    }

    :if ($action = "remove") do={
        :local found [/ppp/secret/find name=$secretName]
        :if ([:len $found] = 0) do={ :error ("SECRET: \"" . $secretName . "\" not found") }
        /ppp/secret/remove $found
        :return true
    }

    :error ("SECRET: unknown action \"" . $action . "\" -- use get, set, remove or print")
}
:set SecretVaultReady true
:log info "secret-vault: \$SECRET is ready."
