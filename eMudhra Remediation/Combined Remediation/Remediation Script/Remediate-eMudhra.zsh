#!/bin/zsh --no-rcs
# shellcheck shell=bash

####################################################################################################
#
# Remediate cert.pem and conda eMudhra
#
#   Purpose: Removes the two roots the leaked eMudhra intermediates chain to from macOS's
#            /etc/ssl/cert.pem (the built-in curl, git, python3, openssl, perl and ruby) and from the
#            CA bundles of conda installs (conda, mamba, micromamba and pixi environments: their own
#            curl, openssl, Python, requests and pip), which don't read /etc/ssl/cert.pem
#
#   Usage:   Jamf Pro: Parameter 4: Operation Mode [ fix (default) | check | dry-run | restore ]
#                      Parameter 5: cert.pem backup to restore (optional; defaults to newest)
#                      Parameter 6: Network Test [ off (default) | on ]
#                      Parameter 7: Test URL (optional; defaults to the advisory's test host)
#                      Parameter 8: Scope [ all (default) | cert.pem | conda ]
#
#            Local:    sudo zsh Remediate-eMudhra.zsh                         # Fix (default)
#                      sudo zsh Remediate-eMudhra.zsh --check                 # Read-only status
#                      sudo zsh Remediate-eMudhra.zsh --dry-run               # Build and verify; install nothing
#                      sudo zsh Remediate-eMudhra.zsh --restore [backup]      # Restore the backups
#                      Append --offline to any local option to skip the network test, and
#                      --cert-pem-only or --conda-only to limit the scope
#
#   Exit:    0 = safe / fixed; 1 = still exposed; 2 = couldn't tell / refused (the worst of the parts)
#
####################################################################################################
#
# HISTORY
#
# Version 0.0.1, 23-Oct-2026, Per Kristian Thorsen
#   - Original version: Dan K. Snelson's Remediate-cert.pem-eMudhra.zsh (0.0.4) and
#     Remediate-conda-eMudhra.zsh (0.0.2) in one script; each part runs in its own subshell, with
#     its own work directory and exit code
#
####################################################################################################

####################################################################################################
#
# Global Variables
#
####################################################################################################

export PATH=/usr/bin:/bin:/usr/sbin:/sbin

# Script Version
scriptVersion="0.0.1"

# Client-side Log
scriptLog="/var/log/Remediate-eMudhra.log"

# Elapsed Time
SECONDS="0"

# Advisory test host: serves a leaf issued under the leaked chain (curl exit 0 = trusted; 60 = refused)
defaultTestURL="https://dv-g3b-emudhra.we-have-a-problem.com/"

# Network verdict until a network test runs
networkResult="disabled"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Jamf Pro Script Parameters
# (Parameters 1–3 are reserved by Jamf Pro: mount point, computer name and username; local runs
# instead pass no arguments or an option such as --check; see "Pre-flight Check: Parameters")
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Parameter 4: Operation Mode [ fix (default) | check | dry-run | restore ]
operationMode="${4:-"fix"}"

# Parameter 5: Backup to restore (optional; defaults to newest; only used when Operation Mode is restore)
restoreSource="${5:-""}"

# Parameter 6: Network Test [ off (default) | on ]; "on" contacts the Test URL and the control URL
networkTest="${6:-"off"}"

# Parameter 7: Test URL (optional; must serve a chain that includes a pinned leaked intermediate)
testURL="${7:-"${defaultTestURL}"}"

# Parameter 8: Scope [ all (default) | cert.pem | conda ]
remediationScope="${8:-"all"}"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Organization Variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Script Human-readabale Name
humanReadableScriptName="Remediate cert.pem and conda eMudhra"

# Organization's Script Name
organizationScriptName="RCCE"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Certificate Variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

certDir="/etc/ssl"
certFile="${certDir}/cert.pem"

# Positive control (network test only): must still verify with the cleaned bundle
controlHost="www.apple.com"
controlURL="https://${controlHost}/"

curlTimeout="15"

# Offline verification time (21-Oct-2026 00:00:00 UTC), pinned so certificate expiry never changes
# the verdict; LibreSSL's openssl verify has -attime, but not -no_check_time
verifyEpoch="1792540800"

# SHA-256 fingerprints of the roots to remove (uppercase hex, no colons)
typeset -A targetRoots
targetRoots=(
    D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4 "AAA Certificate Services"
    86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B "emSign ECC Root CA - G3"
)

# Advisory awk: each certificate in Apple's cert.pem is preceded by a "### " (organization) and/or
# "=== " (subject) header line; skip from a target's "=== " line to the next header line
removalAwk='
    /^(###|===) / { skip=0 }
    /^=== .*\/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$/ { skip=1 }
    !skip
'

# Network test: the served chain must include one of these leaked intermediates; anything else
# means the test host changed or the connection was intercepted (e.g., TLS decryption)
pinnedChainFingerprints=(
    42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493 # EM DV TLS CA - G3B <- emSign Root TLS CA - G3
    3094025792039A68AF6E553686410BDAB7C0D4A36B9084CBA64202E35D6EBBDD # emSign Root TLS CA - G3 <- emSign ECC Root CA - G3
    45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE # EM DV TLS CA - G3B <- AAA Certificate Services
)



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Offline Probes: one leaked intermediate per target root; each verifies against a bundle that
# still holds its issuing root and fails with "error 20" once that root is removed
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

typeset -A probeLabels probeFingerprints probePEMs

probeLabels=(
    emSign "emSign Root TLS CA - G3 <- emSign ECC Root CA - G3"
    AAA    "EM DV TLS CA - G3B <- AAA Certificate Services"
)

probeFingerprints=(
    emSign 3094025792039A68AF6E553686410BDAB7C0D4A36B9084CBA64202E35D6EBBDD
    AAA    45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE
)

# Served by the advisory's test host (crt.sh ID 14658191778)
probePEMs[emSign]='-----BEGIN CERTIFICATE-----
MIIDdDCCAvmgAwIBAgIQAJYaPvsTWVdu0EAFtGhKWzAKBggqhkjOPQQDAzBrMQsw
CQYDVQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhy
YSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290
IENBIC0gRzMwHhcNMjQwNzExMTU0MzM2WhcNMzkwNzA5MTgzMDAwWjBWMQswCQYD
VQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEg
MB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwdjAQBgcqhkjOPQIBBgUr
gQQAIgNiAARfD9w/q1cWxL6D9bMGH6CQ4u+gAV6GN9s+PwQx9Bl4hC+0iU8QOk8m
WO/RwXQy10DCSxT8vSIJClHKp+Ao4qJKdYeV0SwZ7LMQziyLfxIUOY6Grja/sQFw
LKYf8EdDXAyjggF1MIIBcTAfBgNVHSMEGDAWgBR8XQKEE9TMipuBzhccLikenEhj
QjAdBgNVHQ4EFgQU4TqrIXzx401UrtRyt/2LWUIgkFQwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIB
FhxodHRwOi8vcmVwb3NpdG9yeS5lbXNpZ24uY29tMHgGCCsGAQUFBwEBBGwwajAi
BggrBgEFBQcwAYYWaHR0cDovL29jc3AuZW1zaWduLmNvbTBEBggrBgEFBQcwAoY4
aHR0cDovL3JlcG9zaXRvcnkuZW1zaWduLmNvbS9jZXJ0cy9lbVNpZ25FQ0NSb290
Q0FHMy5jcnQwMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2NybC5lbXNpZ24uY29t
P1Jvb3RDQUczLmNybDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIB
ATAKBggqhkjOPQQDAwNpADBmAjEAt9CIpRGp46QHQYDUBnLKw+vvK0/h9vmilEAg
TroUl/anH4x2rXHqiCtBTBfgKDegAjEA8WpG1LTZdAIL0FSYqxXeREaeTSxEofM0
1jJH3jGvCXC79LU9UPJ2o3TU+UIj2gMV
-----END CERTIFICATE-----'

# Cross-signed by AAA Certificate Services (crt.sh ID 18519019583)
probePEMs[AAA]='-----BEGIN CERTIFICATE-----
MIIDzjCCAragAwIBAgIRAKAk/fS6Zlx4XOSgIEg4WLcwDQYJKoZIhvcNAQELBQAw
ezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNV
BAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0y
ODEyMzEyMzU5NTlaMD8xCzAJBgNVBAYTAk5MMRMwEQYDVQQKDAplTXVkaHJhIEJW
MRswGQYDVQQDDBJFTSBEViBUTFMgQ0EgLSBHM0IwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAATnntnASpdzxHNeUREdqFrCvV5kqzdLgOEsvCA47B5PDjuBL8mFnh5nr7BO
L4vJf3SFumWqkR7opORbYtXMA9Vr5nizw4y03JN8okYOI4RTyJKTXSnUT5HhVga2
PM7atGijggE1MIIBMTAfBgNVHSMEGDAWgBSgEQojPpbxB+zirynvgqV/0DCktDAd
BgNVHQ4EFgQU4h4v5xwZOQ5VS2LBICRXNSSKJRQwDgYDVR0PAQH/BAQDAgEGMBIG
A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MDEGA1UdIAQqMCgwCAYGZ4EMAQIBMA0GCysGAQQBg44hAQABMA0GCysGAQQBg44h
AQJkMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FB
QUNlcnRpZmljYXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEF
BQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBCwUAA4IB
AQBzQ1IoqpdotM6gFrR4Q3YrKifOLeaj5XXunldpVE/vZn2TxC2y0s8oYiLR5ICE
wqVXSB7N6BM1Mp+Nif7Jbhb2IswAfSR4Iik8+B0iRmi7lYoNlycCgHjmsjOmZaxM
QkPmjXAJbG5f4V41OsvJZmS7lI3r0IuvEDVX3GAZ13on6IImSs9ybNpHQ7NCqkMQ
7wH4uAO1dtpFycgJSdHaCOhHjrox2BTYGLdpUrYwY3EOAjlZ8UGgsxs7mG+xquMl
bN1LFURwfnkVMP3T/DBIZ/ys2+lNFyxK3FlArrV4/000uTnVB1lO8oGORYdXoT5V
GUyRCEIDhF5TBUuKF4E3kf1h
-----END CERTIFICATE-----'

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Conda Variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Install locations checked in each user's home folder (.local/share/mamba: micromamba 2.x root;
# .pixi: pixi global; .conda: conda's per-user envs/ when the base install isn't writable)
homeCondaRoots=( miniconda3 anaconda3 miniforge3 mambaforge micromamba opt/miniconda3 opt/anaconda3 opt/miniforge3 .local/share/mamba .pixi .conda )

# Shell startup files holding "conda initialize" / "mamba initialize" blocks
shellStartupFiles=( .zshrc .zprofile .bash_profile .bashrc .profile .config/fish/config.fish )

# pixi workspaces: how deep to look for .pixi/envs in each home folder, and folders to skip
pixiSearchDepth="6"
pixiSearchSkip=( Library .Trash node_modules .git )

# Install locations outside home folders (installer packages and Homebrew casks)
systemCondaRoots=(
    /opt/miniconda3
    /opt/anaconda3
    /opt/miniforge3
    /opt/mambaforge
    /opt/homebrew/Caskroom/miniconda/base
    /opt/homebrew/Caskroom/miniforge/base
    /opt/homebrew/anaconda3
    /usr/local/Caskroom/miniconda/base
    /usr/local/Caskroom/miniforge/base
    /usr/local/anaconda3
)

# Per-mode tallies and bundle counter (names each bundle's work files)
exposedCount="0"
unknownCount="0"
bundleIndex="0"

####################################################################################################
#
# Functions
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Client-side Logging (stdout only when scriptLog isn't writable, e.g., --check without sudo)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function updateScriptLog() {
    if [[ -w "${scriptLog}" ]]; then
        echo "${organizationScriptName} ($scriptVersion): $( date +%Y-%m-%d\ %H:%M:%S ) - ${1}" | tee -a "${scriptLog}"
    else
        echo "${organizationScriptName} ($scriptVersion): $( date +%Y-%m-%d\ %H:%M:%S ) - ${1}"
    fi
}

function preFlight() {
    updateScriptLog "[PRE-FLIGHT]      ${1}"
}

function logComment() {
    updateScriptLog "                  ${1}"
}

function notice() {
    updateScriptLog "[NOTICE]          ${1}"
}

function info() {
    updateScriptLog "[INFO]            ${1}"
}

function errorOut(){
    updateScriptLog "[ERROR]           ${1}"
}

function warning() {
    updateScriptLog "[WARNING]         ${1}"
    let errorCount++
}

# Exits 2 (not 1); exit 1 is reserved for "still exposed"
function fatal() {
    updateScriptLog "[FATAL ERROR]     ${1}"
    exit 2
}

function quitOut(){
    updateScriptLog "[QUIT]            ${1}"
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Exit with code (Parameter 1) and summary (Parameter 2)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function exitWith() {
    info "Elapsed Time: $(printf '%dh:%dm:%ds\n' $((SECONDS/3600)) $((SECONDS%3600/60)) $((SECONDS%60)))"
    quitOut "${2} (exit ${1})"
    exit "${1}"
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Remove work directory and any staged install file
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function cleanUp() {
    [[ -n "${workDir}" && -d "${workDir}" ]] && rm -Rf "${workDir}"
    [[ -n "${stagedFile}" && -f "${stagedFile}" ]] && rm -f "${stagedFile}"
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Split every PEM certificate block in a file (Parameter 1) into its own file in a directory
# (Parameter 2)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function splitPEM() {

    local pemFile="${1}"
    local splitDir="${2}"

    rm -Rf "${splitDir}"
    mkdir -p "${splitDir}" || return 2

    awk -v dir="${splitDir}" '
        /^-----BEGIN CERTIFICATE-----/ { n++; inBlock=1; file=sprintf("%s/%04d.pem", dir, n) }
        inBlock { print > file }
        /^-----END CERTIFICATE-----/ { if (inBlock) close(file); inBlock=0 }
    ' "${pemFile}"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# SHA-256 fingerprint (uppercase hex, no colons) of a single-certificate PEM file (Parameter 1)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function certFingerprint() {

    local fingerprint

    fingerprint=$( openssl x509 -noout -fingerprint -sha256 -in "${1}" 2>/dev/null ) || return 2
    fingerprint="${${fingerprint#*=}//:/}"
    fingerprint="${(U)fingerprint}"
    [[ "${fingerprint}" =~ ^[0-9A-F]{64}$ ]] || return 2
    echo "${fingerprint}"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Write sorted SHA-256 fingerprints of every parsed certificate in a PEM bundle (Parameter 1) to an
# output file (Parameter 2); returns 2 if any block fails to parse or the bundle holds none
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function listFingerprints() {

    local pemFile="${1}"
    local outFile="${2}"
    local splitDir="${workDir}/split.${outFile:t}"
    local block

    # Fingerprint the PEM data itself, not the "===" header text
    splitPEM "${pemFile}" "${splitDir}" || return 2

    : > "${outFile}"
    for block in "${splitDir}"/*.pem(N); do
        certFingerprint "${block}" >> "${outFile}" || return 2
    done

    [[ -s "${outFile}" ]] || return 2
    sort -o "${outFile}" "${outFile}"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Bundle status of a PEM file (Parameter 1), fingerprints written to Parameter 2
# Sets: bundleState (clean | exposed | damaged), bundleCount, targetsPresent
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function bundleStatus() {

    local pemFile="${1}"
    local fingerprintFile="${2}"
    local fingerprint

    if ! listFingerprints "${pemFile}" "${fingerprintFile}"; then
        bundleState="damaged"
        errorOut "${pemFile} contains no certificates or a certificate that does not parse"
        return 2
    fi

    bundleCount=$( wc -l < "${fingerprintFile}" | tr -d ' ' )
    targetsPresent=0
    for fingerprint in ${(k)targetRoots}; do
        if grep -qxF "${fingerprint}" "${fingerprintFile}"; then
            logComment "Present: ${targetRoots[$fingerprint]} (SHA-256 ${fingerprint})"
            (( targetsPresent += 1 ))
        fi
    done

    if (( targetsPresent > 0 )); then
        bundleState="exposed"
    else
        bundleState="clean"
    fi
    logComment "${pemFile}: ${bundleCount} certificates; ${targetsPresent} of ${#targetRoots} target roots present"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Write the embedded offline probes to workDir and confirm each matches its pinned fingerprint
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function writeProbes() {

    local probe fingerprint

    for probe in ${(k)probeFingerprints}; do
        print -r -- "${probePEMs[$probe]}" > "${workDir}/probe.${probe}.pem"
        fingerprint=$( certFingerprint "${workDir}/probe.${probe}.pem" )
        if [[ "${fingerprint}" != "${probeFingerprints[$probe]}" ]]; then
            errorOut "Embedded probe '${probeLabels[$probe]}' does not match its pinned SHA-256"
            return 2
        fi
    done

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Offline verification of a bundle (Parameter 1) against the embedded leaked intermediates
# Sets: offlineResult (trusted | refused | inconclusive)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function offlineVerify() {

    local bundle="${1}"
    local probe verifyOutput verifyRC refusal
    local probesTrusted=0
    local probesRefused=0

    for probe in ${(k)probeFingerprints}; do
        verifyOutput=$( openssl verify -attime "${verifyEpoch}" -CAfile "${bundle}" "${workDir}/probe.${probe}.pem" 2>&1 )
        verifyRC=$?
        # "error 20" / "error 2": no path from the probe to a trust anchor in the bundle
        refusal=$( print -r -- "${verifyOutput}" | grep -m1 -E '^error (2|20) at ' )
        if [[ ${verifyRC} -eq 0 && "${verifyOutput}" == *": OK" ]]; then
            (( probesTrusted += 1 ))
            logComment "Offline: ${probeLabels[$probe]}: verifies (exposed)"
        elif [[ -n "${refusal}" ]]; then
            (( probesRefused += 1 ))
            logComment "Offline: ${probeLabels[$probe]}: refused (${refusal})"
        else
            logComment "Offline: ${probeLabels[$probe]}: unexpected result (exit ${verifyRC}): ${verifyOutput//$'\n'/ | }"
        fi
    done

    if (( probesTrusted > 0 )); then
        offlineResult="trusted"
    elif (( probesRefused == ${#probeFingerprints} )); then
        offlineResult="refused"
    else
        offlineResult="inconclusive"
    fi

    logComment "Offline verdict for ${bundle}: ${offlineResult}"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# curl trust test of a URL (Parameter 1), optionally against a CA file (Parameter 2)
# Sets: trustRC, trustResult (trusted | refused | inconclusive)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function trustTest() {

    local url="${1}"
    local caFile="${2}"
    local -a curlOptions=( -q -s -o /dev/null --max-time "${curlTimeout}" )

    [[ -n "${caFile}" ]] && curlOptions+=( --cacert "${caFile}" )
    /usr/bin/curl "${curlOptions[@]}" "${url}"
    trustRC=$?

    case "${trustRC}" in
        0  ) trustResult="trusted" ;;
        60 ) trustResult="refused" ;;
        *  ) trustResult="inconclusive" ;;
    esac

    logComment "curl ${url}${caFile:+ (--cacert ${caFile})}: exit ${trustRC} (${trustResult})"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Inspect the chain a host serves (Parameter 1: host:port; Parameter 2: server name); call only
# after curl completed a TLS handshake with that host, since s_client has no timeout of its own
# Sets: servedChainPinned (yes | no), servedIssuer (issuer of the served leaf)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function inspectServedChain() {

    local connectTo="${1}"
    local serverName="${2}"
    local chainDir="${workDir}/served.${serverName}"
    local block fingerprint

    servedChainPinned="no"
    servedIssuer=""

    openssl s_client -connect "${connectTo}" -servername "${serverName}" -showcerts < /dev/null > "${chainDir}.txt" 2>/dev/null
    splitPEM "${chainDir}.txt" "${chainDir}"

    for block in "${chainDir}"/*.pem(N); do
        [[ -z "${servedIssuer}" ]] && servedIssuer=$( openssl x509 -noout -issuer -in "${block}" 2>/dev/null )
        fingerprint=$( certFingerprint "${block}" ) || continue
        # (Ie): index of an exact match, or 0
        (( ${pinnedChainFingerprints[(Ie)${fingerprint}]} )) && servedChainPinned="yes"
    done

    servedIssuer="${servedIssuer#issuer=}"
    servedIssuer="${servedIssuer# }"
    logComment "Served chain from ${serverName}: pinned leaked intermediate: ${servedChainPinned}; leaf issuer: ${servedIssuer:-none}"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Network test of the Test URL, optionally against a CA file (Parameter 1); confirmation only
# Sets: networkResult (trusted | refused | invalid | unusable)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function networkProbe() {

    local caFile="${1}"

    trustTest "${testURL}" "${caFile}"

    if [[ "${trustResult}" == "inconclusive" ]]; then
        networkResult="unusable"
        warning "Network test unusable (curl exit ${trustRC}); verdict rests on offline verification"
    else
        inspectServedChain "${testConnect}" "${testServerName}"
        if [[ "${servedChainPinned}" == "yes" ]]; then
            networkResult="${trustResult}"
        else
            networkResult="invalid"
            warning "Served chain lacks the pinned leaked intermediates (TLS interception or test host change suspected); network result ignored"
        fi
    fi

    logComment "Network verdict${caFile:+ (--cacert ${caFile})}: ${networkResult}"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Final verdict for an unchanged or newly installed certFile, after bundleStatus, offlineVerify and
# (optionally) networkProbe; Parameter 1 is the summary when safe
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function reportVerdict() {

    if [[ "${bundleState}" == "exposed" ]]; then
        exitWith 1 "EXPOSED: ${targetsPresent} target root(s) present in ${certFile}"
    elif [[ "${offlineResult}" == "trusted" ]]; then
        exitWith 1 "EXPOSED: target roots absent, but a leaked intermediate still verifies against ${certFile}"
    elif [[ "${offlineResult}" != "refused" ]]; then
        exitWith 2 "Offline verification inconclusive; couldn't tell"
    elif [[ "${networkResult}" == "trusted" ]]; then
        exitWith 2 "Contradiction: leaked chain refused offline, but curl trusts ${testServerName} (curl may not be using ${certFile})"
    else
        exitWith 0 "${1} (offline: refused; network: ${networkResult})"
    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Fallback removal: copy every PEM block of a bundle (Parameter 1) to an output file (Parameter 2),
# except blocks whose SHA-256 is a target root; header and comment lines are dropped
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function removeByFingerprint() {

    local pemFile="${1}"
    local outFile="${2}"
    local splitDir="${workDir}/split.fallback"
    local block fingerprint

    splitPEM "${pemFile}" "${splitDir}" || return 2

    : > "${outFile}"
    for block in "${splitDir}"/*.pem(N); do
        fingerprint=$( certFingerprint "${block}" ) || return 2
        # (+): 1 when the key exists
        (( ${+targetRoots[$fingerprint]} )) && continue
        cat "${block}" >> "${outFile}" || return 2
    done

    [[ -s "${outFile}" ]] || return 2

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Build cleaned bundle with the advisory awk (falling back to removeByFingerprint) and confirm it
# equals the original minus only the target roots
# Requires: bundleStatus of certFile written to ${workDir}/original.txt
# Sets: candidateFile
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function prepareCandidate() {

    local originalFingerprints="${workDir}/original.txt"
    local expectedFingerprints="${workDir}/expected.txt"
    local targetList="${workDir}/targets.txt"

    candidateFile="${workDir}/cert.pem.cleaned"

    # Expected = original minus every target root
    print -l -- ${(k)targetRoots} > "${targetList}"
    grep -vxF -f "${targetList}" "${originalFingerprints}" > "${expectedFingerprints}"

    notice "Build cleaned bundle"
    if ! awk "${removalAwk}" "${certFile}" > "${candidateFile}"; then
        errorOut "awk removal failed"
    elif validateCandidate; then
        return 0
    fi

    notice "Advisory awk did not validate; rebuilding by fingerprint"
    if ! removeByFingerprint "${certFile}" "${candidateFile}"; then
        errorOut "Fingerprint removal failed"
        return 2
    fi

    validateCandidate || return 2
    logComment "Cleaned bundle rebuilt by fingerprint (header and comment lines dropped)"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Confirm candidateFile equals the original minus only the target roots
# Requires: ${workDir}/expected.txt and ${workDir}/targets.txt from prepareCandidate
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function validateCandidate() {

    local candidateFingerprints="${workDir}/candidate.txt"
    local expectedFingerprints="${workDir}/expected.txt"
    local targetList="${workDir}/targets.txt"
    local candidateCount expectedCount

    if ! listFingerprints "${candidateFile}" "${candidateFingerprints}"; then
        errorOut "Cleaned bundle contains no certificates or a certificate that does not parse"
        return 2
    fi

    candidateCount=$( wc -l < "${candidateFingerprints}" | tr -d ' ' )
    expectedCount=$(( bundleCount - targetsPresent ))
    logComment "Cleaned bundle: ${candidateCount} certificates (expected ${expectedCount})"

    if grep -qxF -f "${targetList}" "${candidateFingerprints}"; then
        errorOut "A target root is still in the cleaned bundle"
        return 2
    fi

    if (( candidateCount != expectedCount )); then
        errorOut "Certificate count mismatch"
        return 2
    fi

    if ! cmp -s "${expectedFingerprints}" "${candidateFingerprints}"; then
        errorOut "Cleaned bundle removed or changed certificates other than the target roots"
        return 2
    fi

    logComment "Cleaned bundle validated: only the target roots were removed"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Offline verification of the cleaned bundle; exits unless it refuses the leaked chain
# Parameter 1: wording for the outcome (e.g., "no changes made" or "fix would refuse")
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function verifyCandidate() {

    notice "Verify cleaned bundle offline"
    offlineVerify "${candidateFile}"

    case "${offlineResult}" in
        trusted      ) exitWith 1 "Cleaned bundle still verifies a leaked intermediate; ${1}" ;;
        inconclusive ) exitWith 2 "Offline verification of cleaned bundle inconclusive; ${1}" ;;
    esac

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Network test of the cleaned bundle (--cacert) before installing it; confirmation only
# Parameter 1: wording for the outcome (e.g., "no changes made" or "fix would refuse")
# Sets: candidateVerdict (confirmed | unconfirmed | network-unusable)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function testCandidate() {

    notice "Network test: cleaned bundle"
    networkProbe "${candidateFile}"

    trustTest "${controlURL}" "${candidateFile}"
    if [[ "${trustResult}" != "trusted" ]]; then
        # Control failed: cleaned bundle broke normal TLS, or the network is unusable / intercepted
        trustTest "${controlURL}" "${certFile}"
        if [[ "${trustResult}" == "trusted" ]]; then
            exitWith 2 "Cleaned bundle fails ${controlURL} but the original passes; ${1}"
        fi
        candidateVerdict="network-unusable"
        [[ "${trustResult}" == "refused" ]] && inspectServedChain "${controlHost}:443" "${controlHost}"
    elif [[ "${networkResult}" == "trusted" ]]; then
        exitWith 2 "Contradiction: cleaned bundle refuses the leaked chain offline, but curl trusts ${testServerName} with it; ${1}"
    elif [[ "${networkResult}" == "refused" ]]; then
        candidateVerdict="confirmed"
    else
        candidateVerdict="unconfirmed"
    fi

    logComment "Cleaned bundle network verdict: ${candidateVerdict}"
    [[ "${candidateVerdict}" != "confirmed" ]] && warning "Network confirmation unavailable (${candidateVerdict}); relying on offline verification"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Timestamped, verified backup of certFile; never overwrites
# Sets: backupFile
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function backupOriginal() {

    backupFile="${certFile}.bak.$( date +%Y%m%d-%H%M%S )"

    if [[ -e "${backupFile}" ]]; then
        errorOut "Backup ${backupFile} already exists; refusing to overwrite"
        return 2
    fi

    if ! cp -p "${certFile}" "${backupFile}" || ! cmp -s "${certFile}" "${backupFile}"; then
        errorOut "Unable to create verified backup ${backupFile}"
        return 2
    fi

    logComment "Backup: ${backupFile}"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Atomically install a file (Parameter 1) as certFile: stage in certDir (same filesystem), set
# 644 root:wheel, then rename over certFile
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function installFile() {

    local sourceFile="${1}"

    stagedFile=$( mktemp "${certDir}/.cert.pem.XXXXXX" ) || return 2

    if cp "${sourceFile}" "${stagedFile}" \
        && chmod 644 "${stagedFile}" \
        && chown root:wheel "${stagedFile}" \
        && mv -f "${stagedFile}" "${certFile}"; then
        stagedFile=""
    else
        errorOut "Unable to install ${sourceFile} as ${certFile}"
        return 2
    fi

    if ! cmp -s "${sourceFile}" "${certFile}"; then
        errorOut "${certFile} does not match ${sourceFile} after install"
        return 2
    fi

    logComment "Installed: $( stat -f '%Sp %Su:%Sg' "${certFile}" ) ${certFile}"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Roll back certFile to backupFile
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function rollBack() {

    warning "Rolling back to ${backupFile}"
    if installFile "${backupFile}"; then
        logComment "Rolled back; ${certFile} matches ${backupFile}"
    else
        errorOut "ROLLBACK FAILED; restore manually: sudo cp -p '${backupFile}' '${certFile}'"
    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Mode: --check (read-only)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkMode() {

    notice "Check: ${certFile}"
    bundleStatus "${certFile}" "${workDir}/original.txt" || exitWith 2 "${certFile} is damaged; couldn't tell"
    offlineVerify "${certFile}"

    if [[ "${networkTest}" == "on" ]]; then
        notice "Network test: system default trust"
        networkProbe
    fi

    reportVerdict "SAFE: target roots absent and leaked chain refused"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Mode: --dry-run (build and verify a cleaned copy in workDir; install nothing)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function dryRunMode() {

    local originalHash

    notice "Dry run: ${certFile} will not be changed"
    originalHash=$( shasum -a 256 "${certFile}" | awk '{ print $1 }' )

    bundleStatus "${certFile}" "${workDir}/original.txt" || exitWith 2 "${certFile} is damaged; would refuse to touch it"
    offlineVerify "${certFile}"

    if [[ "${bundleState}" == "clean" ]]; then
        if [[ "${networkTest}" == "on" ]]; then
            notice "Network test: system default trust"
            networkProbe
        fi
        reportVerdict "Nothing to remove; ${certFile} is already clean"
    fi

    prepareCandidate || exitWith 2 "Cleaned bundle failed validation; fix would refuse"
    verifyCandidate "fix would refuse"
    [[ "${networkTest}" == "on" ]] && testCandidate "fix would refuse"

    if [[ "$( shasum -a 256 "${certFile}" | awk '{ print $1 }' )" == "${originalHash}" ]]; then
        logComment "${certFile} unchanged (SHA-256 ${originalHash})"
    else
        warning "${certFile} changed during the dry run (not by this script)"
    fi

    exitWith 0 "Dry run complete: ${bundleCount} -> $(( bundleCount - targetsPresent )) certificates; leaked chain refused offline (network: ${networkResult})"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Mode: fix (default)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function fixMode() {

    notice "Fix: ${certFile}"
    bundleStatus "${certFile}" "${workDir}/original.txt" || exitWith 2 "${certFile} is damaged; refusing to touch it"
    offlineVerify "${certFile}"

    if [[ "${bundleState}" == "clean" ]]; then
        if [[ "${networkTest}" == "on" ]]; then
            notice "Network test: system default trust"
            networkProbe
        fi
        reportVerdict "Already clean; no changes made"
    fi

    prepareCandidate || exitWith 2 "Cleaned bundle failed validation; no changes made"
    verifyCandidate "no changes made"
    [[ "${networkTest}" == "on" ]] && testCandidate "no changes made"

    notice "Install cleaned bundle"
    backupOriginal || exitWith 2 "No verified backup; no changes made"
    if ! installFile "${candidateFile}"; then
        rollBack
        exitWith 2 "Install failed; rolled back to original"
    fi

    notice "Verify installed bundle offline"
    if ! bundleStatus "${certFile}" "${workDir}/installed.txt"; then
        rollBack
        exitWith 2 "Installed bundle does not parse; rolled back to original"
    fi
    offlineVerify "${certFile}"
    if [[ "${bundleState}" == "exposed" || "${offlineResult}" == "trusted" ]]; then
        rollBack
        exitWith 1 "STILL EXPOSED after fix (offline); rolled back to original"
    fi

    if [[ "${networkTest}" == "on" ]]; then
        notice "Network test: system default trust"
        networkProbe
    fi

    reportVerdict "FIXED: backup: ${backupFile}"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Mode: --restore [backup]
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function restoreMode() {

    local -a backups

    if [[ -n "${restoreSource}" ]]; then
        backupFile="${restoreSource}"
    else
        # Newest by name; "cp -p" keeps the original's mtime, so mtime can't be used
        backups=( "${certFile}".bak.*(N.On) )
        backupFile="${backups[1]}"
    fi

    [[ -n "${backupFile}" && -f "${backupFile}" && ! -L "${backupFile}" ]] || exitWith 2 "No backup found to restore"

    notice "Restore: ${backupFile}"
    bundleStatus "${backupFile}" "${workDir}/backup.txt" || exitWith 2 "${backupFile} is damaged; refusing to restore it"

    if [[ -f "${certFile}" ]] && cmp -s "${backupFile}" "${certFile}"; then
        exitWith 0 "${certFile} already matches ${backupFile}; no changes made"
    fi

    installFile "${backupFile}" || exitWith 2 "Restore failed"
    offlineVerify "${certFile}"

    if [[ "${networkTest}" == "on" ]]; then
        notice "Network test: system default trust"
        networkProbe
    fi

    exitWith 0 "Restored ${certFile} from ${backupFile} (offline: ${offlineResult}; network: ${networkResult})"

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Roots named by the init blocks in a home folder's (Parameter 1) shell startup files: the prefix of
# the conda that "conda init" wires up, and micromamba's / mamba's MAMBA_ROOT_PREFIX
# Prints one root per line
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function shellInitRoots() {

    local home="${1}"
    local startupFile root

    for startupFile in "${home}/"${^shellStartupFiles}; do
        [[ -f "${startupFile}" && ! -L "${startupFile}" ]] || continue
        # __conda_setup="$('/x/bin/conda' 'shell.zsh' 'hook' …)", . "/x/etc/profile.d/conda.sh",
        # export MAMBA_ROOT_PREFIX='/x' (fish: eval /x/bin/conda "shell.fish" …; set -gx MAMBA_ROOT_PREFIX "/x")
        # Quoted paths may hold spaces; unquoted ones (fish) end at the first space
        grep -hoE "'[^']+/bin/conda'|\"[^\"]+/etc/profile\.d/conda\.sh\"|[^\"' (]+/bin/conda ['\"]shell\.|MAMBA_ROOT_PREFIX[= ]+['\"][^'\"]+|MAMBA_ROOT_PREFIX=[^'\" ;]+" "${startupFile}" 2>/dev/null \
            | sed -E -e "s#^'(.*)/bin/conda'\$#\1#" -e 's#^"(.*)/etc/profile\.d/conda\.sh"$#\1#' -e "s#/bin/conda ['\"]shell\.\$##" -e "s#^MAMBA_ROOT_PREFIX[= ]+['\"]?##" \
            | while IFS= read -r root; do
                root="${root/#\$HOME/${home}}"
                root="${root/#\$\{HOME\}/${home}}"
                root="${root/#\~/${home}}"
                print -r -- "${root}"
            done
    done

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Conda prefixes: base installs and their environments, for every local user when run as root
# (otherwise the current user); a prefix must hold conda-meta
# Sets: prefixes (real paths, deduplicated)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function discoverPrefixes() {

    local -a homes roots pruneExpression
    local -A seen
    local user home environmentsFile root candidate prefix skip

    prefixes=()

    # find: -name Library -o -name .Trash -o …
    for skip in "${pixiSearchSkip[@]}"; do
        pruneExpression+=( -o -name "${skip}" )
    done
    pruneExpression=( "${pruneExpression[@]:1}" )

    if [[ $(id -u) -eq 0 ]]; then
        for user in $( dscl . -list /Users UniqueID | awk '$2 >= 501 { print $1 }' ); do
            home=$( dscl . -read "/Users/${user}" NFSHomeDirectory 2>/dev/null | awk '{ print $2 }' )
            [[ -d "${home}" ]] && homes+=( "${home}" )
        done
    else
        homes=( "${HOME}" )
    fi

    roots=( "${systemCondaRoots[@]}" )
    for home in "${homes[@]}"; do

        roots+=( "${home}/"${^homeCondaRoots} )

        # The conda (or mamba root) each shell's init block activates, wherever it lives
        roots+=( "${(@f)$( shellInitRoots "${home}" )}" )

        # conda records every prefix it creates or activates here, wherever it lives; for
        # …/envs/<name>, the base install above it too
        environmentsFile="${home}/.conda/environments.txt"
        if [[ -f "${environmentsFile}" && ! -L "${environmentsFile}" ]]; then
            for root in "${(@f)$( < "${environmentsFile}" )}"; do
                roots+=( "${root}" )
                [[ "${root}" == */envs/* ]] && roots+=( "${root%/envs/*}" )
            done
        fi

        # pixi workspaces keep their environments in <workspace>/.pixi/envs
        while IFS= read -r root; do
            roots+=( "${root:h}" )
        done < <( find "${home}" -maxdepth "${pixiSearchDepth}" \( "${pruneExpression[@]}" \) -prune -o -type d -name envs -path '*/.pixi/envs' -print 2>/dev/null )

    done

    for root in "${roots[@]}"; do
        [[ -n "${root}" ]] || continue
        for candidate in "${root}" "${root}"/envs/*(N/); do
            [[ -d "${candidate}/conda-meta" && ! -L "${candidate}" ]] || continue
            prefix="${candidate:A}"
            # (+): 1 when the key exists
            (( ${+seen[$prefix]} )) && continue
            seen[$prefix]=1
            prefixes+=( "${prefix}" )
        done
    done

    logComment "conda prefixes: ${#prefixes}"
    for prefix in "${prefixes[@]}"; do
        logComment "  ${prefix}"
    done

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# CA bundles in the discovered prefixes: ssl/cacert.pem (and ssl/cert.pem), certifi's cacert.pem,
# pip's vendored copy and botocore's; symlinks are followed only within their prefix
# Sets: bundles (real paths, deduplicated)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function discoverBundles() {

    local -A seen
    local prefix candidate bundle

    bundles=()

    for prefix in "${prefixes[@]}"; do
        for candidate in "${prefix}/ssl/cacert.pem" "${prefix}/ssl/cert.pem" \
            "${prefix}"/lib/python*/site-packages/certifi/cacert.pem(N) \
            "${prefix}"/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem(N) \
            "${prefix}"/lib/python*/site-packages/botocore/cacert.pem(N); do
            [[ -e "${candidate}" ]] || continue
            bundle="${candidate:A}"
            if [[ "${bundle}" != "${prefix}/"* ]]; then
                logComment "Skipped (resolves outside its prefix): ${candidate} -> ${bundle}"
                continue
            fi
            [[ -f "${bundle}" ]] || continue
            (( ${+seen[$bundle]} )) && continue
            seen[$bundle]=1
            bundles+=( "${bundle}" )
        done
    done

    logComment "CA bundles: ${#bundles}"

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Copy every certificate of a bundle (Parameter 1) to an output file (Parameter 2), together with the
# comment lines above it, except certificates whose SHA-256 is a target root
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function condaRemoveByFingerprint() {

    local pemFile="${1}"
    local outFile="${2}"
    local groupDir="${workDir}/groups.${bundleIndex}"
    local group fingerprint

    rm -Rf "${groupDir}"
    mkdir -p "${groupDir}" || return 2

    # Each group: the lines after the previous certificate, through this certificate's END line;
    # anything after the last certificate is kept as "trailer"
    awk -v dir="${groupDir}" '
        { buffer = buffer $0 "\n" }
        /^-----END CERTIFICATE-----/ { n++; file = sprintf("%s/%05d.grp", dir, n); printf "%s", buffer > file; close(file); buffer = "" }
        END { printf "%s", buffer > (dir "/trailer") }
    ' "${pemFile}" || return 2

    : > "${outFile}"
    for group in "${groupDir}"/*.grp(N); do
        fingerprint=$( certFingerprint "${group}" ) || return 2
        (( ${+targetRoots[$fingerprint]} )) && continue
        cat "${group}" >> "${outFile}" || return 2
    done
    cat "${groupDir}/trailer" >> "${outFile}" || return 2

    [[ -s "${outFile}" ]] || return 2

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Build the cleaned copy of a bundle (Parameter 1) and confirm it equals the original minus only the
# target roots
# Requires: bundleStatus of the bundle written to ${workDir}/original.${bundleIndex}.txt
# Sets: candidateFile
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function condaPrepareCandidate() {

    local bundle="${1}"
    local originalFingerprints="${workDir}/original.${bundleIndex}.txt"
    local expectedFingerprints="${workDir}/expected.${bundleIndex}.txt"
    local candidateFingerprints="${workDir}/candidate.${bundleIndex}.txt"
    local targetList="${workDir}/targets.txt"
    local candidateCount expectedCount

    candidateFile="${workDir}/cleaned.${bundleIndex}.pem"

    # Expected = original minus every target root
    print -l -- ${(k)targetRoots} > "${targetList}"
    grep -vxF -f "${targetList}" "${originalFingerprints}" > "${expectedFingerprints}"

    if ! condaRemoveByFingerprint "${bundle}" "${candidateFile}"; then
        errorOut "Removal by fingerprint failed"
        return 2
    fi

    if ! listFingerprints "${candidateFile}" "${candidateFingerprints}"; then
        errorOut "Cleaned bundle contains no certificates or a certificate that does not parse"
        return 2
    fi

    candidateCount=$( wc -l < "${candidateFingerprints}" | tr -d ' ' )
    expectedCount=$(( bundleCount - targetsPresent ))
    logComment "Cleaned bundle: ${candidateCount} certificates (expected ${expectedCount})"

    if grep -qxF -f "${targetList}" "${candidateFingerprints}"; then
        errorOut "A target root is still in the cleaned bundle"
        return 2
    fi

    if (( candidateCount != expectedCount )); then
        errorOut "Certificate count mismatch"
        return 2
    fi

    if ! cmp -s "${expectedFingerprints}" "${candidateFingerprints}"; then
        errorOut "Cleaned bundle removed or changed certificates other than the target roots"
        return 2
    fi

    logComment "Cleaned bundle validated: only the target roots were removed"

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Offline verification of the cleaned bundle; returns 0 only when it refuses the leaked chain
# Sets: offlineResult
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function condaVerifyCandidate() {

    offlineVerify "${candidateFile}"

    case "${offlineResult}" in
        refused      ) return 0 ;;
        trusted      ) errorOut "Cleaned bundle still verifies a leaked intermediate"; return 1 ;;
        *            ) errorOut "Offline verification of cleaned bundle inconclusive"; return 2 ;;
    esac

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Network test of the cleaned bundle (--cacert) before installing it; confirmation only
# Parameter 1: the original bundle (positive control when the cleaned one fails)
# Sets: candidateVerdict (confirmed | unconfirmed | network-unusable); returns 2 on a contradiction
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function condaTestCandidate() {

    local bundle="${1}"

    networkProbe "${candidateFile}"

    trustTest "${controlURL}" "${candidateFile}"
    if [[ "${trustResult}" != "trusted" ]]; then
        # Control failed: cleaned bundle broke normal TLS, or the network is unusable / intercepted
        trustTest "${controlURL}" "${bundle}"
        if [[ "${trustResult}" == "trusted" ]]; then
            errorOut "Cleaned bundle fails ${controlURL} but the original passes"
            return 2
        fi
        candidateVerdict="network-unusable"
    elif [[ "${networkResult}" == "trusted" ]]; then
        errorOut "Contradiction: cleaned bundle refuses the leaked chain offline, but curl trusts ${testServerName} with it"
        return 2
    elif [[ "${networkResult}" == "refused" ]]; then
        candidateVerdict="confirmed"
    else
        candidateVerdict="unconfirmed"
    fi

    logComment "Cleaned bundle network verdict: ${candidateVerdict}"
    [[ "${candidateVerdict}" != "confirmed" ]] && warning "Network confirmation unavailable (${candidateVerdict}); relying on offline verification"

    return 0

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Timestamped, verified backup of a bundle (Parameter 1); never overwrites
# Sets: backupFile
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function condaBackupBundle() {

    local bundle="${1}"

    backupFile="${bundle}.bak.$( date +%Y%m%d-%H%M%S )"

    if [[ -e "${backupFile}" ]]; then
        errorOut "Backup ${backupFile} already exists; refusing to overwrite"
        return 2
    fi

    if ! cp -p "${bundle}" "${backupFile}" || ! cmp -s "${bundle}" "${backupFile}"; then
        errorOut "Unable to create verified backup ${backupFile}"
        return 2
    fi

    logComment "Backup: ${backupFile}"

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Atomically install a file (Parameter 1) as Parameter 2: stage in the same directory, copy the
# destination's owner and mode (the source's when the destination is missing), then rename over it
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function condaInstallFile() {

    local sourceFile="${1}"
    local destinationFile="${2}"
    local referenceFile="${destinationFile}"
    local owner mode

    [[ -f "${referenceFile}" ]] || referenceFile="${sourceFile}"
    owner=$( stat -f '%u:%g' "${referenceFile}" ) || return 2
    mode=$( stat -f '%Lp' "${referenceFile}" ) || return 2

    stagedFile=$( mktemp "${destinationFile:h}/.${destinationFile:t}.XXXXXX" ) || return 2

    if cp "${sourceFile}" "${stagedFile}" \
        && chmod "${mode}" "${stagedFile}" \
        && chown "${owner}" "${stagedFile}" \
        && mv -f "${stagedFile}" "${destinationFile}"; then
        stagedFile=""
    else
        errorOut "Unable to install ${sourceFile} as ${destinationFile}"
        return 2
    fi

    if ! cmp -s "${sourceFile}" "${destinationFile}"; then
        errorOut "${destinationFile} does not match ${sourceFile} after install"
        return 2
    fi

    logComment "Installed: $( stat -f '%Sp %Su:%Sg' "${destinationFile}" ) ${destinationFile}"

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Roll back a bundle (Parameter 1) to backupFile
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function condaRollBack() {

    local bundle="${1}"

    warning "Rolling back ${bundle} to ${backupFile}"
    if condaInstallFile "${backupFile}" "${bundle}"; then
        logComment "Rolled back; ${bundle} matches ${backupFile}"
    else
        errorOut "ROLLBACK FAILED; restore manually: sudo cp -p '${backupFile}' '${bundle}'"
    fi

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Status of one bundle (Parameter 1): bundleStatus, offlineVerify and (optionally) networkProbe
# Sets: bundleVerdict (safe | exposed | unknown)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function condaInspectBundle() {

    local bundle="${1}"

    (( bundleIndex += 1 ))
    networkResult="disabled"

    if ! bundleStatus "${bundle}" "${workDir}/original.${bundleIndex}.txt"; then
        bundleVerdict="unknown"
        return 2
    fi
    offlineVerify "${bundle}"
    [[ "${networkTest}" == "on" ]] && networkProbe "${bundle}"

    if [[ "${bundleState}" == "exposed" || "${offlineResult}" == "trusted" ]]; then
        bundleVerdict="exposed"
    elif [[ "${offlineResult}" != "refused" ]]; then
        bundleVerdict="unknown"
    elif [[ "${networkResult}" == "trusted" ]]; then
        errorOut "Contradiction: leaked chain refused offline, but curl trusts ${testServerName} with ${bundle}"
        bundleVerdict="unknown"
    else
        bundleVerdict="safe"
    fi

    logComment "${bundle}: ${bundleVerdict}"

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Final verdict from the tallies; Parameter 1 is the summary when safe
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function condaReportVerdict() {

    if (( exposedCount > 0 )); then
        exitWith 1 "EXPOSED: ${exposedCount} of ${#bundles} conda CA bundle(s) still trust the leaked chain"
    elif (( unknownCount > 0 )); then
        exitWith 2 "Couldn't tell or refused for ${unknownCount} of ${#bundles} conda CA bundle(s)"
    else
        exitWith 0 "${1}"
    fi

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Mode: --check (read-only)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function condaCheckMode() {

    local bundle

    for bundle in "${bundles[@]}"; do
        notice "Check: ${bundle}"
        condaInspectBundle "${bundle}"
        case "${bundleVerdict}" in
            exposed ) (( exposedCount += 1 )) ;;
            unknown ) (( unknownCount += 1 )) ;;
        esac
    done

    condaReportVerdict "SAFE: ${#bundles} conda CA bundle(s) hold no target roots and refuse the leaked chain"

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Mode: --dry-run (build and verify cleaned copies in workDir; install nothing)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function condaDryRunMode() {

    local bundle
    local wouldFix=0

    for bundle in "${bundles[@]}"; do

        notice "Dry run: ${bundle}"
        condaInspectBundle "${bundle}"
        case "${bundleVerdict}" in
            safe    ) logComment "Nothing to remove"; continue ;;
            unknown ) (( unknownCount += 1 )); continue ;;
        esac
        if [[ "${bundleState}" != "exposed" ]]; then
            errorOut "Leaked chain verifies, but no target root is present; not a case this script fixes"
            (( unknownCount += 1 ))
            continue
        fi

        if ! condaPrepareCandidate "${bundle}" || ! condaVerifyCandidate; then
            (( unknownCount += 1 ))
            continue
        fi
        if [[ "${networkTest}" == "on" ]] && ! condaTestCandidate "${bundle}"; then
            (( unknownCount += 1 ))
            continue
        fi

        (( wouldFix += 1 ))
        logComment "Fix would install the cleaned bundle: ${bundleCount} -> $(( bundleCount - targetsPresent )) certificates"

    done

    if (( unknownCount > 0 )); then
        exitWith 2 "Dry run: fix would refuse or couldn't tell for ${unknownCount} of ${#bundles} conda CA bundle(s)"
    fi
    exitWith 0 "Dry run complete: fix would clean ${wouldFix} of ${#bundles} conda CA bundle(s)"

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Mode: fix (default)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function condaFixMode() {

    local bundle
    local fixed=0

    for bundle in "${bundles[@]}"; do

        notice "Fix: ${bundle}"
        condaInspectBundle "${bundle}"
        case "${bundleVerdict}" in
            safe    ) logComment "Already clean; no changes made"; continue ;;
            unknown ) (( unknownCount += 1 )); continue ;;
        esac
        if [[ "${bundleState}" != "exposed" ]]; then
            errorOut "Leaked chain verifies, but no target root is present; not a case this script fixes"
            (( exposedCount += 1 ))
            continue
        fi

        notice "Build and verify cleaned bundle"
        if ! condaPrepareCandidate "${bundle}" || ! condaVerifyCandidate; then
            errorOut "Cleaned bundle failed validation; no changes made"
            (( unknownCount += 1 ))
            continue
        fi
        if [[ "${networkTest}" == "on" ]] && ! condaTestCandidate "${bundle}"; then
            errorOut "Network test refused the cleaned bundle; no changes made"
            (( unknownCount += 1 ))
            continue
        fi

        notice "Install cleaned bundle"
        if ! condaBackupBundle "${bundle}"; then
            errorOut "No verified backup; no changes made"
            (( unknownCount += 1 ))
            continue
        fi
        if ! condaInstallFile "${candidateFile}" "${bundle}"; then
            condaRollBack "${bundle}"
            (( unknownCount += 1 ))
            continue
        fi

        notice "Verify installed bundle offline"
        if ! bundleStatus "${bundle}" "${workDir}/installed.${bundleIndex}.txt"; then
            condaRollBack "${bundle}"
            (( unknownCount += 1 ))
            continue
        fi
        offlineVerify "${bundle}"
        if [[ "${bundleState}" == "exposed" || "${offlineResult}" != "refused" ]]; then
            condaRollBack "${bundle}"
            (( exposedCount += 1 ))
            continue
        fi

        (( fixed += 1 ))
        logComment "FIXED: ${bundle} (backup: ${backupFile})"

    done

    condaReportVerdict "FIXED: cleaned ${fixed} of ${#bundles} conda CA bundle(s); the rest needed no change"

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Mode: --restore (each bundle's newest backup)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function condaRestoreMode() {

    local bundle
    local -a backups
    local restored=0

    for bundle in "${bundles[@]}"; do

        (( bundleIndex += 1 ))

        # Newest by name; "cp -p" keeps the original's mtime, so mtime can't be used
        backups=( "${bundle}".bak.*(N.On) )
        if (( ${#backups} == 0 )); then
            logComment "No backup for ${bundle}; no changes made"
            continue
        fi
        backupFile="${backups[1]}"

        notice "Restore: ${bundle} from ${backupFile}"
        if [[ -L "${backupFile}" ]] || ! bundleStatus "${backupFile}" "${workDir}/backup.${bundleIndex}.txt"; then
            errorOut "${backupFile} is damaged; refusing to restore it"
            (( unknownCount += 1 ))
            continue
        fi

        if [[ -f "${bundle}" ]] && cmp -s "${backupFile}" "${bundle}"; then
            logComment "${bundle} already matches ${backupFile}; no changes made"
            continue
        fi

        if condaInstallFile "${backupFile}" "${bundle}"; then
            (( restored += 1 ))
        else
            (( unknownCount += 1 ))
        fi

    done

    if (( unknownCount > 0 )); then
        exitWith 2 "Restore incomplete for ${unknownCount} of ${#bundles} conda CA bundle(s)"
    fi
    exitWith 0 "Restored ${restored} of ${#bundles} conda CA bundle(s) from their newest backup"

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Usage
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function usage() {
    cat <<EOF
Usage: ${ZSH_ARGZERO:t} [--fix | --check | --dry-run | --restore [backup]] [--offline] [--cert-pem-only | --conda-only] | --help

  --fix (default)     Remove the two roots from ${certFile} and every conda CA bundle (requires root)
  --check             Report status only; no changes (root to include other users' conda installs)
  --dry-run           Build and verify cleaned copies; install nothing
  --restore [backup]  Restore the newest (or specified) ${certFile}.bak.* and each conda bundle's
                      newest .bak.* (requires root)
  --offline           Skip the network test (local runs include it by default)
  --cert-pem-only     Only ${certFile}
  --conda-only        Only the conda CA bundles

Jamf Pro:
  Parameter 4         Operation Mode [ fix (default) | check | dry-run | restore ]
  Parameter 5         ${certFile} backup to restore (optional; defaults to newest)
  Parameter 6         Network Test [ off (default) | on ]
  Parameter 7         Test URL (optional; defaults to ${defaultTestURL})
  Parameter 8         Scope [ all (default) | cert.pem | conda ]

Exit codes: 0 = safe / fixed; 1 = still exposed; 2 = couldn't tell / refused (the worst of the parts)
EOF
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Work directory and offline probes for one part; each part's subshell sets "trap cleanUp EXIT" at
# its top level (a trap set in a function would fire as soon as the function returns)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function prepareWorkDir() {

    workDir=$( mktemp -d -t "${organizationScriptName}" ) || fatal "Unable to create work directory; exiting."

    writeProbes || fatal "Embedded offline probes failed verification; exiting."

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Part: /etc/ssl/cert.pem (Dan K. Snelson's Remediate-cert.pem-eMudhra.zsh, 0.0.4); run in a
# subshell, it exits with that script's exit code
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function remediateCertPem() {

    # certFile must be a regular file, not a symlink (restore may recreate a missing one)
    if [[ -L "${certFile}" ]]; then
        fatal "${certFile} is a symlink; refusing to continue."
    elif [[ "${operationMode}" != "restore" ]] && [[ ! -f "${certFile}" || ! -r "${certFile}" ]]; then
        fatal "${certFile} is missing or unreadable; refusing to continue."
    fi

    prepareWorkDir

    case "${operationMode}" in
        check   ) checkMode ;;
        dry-run ) dryRunMode ;;
        restore ) restoreMode ;;
        *       ) fixMode ;;
    esac

    # Every mode exits via exitWith; reaching here is unexpected
    exitWith 2 "Unexpected end of the cert.pem part"

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Part: conda CA bundles (Remediate-conda-eMudhra.zsh, 0.0.2); run in a subshell, it exits with that
# script's exit code
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function remediateConda() {

    prepareWorkDir

    notice "Discover conda installs"
    discoverPrefixes
    (( ${#prefixes} > 0 )) || exitWith 0 "No conda installs found"

    discoverBundles
    (( ${#bundles} > 0 )) || exitWith 0 "No CA bundles found in ${#prefixes} conda prefix(es)"

    case "${operationMode}" in
        check   ) condaCheckMode ;;
        dry-run ) condaDryRunMode ;;
        restore ) condaRestoreMode ;;
        *       ) condaFixMode ;;
    esac

    # Every mode exits via exitWith; reaching here is unexpected
    exitWith 2 "Unexpected end of the conda part"

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# One part's exit code (Parameter 1) in words, or "skipped" when the part didn't run
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function partSummary() {

    if [[ -z "${1}" ]]; then
        echo "skipped"
    else
        echo "${exitMeaning[$1]:-unexpected} (exit ${1})"
    fi

}

####################################################################################################
#
# Pre-flight Checks
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Parameters
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Local runs pass no arguments or an option (e.g., --check) first; Jamf Pro runs pass Parameters 1–3
# (mount point, computer name, username), so the Operation Mode comes from Parameter 4
if [[ $# -eq 0 || "${1}" == -* ]]; then
    if [[ $# -eq 0 ]]; then
        parameterSource="local (default)"
    else
        parameterSource="local option"
    fi
    operationMode="${1:-"--fix"}"
    operationMode="${(L)operationMode#--}"
    restoreSource=""
    networkTest="on"
    testURL="${defaultTestURL}"
    remediationScope="all"
    (( $# > 0 )) && shift
    for localArgument in "$@"; do
        if [[ "${localArgument}" == "--offline" ]]; then
            networkTest="off"
        elif [[ "${localArgument}" == "--cert-pem-only" ]]; then
            remediationScope="cert.pem"
        elif [[ "${localArgument}" == "--conda-only" ]]; then
            remediationScope="conda"
        elif [[ "${operationMode}" == "restore" && -z "${restoreSource}" && "${localArgument}" != -* ]]; then
            restoreSource="${localArgument}"
        else
            usage >&2
            exit 2
        fi
    done
elif [[ -n "${4}" ]]; then
    parameterSource="Jamf Pro Parameter 4"
else
    parameterSource="Jamf Pro (default)"
fi

# Accept "check", "Check" or "--check" from either source
operationMode="${(L)operationMode//[[:space:]]/}"
operationMode="${operationMode#--}"
networkTest="${(L)networkTest//[[:space:]]/}"
remediationScope="${(L)remediationScope//[[:space:]]/}"

case "${operationMode}" in
    fix | check | dry-run | restore ) ;;
    -h | help                       ) usage; exit 0 ;;
    *                               ) echo "Invalid Operation Mode: '${operationMode}'" >&2; usage >&2; exit 2 ;;
esac

case "${networkTest}" in
    on | off ) ;;
    *        ) echo "Invalid Network Test: '${networkTest}'" >&2; usage >&2; exit 2 ;;
esac

case "${remediationScope}" in
    all | cert.pem | conda ) ;;
    *                      ) echo "Invalid Scope: '${remediationScope}'" >&2; usage >&2; exit 2 ;;
esac

# Test URL: https only; its host (and optional port) drive the served-chain inspection
if [[ "${testURL}" != https://?* ]]; then
    echo "Invalid Test URL: '${testURL}'" >&2
    usage >&2
    exit 2
fi
testHost="${${testURL#https://}%%/*}"
testServerName="${testHost%%:*}"
if [[ "${testHost}" == *:* ]]; then
    testConnect="${testHost}"
else
    testConnect="${testHost}:443"
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Client-side Logging
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ ! -f "${scriptLog}" && $(id -u) -eq 0 ]]; then
    touch "${scriptLog}"
    if [[ -f "${scriptLog}" ]]; then
        preFlight "Created specified scriptLog: ${scriptLog}"
    else
        fatal "Unable to create specified scriptLog '${scriptLog}'; exiting."
    fi
elif [[ -w "${scriptLog}" ]]; then
    preFlight "Specified scriptLog '${scriptLog}' exists; writing log entries to it"
else
    preFlight "Specified scriptLog '${scriptLog}' not writable; logging to stdout only"
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Logging Preamble
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

preFlight "\n\n###\n# $humanReadableScriptName (${scriptVersion})\n###\n"
preFlight "Initiating …"
preFlight "Operation Mode: ${operationMode} (${parameterSource})"
preFlight "Scope: ${remediationScope}"
if [[ "${networkTest}" == "on" ]]; then
    preFlight "Network Test: on (${testURL}; control ${controlURL})"
else
    preFlight "Network Test: off"
fi
preFlight "macOS $( sw_vers -productVersion ) ($( sw_vers -buildVersion ))"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Confirm script is running as root (fix and restore only)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ "${operationMode}" == "fix" || "${operationMode}" == "restore" ]] && [[ $(id -u) -ne 0 ]]; then
    fatal "Mode '${operationMode}' must be run as root; exiting."
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Required tools
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

command -v openssl > /dev/null 2>&1 || fatal "openssl not found; exiting."
if [[ "${networkTest}" == "on" && ! -x /usr/bin/curl ]]; then
    fatal "/usr/bin/curl not found; exiting."
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Complete
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

preFlight "Complete!"



####################################################################################################
#
# Program
#
####################################################################################################

typeset -A exitMeaning
exitMeaning=( 0 "safe / fixed" 1 "still exposed" 2 "couldn't tell / refused" )

# Each part runs in its own subshell: its own work directory (removed by the subshell's EXIT trap)
# and exit code; one part failing never stops the other
if [[ "${remediationScope}" != "conda" ]]; then
    notice "Part: ${certFile} (Remediate-cert.pem-eMudhra.zsh 0.0.4)"
    ( trap cleanUp EXIT; remediateCertPem )
    certPemRC=$?
fi

if [[ "${remediationScope}" != "cert.pem" ]]; then
    notice "Part: conda CA bundles (Remediate-conda-eMudhra.zsh 0.0.2)"
    ( trap cleanUp EXIT; remediateConda )
    condaRC=$?
fi

# The worst of the parts: 1 (still exposed), then 2 (couldn't tell / refused), then 0
overallRC=0
for partRC in ${certPemRC} ${condaRC}; do
    if (( partRC == 1 )); then
        overallRC=1
    elif (( partRC != 0 && overallRC == 0 )); then
        overallRC=2
    fi
done

exitWith "${overallRC}" "cert.pem: $( partSummary "${certPemRC}" ); conda: $( partSummary "${condaRC}" )"
