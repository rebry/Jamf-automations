#!/bin/zsh --no-rcs

####################################################################################################
#
# conda eMudhra Status
#
#   Purpose: Reports whether the CA bundles of conda installs (conda, mamba, micromamba and pixi
#            environments) still trust the leaked eMudhra intermediates
#
#   Jamf Pro Extension Attribute Data Type: String
#
#   Results: Not Installed  No conda prefix with a CA bundle found
#            Remediated     In every bundle, neither target root present and both leaked
#                           intermediates refused
#            Exposed        In any bundle, a target root present or a leaked intermediate still
#                           verifies
#            Damaged        A bundle unreadable, empty or holding an unparsable certificate (and none
#                           exposed)
#            Unknown        openssl missing, an embedded probe altered, an unexpected verify result or
#                           any other failure
#
####################################################################################################
#
# HISTORY
#
# Version 0.0.1, 23-Oct-2026, Per Kristian Thorsen
#   - Original version; discovery and bundles from Remediate-conda-eMudhra.zsh (0.0.2), probes and
#     verification from Dan K. Snelson's cert.pem eMudhra Status (0.0.1)
#
####################################################################################################

####################################################################################################
#
# Variables
#
####################################################################################################

export PATH=/usr/bin:/bin:/usr/sbin:/sbin

# Jamf Pro reads only stdout; discard all stderr
exec 2>/dev/null

opensslBinary="/usr/bin/openssl"

# Offline verification time (21-Oct-2026 00:00:00 UTC), pinned so certificate expiry never changes
# the verdict; LibreSSL's openssl verify has -attime, but not -no_check_time
verifyEpoch="1792540800"

# SHA-256 fingerprints of the roots to remove (uppercase hex, no colons)
typeset -A targetRoots
targetRoots=(
    D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4 "AAA Certificate Services"
    86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B "emSign ECC Root CA - G3"
)

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Conda locations (as in Remediate-conda-eMudhra.zsh)
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

# Bundle counter (names each bundle's work files) and verdicts by bundle content (SHA-256)
bundleIndex="0"
typeset -A verdictByContent

####################################################################################################
#
# Functions
#
####################################################################################################

# Emit exactly one Jamf Pro Extension Attribute result, then stop.
function printResult() {
    /usr/bin/printf '<result>%s</result>\n' "${1}"
    exit 0
}

# Remove the work directory (the only place this script writes).
function cleanUp() {
    [[ -n "${workDir}" && -d "${workDir}" ]] && /bin/rm -Rf "${workDir}"
}

# Split every PEM certificate block in a file (Parameter 1) into its own file in a directory
# (Parameter 2)
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

# SHA-256 fingerprint (uppercase hex, no colons) of a single-certificate PEM file (Parameter 1)
function certFingerprint() {

    local fingerprint

    fingerprint=$( "${opensslBinary}" x509 -noout -fingerprint -sha256 -in "${1}" 2>/dev/null ) || return 2
    fingerprint="${${fingerprint#*=}//:/}"
    fingerprint="${(U)fingerprint}"
    [[ "${fingerprint}" =~ ^[0-9A-F]{64}$ ]] || return 2
    echo "${fingerprint}"

}

# Write sorted SHA-256 fingerprints of every parsed certificate in a PEM bundle (Parameter 1) to an
# output file (Parameter 2); returns 2 if any block fails to parse or the bundle holds none
function listFingerprints() {

    local pemFile="${1}"
    local outFile="${2}"
    local splitDir="${workDir}/split.${outFile:t}"
    local -a blocks
    local block

    # Fingerprint the PEM data itself, not the "# Issuer:" header text
    splitPEM "${pemFile}" "${splitDir}" || return 2
    blocks=( "${splitDir}"/*.pem(N) )
    (( ${#blocks} > 0 )) || return 2

    # Fast path: one LibreSSL interactive-mode process fingerprints every block (one fork per block
    # costs ~13 ms, ~2 s per bundle); relative names, as interactive mode splits on whitespace
    (
        cd "${splitDir}" || exit 2
        for block in "${blocks[@]:t}"; do
            print -r -- "x509 -noout -fingerprint -sha256 -in ${block}"
        done | "${opensslBinary}"
    ) | /usr/bin/grep -oE 'SHA256 Fingerprint=([0-9A-F]{2}:){31}[0-9A-F]{2}' \
      | /usr/bin/sed -e 's/^.*=//' -e 's/://g' > "${outFile}"

    # Fallback unless the fast path returned exactly one fingerprint per block (e.g., OpenSSL 3 has
    # no interactive mode, or a block failed to parse): one fork per block, which then decides
    # whether the bundle is damaged
    if (( $( /usr/bin/wc -l < "${outFile}" ) != ${#blocks} )); then
        : > "${outFile}"
        for block in "${blocks[@]}"; do
            certFingerprint "${block}" >> "${outFile}" || return 2
        done
    fi

    [[ -s "${outFile}" ]] || return 2
    sort -o "${outFile}" "${outFile}"

}

# Write the embedded offline probes to workDir and confirm each matches its pinned fingerprint
function writeProbes() {

    local probe fingerprint

    for probe in ${(k)probeFingerprints}; do
        print -r -- "${probePEMs[$probe]}" > "${workDir}/probe.${probe}.pem"
        fingerprint=$( certFingerprint "${workDir}/probe.${probe}.pem" )
        [[ "${fingerprint}" == "${probeFingerprints[$probe]}" ]] || return 2
    done

}

# Offline verification of a bundle (Parameter 1) against the embedded leaked intermediates
# Sets: offlineResult (trusted | refused | inconclusive)
function offlineVerify() {

    local bundle="${1}"
    local probe verifyOutput verifyRC refusal
    local probesTrusted=0
    local probesRefused=0

    for probe in ${(k)probeFingerprints}; do
        verifyOutput=$( "${opensslBinary}" verify -attime "${verifyEpoch}" -CAfile "${bundle}" "${workDir}/probe.${probe}.pem" 2>&1 )
        verifyRC=$?
        # "error 20" / "error 2": no path from the probe to a trust anchor in the bundle
        refusal=$( print -r -- "${verifyOutput}" | grep -m1 -E '^error (2|20) at ' )
        if [[ ${verifyRC} -eq 0 && "${verifyOutput}" == *": OK" ]]; then
            (( probesTrusted += 1 ))
        elif [[ -n "${refusal}" ]]; then
            (( probesRefused += 1 ))
        fi
    done

    if (( probesTrusted > 0 )); then
        offlineResult="trusted"
    elif (( probesRefused == ${#probeFingerprints} )); then
        offlineResult="refused"
    else
        offlineResult="inconclusive"
    fi

}

# Roots named by the init blocks in a home folder's (Parameter 1) shell startup files: the prefix of
# the conda that "conda init" wires up, and micromamba's / mamba's MAMBA_ROOT_PREFIX; one per line
function shellInitRoots() {

    local home="${1}"
    local startupFile root

    for startupFile in "${home}/"${^shellStartupFiles}; do
        [[ -f "${startupFile}" && ! -L "${startupFile}" ]] || continue
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

# Conda prefixes: base installs and their environments, for every local user when run as root
# (otherwise the current user); a prefix must hold conda-meta
# Sets: prefixes (real paths, deduplicated)
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

}

# CA bundles in the discovered prefixes: ssl/cacert.pem (and ssl/cert.pem), certifi's cacert.pem,
# pip's vendored copy and botocore's; symlinks are followed only within their prefix
# Sets: bundles (real paths, deduplicated)
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
            [[ "${bundle}" == "${prefix}/"* && -f "${bundle}" ]] || continue
            (( ${+seen[$bundle]} )) && continue
            seen[$bundle]=1
            bundles+=( "${bundle}" )
        done
    done

}

# Status of one bundle (Parameter 1); identical bundles (a cloned env, pip's copy in each env) are
# checked once
# Sets: bundleResult (Exposed | Damaged | Unknown | Remediated)
function bundleStatus() {

    local bundle="${1}"
    local contentHash

    contentHash=$( /usr/bin/shasum -a 256 "${bundle}" 2>/dev/null ) && contentHash="${contentHash%% *}"
    # (+): 1 when the key exists
    if [[ -n "${contentHash}" ]] && (( ${+verdictByContent[$contentHash]} )); then
        bundleResult="${verdictByContent[$contentHash]}"
        return
    fi

    bundleVerdict "${bundle}"
    [[ -n "${contentHash}" ]] && verdictByContent[$contentHash]="${bundleResult}"

}

# Verdict for one bundle (Parameter 1)
# Sets: bundleResult (Exposed | Damaged | Unknown | Remediated)
function bundleVerdict() {

    local bundle="${1}"
    local fingerprintFile="${workDir}/bundle.$(( ++bundleIndex )).txt"
    local targetFingerprint

    if [[ ! -r "${bundle}" ]] || ! listFingerprints "${bundle}" "${fingerprintFile}"; then
        bundleResult="Damaged"
        return
    fi

    for targetFingerprint in ${(k)targetRoots}; do
        if /usr/bin/grep -qxF "${targetFingerprint}" "${fingerprintFile}"; then
            bundleResult="Exposed"
            return
        fi
    done

    offlineVerify "${bundle}"

    case "${offlineResult}" in
        trusted ) bundleResult="Exposed" ;;
        refused ) bundleResult="Remediated" ;;
        *       ) bundleResult="Unknown" ;;
    esac

}

####################################################################################################
#
# Status Check
#
####################################################################################################

[[ -x "${opensslBinary}" ]] || printResult "Unknown"

trap cleanUp EXIT
workDir=$( /usr/bin/mktemp -d -t "conda-eMudhra-Status" ) || printResult "Unknown"
[[ -d "${workDir}" ]] || printResult "Unknown"

writeProbes || printResult "Unknown"

discoverPrefixes
discoverBundles
(( ${#bundles} > 0 )) || printResult "Not Installed"

typeset -A verdictCount
verdictCount=( Exposed 0 Damaged 0 Unknown 0 Remediated 0 )
for bundle in "${bundles[@]}"; do
    bundleStatus "${bundle}"
    (( verdictCount[${bundleResult}] += 1 ))
done

# The worst verdict across all bundles
for verdict in Exposed Damaged Unknown; do
    (( verdictCount[${verdict}] > 0 )) && printResult "${verdict}"
done
printResult "Remediated"
