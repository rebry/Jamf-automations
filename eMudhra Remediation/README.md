# eMudhra Remediation for macOS (Jamf Pro)

Removes the two roots the leaked eMudhra intermediates chain to, *emSign ECC Root CA - G3* and
*AAA Certificate Services*, from the CA bundles conda ships with.

This code is heavily inspired by Dan K. Snelson's fix for Apple's built-in tools like curl:
[Dan K. Snelson's cert.pem fix](https://snelson.us/2026/10/remediating-emudhras-private-key-compromise-with-jamf-pro/)

I used Claude to download different versions of conda into Tart VMs to verify that it could also fix
other versions of conda, like conda, Anaconda, Miniforge, Mambaforge, micromamba and pixi, in the
home folder, in `/opt` or as Homebrew casks.

| Solution | Script | Extension Attribute |
|---|---|---|
| **Combined** (recommended): cert.pem + conda | `Combined Remediation/Remediation Script/Remediate-eMudhra.zsh` | `Combined Remediation/Extention attribute/eMudhra-Status-EA.zsh` |
| **Conda only**: next to Snelson's script | `Conda Remediation/Remediate-conda-eMudhra.zsh` | `Conda Remediation/conda-eMudhra-Status-EA.zsh` |

## Jamf Pro

1. **Extension Attribute:** data type *String*, input type *Script*, named *eMudhra Status*.
2. **Script:** add the parameter labels from the table below.
3. **Smart group:** *eMudhra Status* **like** `Exposed`.
4. **Policy:**
   - Script with Parameter 4 = `fix` and the network test `off` (Parameter 6 combined, Parameter 5
     conda only).
   - *Maintenance → Update Inventory* turned on.
   - *Recurring Check-in*, *Once every day*, scoped to the smart group.
5. **PPPC:** Full Disk Access for the Jamf agent, so pixi workspaces in Desktop, Documents and
   Downloads are found.

Running daily re-applies the fix after macOS updates and new conda environments. I would recommend a
`dry-run` on a pilot group first.

| Parameter | Combined | Conda only |
|---|---|---|
| 4 | Operation Mode: `fix` (default), `check`, `dry-run`, `restore` | Same |
| 5 | cert.pem backup to restore (optional) | Network Test: `off` (default), `on` |
| 6 | Network Test: `off` (default), `on` | — |
| 7 | Test URL (optional) | — |
| 8 | Scope: `all` (default), `cert.pem`, `conda` | — |

## Results

- **Exit codes:** 0 = safe or fixed, 1 = still exposed, 2 = couldn't tell or refused.
- **EA:** `Remediated`, `Exposed`, `Not Installed` (conda only), `Damaged` or `Unknown`. The
  combined EA shows the worst of the two first, e.g. `Exposed (cert.pem: Remediated, conda: Exposed)`.
- **`Damaged`** means a CA bundle is missing, empty or holds a certificate that doesn't parse, like a
  company CA pasted in the wrong format.
- **`Unknown`** means the check itself couldn't run, like a missing `openssl` or a verify result
  that's neither OK nor refused.
- **Logs:**
  - combined: `/var/log/Remediate-eMudhra.log`
  - conda only: `/var/log/Remediate-conda-eMudhra.log`
- **Backups:** `<file>.bak.<timestamp>` next to each changed file. Parameter 4 = `restore` puts them
  back.

## Credits

The cert.pem part, the offline probes and the script structure are by
[Dan K. Snelson](https://snelson.us/2026/10/remediating-emudhras-private-key-compromise-with-jamf-pro/).

Test in a pilot group first, and use at your own risk. ;) 
