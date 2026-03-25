# Citrix NetScaler Triage

This repository contains triage and fingerprinting scripts for Citrix NetScaler devices.

> **Fork of [fox-it/citrix-netscaler-triage](https://github.com/fox-it/citrix-netscaler-triage)** with additional detection tools by [Black Lantern Security](https://www.blacklanternsecurity.com/).

## Tools

| Script | Description |
|--------|-------------|
| `citrix_detect.py` | **BLS** - Comprehensive version detection using 12 techniques with CVE assessment |
| `citrix_version_correlator.py` | **BLS** - Identify unknown fingerprints using public release dates (no Citrix account needed) |
| `scan-citrix-netscaler-version.py` | Fox-IT - Mass version scanner via GZIP timestamp fingerprinting |
| `iocitrix.py` | Fox-IT - Dissect-based IOC checker for forensic disk images |
| `extract-Stamp-From-TgzFile.py` | Fox-IT - Extract fingerprints from Citrix firmware .tgz packages |
| `nuclei-templates/` | **BLS** - Nuclei templates for detection, version fingerprinting, and CVE checks |
| `custom-fingerprints.csv` | **BLS** - Tracking file for newly discovered fingerprints |

---

# citrix_detect.py

A comprehensive Citrix NetScaler ADC/Gateway version detection and vulnerability assessment tool. Uses 12 detection techniques across 8 phases to identify and fingerprint NetScaler appliances.

## Detection Techniques

| Phase | Technique | Confidence | Source |
|-------|-----------|------------|--------|
| 1 | GZIP timestamp fingerprinting (`rdx_en.json.gz`) | HIGH | fox-it |
| 1 | MD5 vhash of GZIP file | HIGH | fox-it |
| 2 | Root URL headers, cookies, redirects | MEDIUM | - |
| 2 | `Last-Modified` header fingerprinting | MEDIUM | telekom-security |
| 2 | `Via: NS-CACHE-X.X` header version extraction | MEDIUM | WhatWeb/Nmap |
| 2 | `Cneonction`/`nnCoection` misspelled header detection | MEDIUM | wafw00f |
| 3 | Endpoint probing (11 known Citrix paths) | MEDIUM | - |
| 3 | `?v=<hash>` extraction from `index.html` | HIGH | securekomodo |
| 3 | EPA plugin version from `pluginlist.xml` | MEDIUM | securekomodo |
| 4 | Build-specific JavaScript version strings | LOW | - |
| 5 | EPA binary PE version metadata extraction | HIGH | kolbicz blog |
| 6 | Favicon MD5 fingerprinting (6 known hashes) | MEDIUM | rapid7/recog |
| 7 | Static file content hashing (MD5 + size) | MEDIUM | - |
| 8 | TLS certificate analysis (default Citrix cert, SANs) | MEDIUM | rapid7/recog |

## Fingerprint Database

- **237 GZIP timestamp fingerprints** (NetScaler 11.1 through 14.1, 2018-2025)
- **132 MD5 vhash fingerprints** for older builds
- **6 favicon MD5 hashes** from Rapid7 Recog
- **3 Last-Modified header timestamps** for known patched builds

## CVE Vulnerability Assessment

When run with `--cve`, checks detected versions against 6 CVEs across 3 Citrix advisories:

| CVE | Advisory | Description |
|-----|----------|-------------|
| CVE-2025-5349 | CTX693420 | CitrixBleed 2 - memory disclosure |
| CVE-2025-5777 | CTX693420 | CitrixBleed 2 - memory disclosure |
| CVE-2025-6543 | CTX694788 | Memory overflow (exploited in-the-wild) |
| CVE-2025-7775 | CTX694938 | Multiple vulnerabilities |
| CVE-2025-7776 | CTX694938 | Multiple vulnerabilities |
| CVE-2025-8424 | CTX694938 | Multiple vulnerabilities |

Includes FIPS/NDcPP build awareness (12.1-55.x and 13.1-37.x) and EOL detection.

## Installing `citrix_detect.py`

```shell
git clone https://github.com/blacklanternsecurity/citrix-netscaler-triage.git
cd citrix-netscaler-triage
pip install requests
python3 citrix_detect.py --help
```

## Usage

```shell
# Basic version detection
python3 citrix_detect.py https://vpn.example.com

# With CVE vulnerability assessment
python3 citrix_detect.py --cve https://vpn.example.com

# Custom timeout and user-agent
python3 citrix_detect.py -t 15 -a "Custom-Agent" --cve https://vpn.example.com
```

### Example Output

```
=================================================================
 SUMMARY
=================================================================

  Target: https://vpn.example.com
  [+] Citrix NetScaler DETECTED

  Best version match: 14.1-56.74
  Confidence: HIGH (GZIP timestamp fingerprint)

  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  CVE VULNERABILITY ASSESSMENT (version 14.1-56.74)
  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  [ok] CVE-2025-5349: Not affected
  [ok] CVE-2025-5777: Not affected
  [ok] CVE-2025-6543: Not affected
  [ok] CVE-2025-7775: Not affected
  [ok] CVE-2025-7776: Not affected
  [ok] CVE-2025-8424: Not affected

  >> No known CVEs affect this version.
```

When the GZIP timestamp is not in the database, the tool extrapolates from the nearest known version:

```
  Firmware build date: 2026-01-13 09:52:07 UTC
  GZIP timestamp: 1768297927 (not in fingerprint DB)
  Nearest older known version: 12.1-55.333 (63 days older)
  Likely version: newer than 12.1-55.333
  Confidence: MEDIUM (timestamp extrapolation)
```

Exit code is `0` if Citrix is detected, `1` if not.

---

# Nuclei Templates

Three Nuclei templates (v3+) are provided in `nuclei-templates/`:

| Template | Severity | Description |
|----------|----------|-------------|
| `citrix-netscaler-detect.yaml` | info | Product detection via multiple HTTP matchers |
| `citrix-netscaler-version.yaml` | info | Version fingerprinting via `flow: http() && code()` |
| `citrix-netscaler-cves.yaml` | high | CVE vulnerability assessment with FIPS/EOL awareness |

The version and CVE templates use the `code:` protocol with Python to perform GZIP timestamp extraction, so they require `nuclei` with code protocol support enabled.

## Usage

```shell
# Detection only
nuclei -t nuclei-templates/citrix-netscaler-detect.yaml -u https://vpn.example.com

# Version fingerprinting
nuclei -t nuclei-templates/citrix-netscaler-version.yaml -u https://vpn.example.com

# CVE assessment
nuclei -t nuclei-templates/citrix-netscaler-cves.yaml -u https://vpn.example.com

# All templates against a target list
nuclei -t nuclei-templates/ -l targets.txt
```

---

# citrix_version_correlator.py

Identifies unknown GZIP timestamps by correlating build dates with publicly available release dates from docs.netscaler.com and citrix.com/downloads. No Citrix account required.

Contains **188 version-to-release-date mappings** across all branches (14.1, 13.1, 13.0, 12.1, 11.1 + FIPS variants).

## How It Works

Citrix firmware is compiled days before its public GA release. The GZIP timestamp in `rdx_en.json.gz` reflects the compile date. By cross-referencing against known release dates, the tool narrows an unknown timestamp to 2-3 candidate versions.

## Usage

```shell
# Show compile-to-release offset statistics per branch
python3 citrix_version_correlator.py --stats

# Identify an unknown GZIP timestamp
python3 citrix_version_correlator.py --stamp 1768297927

# Scan a target and predict its version
python3 citrix_version_correlator.py --scan https://vpn.example.com

# Export merged database as CSV
python3 citrix_version_correlator.py --export
```

### Example Output

```
=================================================================
 Identifying timestamp 1768297927
 Build date: 2026-01-13 09:52:07 UTC
=================================================================

  Top candidates (by compile-to-release offset fit):

  #    Version          Branch       Release Date    Days Before
  ------------------------------------------------------------
  1    13.1-37.259      13.1-FIPS    2026-01-22            8.6d
  2    14.1-60.57       14.1         2026-01-20            6.6d
  3    13.1-61.26       13.1         2026-01-20            6.6d

  Best guess: 13.1-37.259 (released 2026-01-22)
```

Combined with other signals from `citrix_detect.py` (e.g., `Via: NS-CACHE` header, EPA plugin version, FIPS-specific endpoints), you can determine the exact version from the candidate list.

---

# Adding New Fingerprints

When `citrix_detect.py` reports a GZIP timestamp not in the database, you can identify it and add it:

### Step 1: Identify the version

Use one of these methods (no Citrix account required for the first two):

| Method | Requires Account? | How |
|--------|-------------------|-----|
| **Version correlator** | No | `python3 citrix_version_correlator.py --stamp <TIMESTAMP>` — narrows to 2-3 candidates using public release dates |
| **Release notes / forums** | No | Cross-reference build date against [docs.netscaler.com](https://docs.netscaler.com) release notes or Citrix Community forum posts |
| **Firmware extraction** | Yes (free account) | Download `.tgz` from support.citrix.com, run `python3 extract-Stamp-From-TgzFile.py <file.tgz>` |
| **Known running instance** | Admin access | Run `show ns version` on the CLI, then scan it to capture the fingerprint |

### Step 2: Add to the database

1. Add an entry to `custom-fingerprints.csv` with the source and notes
2. Add the CSV line to the embedded database in `scan-citrix-netscaler-version.py` (line ~47)
3. Add the CSV line to the embedded database in `citrix_detect.py`
4. Add the stamp to the Nuclei templates in `nuclei-templates/`

### Step 3: Update release date DB (optional)

If this is a newly released version not yet in the correlator, add it to the `RELEASE_DATES_CSV` in `citrix_version_correlator.py` so future correlations are more accurate.

---

# scan-citrix-netscaler-version.py

*From upstream [fox-it/citrix-netscaler-triage](https://github.com/fox-it/citrix-netscaler-triage)*

You can use this script to scan and determine the version of a Citrix NetScaler device over HTTP(s).
It will also determine if the NetScaler is vulnerable to specific CVEs based on the version.

## Installing `scan-citrix-netscaler-version.py`

Use the following steps if you are using pip:

1. git clone https://github.com/blacklanternsecurity/citrix-netscaler-triage.git
2. cd citrix-netscaler-triage
3. pip install httpx
4. python3 scan-citrix-netscaler-version.py --help

In case of [uv](https://docs.astral.sh/uv/), you can run the script directly using:

1. uv run https://raw.githubusercontent.com/blacklanternsecurity/citrix-netscaler-triage/refs/heads/main/scan-citrix-netscaler-version.py

Example usage:

```shell
$ python3 scan-citrix-netscaler-version.py 192.168.1.10 192.168.1.12
192.168.1.10 (*.local.domain) is running Citrix NetScaler version 13.1-51.15 (VULNERABLE)
192.168.1.12 (*.local.domain) is running Citrix NetScaler version 12.1-55.330 (NOT VULNERABLE)
```

Or get the results in JSON:

```shell
$ python3 scan-citrix-netscaler-version.py https://192.168.1.11 --json | jq
```
```json
{
  "scanned_at": "2025-09-03T23:11:36.864228+00:00",
  "target": "https://192.168.1.11",
  "tls_names": "my-first-netscaler.local",
  "rdx_en_stamp": 1702886392,
  "rdx_en_dt": "2023-12-18T07:59:52+00:00",
  "version": "12.1-55.302",
  "error": null,
  "vulnerable": {
    "CVE-2025-5349": true,
    "CVE-2025-5777": true,
    "CVE-2025-6543": false,
    "CVE-2025-7775": true,
    "CVE-2025-7776": true,
    "CVE-2025-8424": true
  },
  "is_vulnerable": true
}
```

It's also possible to limit vulnerability status checks to specific CVEs by using the `--cve` flag:

```shell
$ python3 scan-citrix-netscaler-version.py https://192.168.1.11 --cve CVE-2025-6543 --json | jq
```
```json
{
  "scanned_at": "2025-09-03T23:16:36.573016+00:00",
  "target": "https://192.168.1.11",
  "tls_names": "my-first-netscaler.local",
  "rdx_en_stamp": 1702886392,
  "rdx_en_dt": "2023-12-18T07:59:52+00:00",
  "version": "12.1-55.302",
  "error": null,
  "vulnerable": {
    "CVE-2025-6543": false
  },
  "is_vulnerable": false
}
```

To get the results in CSV format, just use the `--csv` flag.
For more options see `--help`.

# iocitrix.py

*From upstream [fox-it/citrix-netscaler-triage](https://github.com/fox-it/citrix-netscaler-triage)*

You can use `iocitrix.py` to check for known Indicators of Compromise on a NetScaler Dissect target. It checks for the following things:

* Known strings used in webshells
* Timestomped files
* Suspicious cronjobs
* Unknown SUID binaries

Note that this script is meant to run on forensic disk images of Citrix NetScaler devices and not on the device itself.
Also see the [Creating Citrix NetScaler disk images](#creating-citrix-netscaler-disk-images) section on how to create forensic disk images of your Citrix NetScaler.

Ensure that you have the latest version of Dissect, support for Citrix NetScaler was added in this PR: https://github.com/fox-it/dissect.target/pull/357

**Disclaimer**: While this tool strives for accuracy, it is possible for it to produce false positives or false negatives. Users are advised to cross-check results and use their own judgement before making any decisions based on this tool's output.

## Installing `iocitrix.py`

Use the following steps:

1. git clone https://github.com/blacklanternsecurity/citrix-netscaler-triage.git
2. cd citrix-netscaler-triage
3. pip install -r requirements.txt
4. pip install --upgrade --pre dissect.volume dissect.target

Note that step 4 will print the following error, but you can ignore it:

```
ERROR: pip's dependency resolver does not currently take into account all the packages that are installed. This behaviour is the source of the following dependency conflicts.
```

You can then run `iocitrix.py <TARGETS>` to start an IOC check against one or more forensic images. The script accepts any input that [dissect](https://github.com/fox-it/dissect.target) can read as a `Target`, such as a `.VMDK`, or a raw disk image. Some examples are provided below.

```shell
python3 iocitrix.py image.vmx
python3 iocitrix.py image.vmdk
```

If you have also created a forensic image of the [RAM disk](#create-a-disk-image-of-the-devmd0-disk-to-your-local-machine), you can utilize `iocitrix.py` to incorporate volatile data in its triage as such:

```shell
python3 iocitrix.py md0.img+image.vmx
python3 iocitrix.py md0.img+image.vmdk
python3 iocitrix.py md0.img+da0.img
```

The `+` (plus) sign will load the two disk images as a single Dissect Target.

## Creating Citrix NetScaler disk images

A Citrix NetScaler exposes two important block devices which can imaged for offline forensic analysis. These block device files can be found at the following paths:
* `/dev/md0`: The disk that holds the root (`/`) directory. This is a RAM disk
* `/dev/da0`: The disk that holds the `/var` and `/flash` directories. This is a persistent disk.

The root directory (`/`) of Citrix NetScaler is a RAM disk, meaning that this is a volatile disk. This disk can be found at `/dev/md0` when the NetScaler is powered-on and running, and will be unavailable when the NetScaler is powered-off. The `/var` and `/flash` directories reside on the `/dev/da0` disk as two separate partitions and is persistent.

The following commands can be used on a local linux machine to create disk of your NetScaler over SSH:

#### Create a disk image of the `/dev/da0` disk to your local machine

```shell
local ~ $ ssh nsroot@<YOUR-NETSCALER-IP> shell dd if=/dev/da0 bs=10M | tail -c +7 | head -c -6 > da0.img
```

Do note, that this can take some time to complete. No progess is shown when using `dd`.
It is adviced to wait until you gain control back over the prompt. This is an indication that `dd` finished.

Also if you don't have `/dev/da0` it's most likely `/dev/ada0`, you can verify using the `mount` or `gpart show` command.

#### Create a disk image of the `/dev/md0` disk to your local machine
```shell
local ~ $ ssh nsroot@<YOUR-NETSCALER-IP> shell dd if=/dev/md0 bs=10M | tail -c +7 | head -c -6 > md0.img
```

**NOTE**: While it is recommended to create disk images of both `/dev/md0` and `/dev/da0`. Creating a disk image of `/dev/md0` is optional. This step could be skipped, though this can cause `iocitrix.py` to miss certains incicators of compromise.

### Running `iocitrix.py` on your images

After executing the previous commands on your local machine, the `da0.img` and `md0.img` files will be present. You can point `iocitrix` to these files to start triaging your images. Use the following command to do so:

```shell
local ~ $ python3 iocitrix.py md0.img+da0.img
```

Example output:
```
(venv) user@dissect:/data/netscaler/image$ python3 iocitrix.py md0.img+da0.img
<Target md0.img+da0.img>

Disks
- <RawContainer size=555745286 vs=None>
- <RawContainer size=21474836486 vs=<DissectVolumeSystem serial=None>>

Volumes
- <Volume name=None size=555745286 fs=<FfsFilesystem>>
- <Volume name='part_00000000' size=1717567488 fs=<FfsFilesystem>>
- <Volume name='part_66600000' size=4401922048 fs=<FfsFilesystem>>
- <Volume name='part_16cc00000' size=2097152 fs=<FfsFilesystem>>
- <Volume name='part_16ce00000' size=15353200128 fs=<FfsFilesystem>>

Hostname      : None
Domain        : None
IPs           : 10.164.0.39, 10.164.0.10
OS family     : citrix-netscaler (CitrixBsdPlugin)
OS version    : NetScaler 13.1 build 30 (ns-13.1-30.52)
Architecture  : x86_64-citrix-netscaler
Language(s)   :
Timezone      : None
Install date  : 2023-08-08 13:59:38.228043+00:00
Last activity : 2023-08-11 08:51:13.979536+00:00


*** Checking for webshells ***

<ioc/hit type='php-file-permission' alert='Suspicious php permission 0o644' confidence='high' path='/var/netscaler/logon/LogonPoint/uiareas/linux/adminupevents.php'>
<ioc/hit type='php-file-contents' alert="Suspicious PHP code 'b'array_filter(''" confidence='high' path='/var/netscaler/logon/LogonPoint/uiareas/linux/adminupevents.php'>
<ioc/hit type='php-file-permission' alert='Suspicious php permission 0o644' confidence='high' path='/var/vpn/config.php'>
<ioc/hit type='php-file-contents' alert="Suspicious PHP code 'b'array_filter(''" confidence='high' path='/var/vpn/config.php'>
<ioc/hit type='php-file-permission' alert='Suspicious php permission 0o644' confidence='high' path='/var/vpn/themes/config.php'>

*** Checking for timestomped files ***


*** Checking for suspicious cronjobs ***


*** Checking for SUID Binaries (this takes a while) ***

<ioc/hit type='binary/suid' alert='Binary with SUID bit set Observed' confidence='medium' path='/tmp/python/bash'>

********************************************************************************
***                                                                          ***
*** There were findings for Indicators of Compromise.                        ***
*** Please consider performing further forensic investigation of the system. ***
***                                                                          ***
********************************************************************************

Confidence    Type                 Alert                                       Artefact Location
------------  -------------------  ------------------------------------------  ---------------------------------------------------------------
high          php-file-permission  Suspicious php permission 0o644             /var/netscaler/logon/LogonPoint/uiareas/linux/adminupevents.php
high          php-file-contents    Suspicious PHP code 'b'array_filter(''      /var/netscaler/logon/LogonPoint/uiareas/linux/adminupevents.php
high          php-file-permission  Suspicious php permission 0o644             /var/vpn/config.php
high          php-file-contents    Suspicious PHP code 'b'array_filter(''      /var/vpn/config.php
high          php-file-permission  Suspicious php permission 0o644             /var/vpn/themes/config.php
medium        binary/suid          Binary with SUID bit set Observed           /tmp/python/bash

All targets analyzed.
```
