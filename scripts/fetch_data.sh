#!/usr/bin/env bash
# Downloads every external dataset the project uses into data/raw/<source>/.
# Each source gets its own directory; nothing in data/raw is ever executed except
# the pinned Hayabusa release binary.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RAW="$ROOT/data/raw"
mkdir -p "$RAW"

ATTACK_VERSION="${ATTACK_VERSION:-master}"

fetch() {  # fetch <url> <dest>
  if [[ -s "$2" ]]; then echo "skip  $2"; return; fi
  echo "fetch $1"
  curl -fsSL --retry 3 -o "$2.part" "$1" && mv "$2.part" "$2"
}

# --- MITRE ATT&CK (enterprise, STIX 2.1) -------------------------------------
mkdir -p "$RAW/attack"
fetch "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/${ATTACK_VERSION}/enterprise-attack/enterprise-attack.json" \
      "$RAW/attack/enterprise-attack.json"

# --- Attack logs (tarball, so no nested .git) --------------------------------
if [[ -z "$(ls -A "$RAW/evtx-attack-samples" 2>/dev/null)" ]]; then
  mkdir -p "$RAW/evtx-attack-samples"
  curl -fsSL https://codeload.github.com/sbousseaden/EVTX-ATTACK-SAMPLES/tar.gz/refs/heads/master \
    | tar xz --strip-components=1 -C "$RAW/evtx-attack-samples"
else
  echo "skip  $RAW/evtx-attack-samples"
fi

# --- Threat intel: known bad -------------------------------------------------
mkdir -p "$RAW/firehol" "$RAW/feodo" "$RAW/urlhaus" "$RAW/threatfox"
fetch https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset "$RAW/firehol/firehol_level1.netset"
fetch https://feodotracker.abuse.ch/downloads/ipblocklist.txt                    "$RAW/feodo/ipblocklist.txt"
fetch https://urlhaus.abuse.ch/downloads/hostfile/                               "$RAW/urlhaus/hostfile.txt"
fetch https://threatfox.abuse.ch/downloads/hostfile/                             "$RAW/threatfox/hostfile.txt"

# --- Threat intel: known good ------------------------------------------------
mkdir -p "$RAW/tranco"
fetch https://tranco-list.eu/top-1m.csv.zip "$RAW/tranco/top-1m.csv.zip"
[[ -s "$RAW/tranco/top-1m.csv" ]] || unzip -oq "$RAW/tranco/top-1m.csv.zip" -d "$RAW/tranco"

# --- Hayabusa (Sigma engine for EVTX) ----------------------------------------
HAYA_DIR="$RAW/hayabusa"
if [[ ! -d "$HAYA_DIR/bin" ]]; then
  mkdir -p "$HAYA_DIR/bin"
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64)  pattern='mac-aarch64' ;;
    Darwin-x86_64) pattern='mac-x64' ;;
    Linux-x86_64)  pattern='lin-x64-gnu' ;;
    Linux-aarch64) pattern='lin-aarch64-gnu' ;;
    *) echo "unsupported platform for hayabusa"; exit 1 ;;
  esac
  url=$(curl -fsSL https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest \
        | grep -o "https://[^\"]*${pattern}[^\"]*\.zip" | head -1)
  echo "fetch $url"
  curl -fsSL -o "$HAYA_DIR/hayabusa.zip" "$url"
  unzip -oq "$HAYA_DIR/hayabusa.zip" -d "$HAYA_DIR/bin"
  rm "$HAYA_DIR/hayabusa.zip"
fi

echo "done -> $RAW"
