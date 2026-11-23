#!/bin/sh
# Inventory only. No installers, daemon startup, or ambient PATH tools.
set -f
PATH=/usr/bin:/bin
export PATH LC_ALL=C
schema=openclaw-preflight-v1
emit() {
  printf '{"schema":"%s","status":"%s","reason":"%s","checks":{"platform":"%s","python":"%s"},"workload_started":false,"release_authorized":false,"security_qualified":false}\n' "$schema" "$1" "$2" "$3" "$4"
}
usage() {
  /bin/cat <<'EOF'
Usage: bash scripts/preflight.sh [--json] [--python ABS --python-sha256 HEX] [--node ABS]
       [--pins ABS --pins-sha256 HEX]
       [--docker-cli ABS --docker-socket ABS --docker-config ABS]
       [--runner ABS] [--model ABS] [--template ABS] [--full-model-hash]
       bash scripts/preflight.sh --help

Outputs JSON. Missing checks are incomplete, never a pass. The full model
SHA-256 is opt-in and reads the entire roughly 24 GB file; it can take time.
Use separately reviewed installed-byte pins, not archive hashes.
Pins JSON exact keys: schema (openclaw-preflight-pins-v1), python_sha256,
node_sha256, docker_cli_sha256, runner_sha256, model_sha256, template_sha256
(each 64 lowercase hex), model_bytes (integer), image_id (sha256: plus hex).
Provide the pins-file SHA independently, before trusting that file.
No installs, downloads, workload, listener bind, or automatic Docker lookup.
Exit 0: evaluated checks passed; 1: blocked; 2: incomplete or bad arguments.
EOF
}
python=
python_hash=
seen_python=no
seen_python_hash=no
inspect_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --json|--full-model-hash) shift ;;
      --python|--node|--docker-cli|--docker-socket|--docker-config|--runner|--model|--template|--pins)
        [ "$#" -ge 2 ] || return 1
        case "$2" in /*) ;; *) return 1;; esac
        if [ "$1" = --python ]; then
          [ "$seen_python" = no ] || return 1
          seen_python=yes
          python=$2
        fi
        shift 2 ;;
      --python-sha256|--pins-sha256)
        [ "$#" -ge 2 ] && [ "${#2}" -eq 64 ] || return 1
        case "$2" in *[!0-9a-f]*) return 1;; esac
        if [ "$1" = --python-sha256 ]; then
          [ "$seen_python_hash" = no ] || return 1
          seen_python_hash=yes
          python_hash=$2
        fi
        shift 2 ;;
      *) return 1 ;;
    esac
  done
}
if [ "$#" -eq 1 ] && [ "$1" = --help ]; then
  usage
  exit 0
fi
if ! inspect_args "$@"; then
  emit incomplete invalid_arguments not_checked not_checked
  exit 2
fi
os=$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/uname -s 2>/dev/null) || {
  emit blocked platform_unconfirmed unconfirmed not_checked; exit 1;
}
arch=$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/uname -m 2>/dev/null) || {
  emit blocked platform_unconfirmed unconfirmed not_checked; exit 1;
}
if [ "$os" != Darwin ] || [ "$arch" != arm64 ]; then
  emit blocked unsupported_platform unsupported not_checked
  exit 1
fi
if [ "$seen_python" = no ] || [ "$seen_python_hash" = no ]; then
  emit incomplete explicit_python_and_digest_required macos_arm64 not_checked
  exit 2
fi
case "$python" in */python3.13) ;; *) emit blocked python_digest_unconfirmed macos_arm64 name_unconfirmed; exit 1;; esac
if [ ! -f "$python" ]; then
  emit incomplete python_path_required macos_arm64 not_found
  exit 2
fi
if [ -L "$python" ] || [ ! -x "$python" ]; then
  emit blocked python_digest_unconfirmed macos_arm64 path_unconfirmed
  exit 1
fi
physical=$(CDPATH= cd -P "${python%/*}" 2>/dev/null && pwd -P) || physical=
if [ "$physical" != "${python%/*}" ]; then
  emit blocked python_digest_unconfirmed macos_arm64 path_unconfirmed
  exit 1
fi
n=$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/stat -f %z "$python" 2>/dev/null) || n=0
case "$n" in ''|*[!0-9]*) n=0;; esac
if [ "$n" -lt 1 ] || [ "$n" -gt 10485760 ]; then
  emit blocked python_digest_unconfirmed macos_arm64 size_unconfirmed
  exit 1
fi
h=$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/shasum -a 256 2>/dev/null < "$python") || h=
if [ "${h%% *}" != "$python_hash" ]; then
  emit blocked python_digest_unconfirmed macos_arm64 digest_mismatch
  exit 1
fi
case "$0" in */*) here=${0%/*};; *) here=.;; esac
here=$(CDPATH= cd -P "$here" 2>/dev/null && pwd -P) || {
  emit blocked helper_unavailable macos_arm64 not_checked; exit 1;
}
[ -f "$here/preflight.py" ] && [ ! -L "$here/preflight.py" ] || {
  emit blocked helper_unavailable macos_arm64 not_checked; exit 1;
}
exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent "$python" -I -B -S "$here/preflight.py" "$@" 2>/dev/null
