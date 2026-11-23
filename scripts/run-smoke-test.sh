#!/bin/sh
# Distribution-side smoke boundary. No application, model or container is invoked.
set -eu

usage() {
    printf '%s\n' 'Usage: scripts/run-smoke-test.sh [--help]' \
        'Checks whether this distribution has an approved portable smoke runtime.' \
        'Does not start services, accept a launcher, or certify a previous receipt.' \
        'Exit codes: 0 help; 2 invalid usage; 3 blocked (no approved portable runtime).'
}

case "$#" in
    0)
        printf '%s\n' '{"schema":"openclaw-smoke-v1","status":"blocked","reason":"portable_runtime_unavailable","workload_started":false,"acceptance_verified":false}'
        exit 3
        ;;
    1)
        case "$1" in
            -h|--help) usage; exit 0 ;;
        esac
        ;;
esac

usage >&2
exit 2
