#!/usr/bin/env bash
# Ephemeral, real PSMDB 8.0.32-14 replica set plus a standalone negative fixture.
set -euo pipefail

task_repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd -- "$task_repo_root"

task_image=${AUTH_TEST_PSMDB_IMAGE:-percona/percona-server-mongodb:8.0@sha256:5ba5f240d2dc98bc6236ab1d79c0862c4b62dba9d98cd0ffdf716c30473d2d11}
task_rs_container=""
task_standalone_container=""
cleanup() {
    task_exit=$?
    trap - EXIT
    for task_container in "$task_rs_container" "$task_standalone_container"; do
        if [[ -n "$task_container" ]]; then
            if (( task_exit != 0 )) && [[ ${AUTH_TEST_MONGO_LOGS:-0} == 1 ]]; then docker logs --tail 40 "$task_container" >&2 || true; fi
            docker rm --force --volumes "$task_container" >/dev/null 2>&1 || true
        fi
    done
    exit "$task_exit"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

task_rs_container=$(docker run --detach --rm --publish 127.0.0.1::27017 \
    --env PERCONA_TELEMETRY_DISABLE=1 "$task_image" \
    --replSet auth-rs --bind_ip_all --wiredTigerCacheSizeGB 0.25)
task_standalone_container=$(docker run --detach --rm --publish 127.0.0.1::27017 \
    --env PERCONA_TELEMETRY_DISABLE=1 "$task_image" \
    --bind_ip_all --wiredTigerCacheSizeGB 0.25)

wait_for_mongo() {
    local task_container=$1 task_expression=$2 task_attempt
    for (( task_attempt=0; task_attempt<90; task_attempt++ )); do
        if docker exec "$task_container" mongosh --quiet --eval "$task_expression" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    echo "PSMDB did not become ready" >&2
    docker logs --tail 40 "$task_container" >&2 || true
    return 1
}
for task_container in "$task_rs_container" "$task_standalone_container"; do
    wait_for_mongo "$task_container" 'quit(db.runCommand({ping:1}).ok ? 0 : 1)'
done
docker exec "$task_rs_container" mongosh --quiet --eval \
    'const r = rs.initiate({_id:"auth-rs",members:[{_id:0,host:"localhost:27017"}]}); if (!r.ok) { throw new Error(JSON.stringify(r)); }' >/dev/null
wait_for_mongo "$task_rs_container" 'quit(db.hello().isWritablePrimary ? 0 : 1)'

task_rs_address=$(docker port "$task_rs_container" 27017/tcp)
task_standalone_address=$(docker port "$task_standalone_container" 27017/tcp)
export AUTH_TEST_MONGO_URI="mongodb://127.0.0.1:${task_rs_address##*:}/?replicaSet=auth-rs&directConnection=true"
export AUTH_TEST_MONGO_STANDALONE_URI="mongodb://127.0.0.1:${task_standalone_address##*:}/?directConnection=true"
if (( $# == 0 )); then set -- go test ./...; fi
"$@"
