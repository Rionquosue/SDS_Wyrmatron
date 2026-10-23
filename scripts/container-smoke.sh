#!/bin/sh
# Starts the image with Telegram and FFmpeg disabled and checks the API,
# health, persistence across container replacement and container hardening.
set -eu
image="${1:-wyrmatron:test}"
suffix="$$"
name="wyrmatron-smoke-$suffix"
volume="wyrmatron-smoke-data-$suffix"
scratch="$(mktemp -d)"
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  rm -rf "$scratch"
}
trap cleanup EXIT INT TERM

key="smoke-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
hash="$(printf %s "$key" | docker run --rm -i --entrypoint /usr/local/bin/wyrmatron "$image" hash-key)"
cat > "$scratch/config.toml" <<CONF
[telegram]
enabled = false
[ffmpeg]
enabled = false
[destinations.ops]
chat_id = -100123
[[consumers]]
id = "smoke"
key_sha256 = ["$hash"]
scopes = ["notify", "media"]
destinations = ["ops"]
[uptime_kuma.main]
destination = "ops"
CONF
chmod 0644 "$scratch/config.toml"

start() {
  docker run -d --name "$name" --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    --pids-limit 64 --memory 256m --cpus 0.5 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700 \
    -v "$volume:/data" -v "$scratch/config.toml:/etc/wyrmatron/config.toml:ro" \
    -p 127.0.0.1::8080 "$image" >/dev/null
  for _ in $(seq 1 30); do
    if docker exec "$name" /usr/local/bin/wyrmatron healthcheck; then return 0; fi
    sleep 1
  done
  docker logs "$name"
  exit 1
}

start
port="$(docker port "$name" 8080/tcp | head -n1 | sed 's/.*://')"
api="http://127.0.0.1:$port"
curl -fsS "$api/health/live" | grep -q '"ok":true'
test "$(curl -s -o /dev/null -w '%{http_code}' "$api/v1/capabilities")" = 401
curl -fsS -H "Authorization: Bearer $key" "$api/v1/capabilities" | grep -q '"api_version":"1"'
body='{"destination":"ops","text":"container smoke test","event_id":"smoke-1"}'
test "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $key" -H 'Content-Type: application/json' -d "$body" "$api/v1/notifications")" = 202
kuma='{"heartbeat":{"monitorID":1,"status":0,"time":"2026-10-22 14:00:00.000","msg":"down"},"monitor":{"id":1,"name":"NAS"},"msg":"[NAS] down"}'
test "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $key" -H 'Content-Type: application/json' -d "$kuma" "$api/v1/hooks/uptime-kuma/main")" = 202

# Hardening: non-root, no capabilities, read-only root.
docker exec "$name" sh -c 'test "$(id -u)" = 10001'
docker exec "$name" sh -c 'grep -q "^CapEff:[[:space:]]*0*$" /proc/1/status'
if docker exec "$name" sh -c 'touch /usr/local/bin/x' 2>/dev/null; then echo "root filesystem is writable" >&2; exit 1; fi

# Graceful stop, then a new container on the same volume keeps the outbox:
# the duplicate event is recognised.
docker stop -t 30 "$name" >/dev/null
docker logs "$name" 2>&1 | grep -q '"stopped"' || { docker logs "$name"; echo "no clean shutdown" >&2; exit 1; }
docker rm "$name" >/dev/null
start
port="$(docker port "$name" 8080/tcp | head -n1 | sed 's/.*://')"
test "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $key" -H 'Content-Type: application/json' -d "$body" "http://127.0.0.1:$port/v1/notifications")" = 200
echo "container smoke checks passed"
