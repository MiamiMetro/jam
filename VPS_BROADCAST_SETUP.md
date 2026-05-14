# Jam broadcast VPS setup runbook

Reproducible setup for running the Listener Mode V3 ingest/HLS stack on the
same VPS used by `VPS_SETUP.md`.

This is broadcast/listener-only. It does not install or run the native UDP SFU.
Keep the SFU governed by `VPS_SETUP.md`.

Assumptions:

- `VPS_SETUP.md` is already done.
- You can SSH as the unprivileged `jam` user.
- The project lives at `/home/jam/jam`.
- Docker is not installed yet.
- Listener Mode V3 uses SRT ingest on UDP port `8890`.
- HLS is served by nginx from TCP port `8080` for the first VPS smoke test.
- Convex has the `/broadcast/auth` HTTP endpoint from the V3 branch.

Set these values in Windows `cmd` before following the commands:

```bat
set VPS_HOST=your.vps.ip.or.dns
set VPS_SSH_PORT=2222
set LOCAL_KEY=%USERPROFILE%\.ssh\jam_vps_ed25519
set CONVEX_SITE_URL=https://your-deployment.convex.site
```

`CONVEX_SITE_URL` must be the Convex site URL, not the Convex cloud API URL.
The broadcast auth endpoint will be:

```text
%CONVEX_SITE_URL%/broadcast/auth
```

## 1. Install Docker

Run on the VPS as `jam`:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

. /etc/os-release
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker jam
sudo systemctl enable --now docker
sudo systemctl status docker --no-pager
```

Log out and back in so the `docker` group takes effect:

```bash
exit
```

Then reconnect from Windows:

```bat
ssh -i "%LOCAL_KEY%" -p %VPS_SSH_PORT% jam@%VPS_HOST%
```

Verify Docker works without `sudo`:

```bash
docker version
docker compose version
docker run --rm hello-world
```

If `docker version` prints the client version but then says:

```text
failed to connect to the docker API at unix:///var/run/docker.sock
```

the Docker CLI is installed but the daemon is not running. Start it:

```bash
sudo systemctl enable --now docker
sudo systemctl status docker --no-pager
```

Then retry:

```bash
docker run --rm hello-world
```

If Docker is running but your user cannot access it, refresh the `docker` group:

```bash
newgrp docker
docker run --rm hello-world
```

## 2. Update the project

Run on the VPS as `jam`:

```bash
cd /home/jam/jam
git pull
```

If Git reports dubious ownership or permission denied inside `.git`, the repo
was probably cloned or uploaded as `root`. Fix ownership instead of only adding
`safe.directory`:

```bash
sudo chown -R jam:jam /home/jam/jam
cd /home/jam/jam
git pull
```

If you already ran `git config --global --add safe.directory /home/jam/jam`,
that is harmless, but it does not fix `.git/FETCH_HEAD: Permission denied`.

Verify the broadcast files exist:

```bash
ls -lh docker-compose.broadcast.yml docker-compose.broadcast.auth.yml
ls -lh broadcast/mediamtx.yml broadcast/nginx.conf
```

## 3. Configure firewall

Run on the VPS as `jam`:

```bash
sudo ufw allow 8890/udp
sudo ufw allow 8080/tcp
sudo ufw status verbose
```

Provider firewalls also matter. If your VPS provider has a separate firewall UI,
open:

- UDP `8890` for SRT ingest.
- TCP `8080` for first HLS smoke test.

## 4. Create the broadcast environment

Run on the VPS as `jam`:

```bash
export CONVEX_SITE_URL="https://your-deployment.convex.site"

cat >/home/jam/jam/.env.broadcast <<EOF
BROADCAST_SRT_PORT=8890
BROADCAST_HTTP_PORT=8080
BROADCAST_MEDIAMTX_API_PORT=9997
BROADCAST_AUTH_HTTP_ADDRESS=${CONVEX_SITE_URL}/broadcast/auth
EOF

chmod 600 /home/jam/jam/.env.broadcast
```

Check it:

```bash
cat /home/jam/jam/.env.broadcast
```

## 5. Start the broadcast stack

Run on the VPS as `jam`:

```bash
cd /home/jam/jam
set -a
. /home/jam/jam/.env.broadcast
set +a

docker compose \
  -f docker-compose.broadcast.yml \
  -f docker-compose.broadcast.auth.yml \
  up -d
```

Check containers:

```bash
docker ps --filter "name=jam-broadcast"
```

Expected containers:

```text
jam-broadcast-mediamtx
jam-broadcast-nginx
```

## 6. Health checks

Run on the VPS:

```bash
curl -i http://127.0.0.1:8080/health
```

Expected:

```text
HTTP/1.1 200 OK
ok
```

Check MediaMTX API locally:

```bash
curl -s http://127.0.0.1:9997/v3/config/global/get | grep -E '"authMethod"|"srt"|"hls"|"authHTTPAddress"'
```

Expected facts:

- `"authMethod":"http"`
- `"srt":true`
- `"hls":true`
- `"authHTTPAddress":"https://.../broadcast/auth"`

Check logs:

```bash
docker logs jam-broadcast-mediamtx --tail 100
docker logs jam-broadcast-nginx --tail 100
```

## 7. Public smoke checks

Run from your Windows machine:

```bat
curl http://%VPS_HOST%:8080/health
```

Expected:

```text
ok
```

The HLS URL shape is:

```text
http://%VPS_HOST%:8080/hls/<room-handle>/stream.m3u8
```

Do not expect that URL to work until a broadcaster is actively publishing that
room path.

## 8. Start, stop, restart

Run on the VPS as `jam`:

```bash
cd /home/jam/jam
set -a
. /home/jam/jam/.env.broadcast
set +a
```

Start:

```bash
docker compose -f docker-compose.broadcast.yml -f docker-compose.broadcast.auth.yml up -d
```

Stop:

```bash
docker compose -f docker-compose.broadcast.yml -f docker-compose.broadcast.auth.yml down --remove-orphans
```

Restart:

```bash
docker compose -f docker-compose.broadcast.yml -f docker-compose.broadcast.auth.yml restart
```

Logs:

```bash
docker logs jam-broadcast-mediamtx -f
docker logs jam-broadcast-nginx -f
```

## 9. Update after code changes

Run on the VPS as `jam`:

```bash
cd /home/jam/jam
git pull
set -a
. /home/jam/jam/.env.broadcast
set +a
docker compose -f docker-compose.broadcast.yml -f docker-compose.broadcast.auth.yml pull
docker compose -f docker-compose.broadcast.yml -f docker-compose.broadcast.auth.yml up -d
docker ps --filter "name=jam-broadcast"
```

## 10. Windows one-liners

Set these first in Windows `cmd`:

```bat
set VPS_HOST=your.vps.ip.or.dns
set VPS_SSH_PORT=2222
set LOCAL_KEY=%USERPROFILE%\.ssh\jam_vps_ed25519
```

Check containers:

```bat
ssh -i "%LOCAL_KEY%" -p %VPS_SSH_PORT% jam@%VPS_HOST% "docker ps --filter name=jam-broadcast"
```

Show MediaMTX logs:

```bat
ssh -i "%LOCAL_KEY%" -p %VPS_SSH_PORT% jam@%VPS_HOST% "docker logs jam-broadcast-mediamtx --tail 100"
```

Show nginx logs:

```bat
ssh -i "%LOCAL_KEY%" -p %VPS_SSH_PORT% jam@%VPS_HOST% "docker logs jam-broadcast-nginx --tail 100"
```

Restart broadcast stack:

```bat
ssh -i "%LOCAL_KEY%" -p %VPS_SSH_PORT% jam@%VPS_HOST% "cd /home/jam/jam && set -a && . ./.env.broadcast && set +a && docker compose -f docker-compose.broadcast.yml -f docker-compose.broadcast.auth.yml restart"
```

Stop broadcast stack:

```bat
ssh -i "%LOCAL_KEY%" -p %VPS_SSH_PORT% jam@%VPS_HOST% "cd /home/jam/jam && set -a && . ./.env.broadcast && set +a && docker compose -f docker-compose.broadcast.yml -f docker-compose.broadcast.auth.yml down --remove-orphans"
```

## Notes

- This stack is listener/broadcast-only. It must not expose or start the native
  SFU server.
- For the current local desktop branch, Convex still returns local HLS/SRT URLs
  unless the app/backend config is changed to the VPS values. This runbook gets
  the VPS ingest/HLS stack ready.
- `8080` is for the first smoke test. For production-style browser playback,
  put HTTPS in front of HLS, for example `https://listen.<domain>/hls/<room>/stream.m3u8`.
- Do not run the app-backed authenticated path without
  `docker-compose.broadcast.auth.yml`; Convex now issues per-session publish
  credentials in the SRT stream ID.
- If HLS returns `404`, check that the broadcaster is running and publishing the
  same room handle that appears in the URL.
