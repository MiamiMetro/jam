# Jam VPS setup runbook

Reproducible setup for running the native UDP SFU on a fresh Ubuntu/Debian VPS.

Assumptions:

- Fresh Ubuntu 22.04/24.04 or Debian 12 VPS.
- You have initial root SSH access from the provider.
- The server should run on UDP port `9999`.
- SSH should move off port `22`.
- The app should run as an unprivileged `jam` user under `systemd`.

Set these values in Windows `cmd` before following the commands:

```bat
set VPS_HOST=your.vps.ip.or.dns
set VPS_SSH_PORT=2222
set LOCAL_KEY=%USERPROFILE%\.ssh\jam_vps_ed25519
set SERVER_ID=istanbul-test
set JOIN_SECRET=replace-with-a-long-random-secret
```

## 1. Create a local SSH key

Run this in Windows `cmd` on your own computer, not on the VPS:

```bat
ssh-keygen -t ed25519 -a 100 -f "%LOCAL_KEY%" -C "jam-vps"
```

Copy the public key to the fresh VPS using the provider's default root SSH access:

```bat
type "%LOCAL_KEY%.pub" | ssh root@%VPS_HOST% "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys"
```

If the copy command does not work, print the public key and paste it into `/root/.ssh/authorized_keys` on the VPS:

```bat
type "%LOCAL_KEY%.pub"
```

Verify key login works:

```bat
ssh -i "%LOCAL_KEY%" root@%VPS_HOST%
```

## 2. Harden SSH and create the app user

Run on the VPS as `root`:

```bash
export VPS_SSH_PORT="2222"

apt-get update
apt-get install -y sudo ufw git cmake ninja-build build-essential pkg-config ca-certificates

adduser --disabled-password --gecos "" jam
usermod -aG sudo jam

install -d -m 700 -o jam -g jam /home/jam/.ssh
cp /root/.ssh/authorized_keys /home/jam/.ssh/authorized_keys
chown jam:jam /home/jam/.ssh/authorized_keys
chmod 600 /home/jam/.ssh/authorized_keys
```

Create a dedicated SSH config file:

```bash
cat >/etc/ssh/sshd_config.d/99-jam.conf <<EOF
Port ${VPS_SSH_PORT}
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
X11Forwarding no
AllowUsers jam
EOF
```

Validate the SSH config before restarting:

```bash
sshd -t
```

Open the new SSH port and the UDP server port:

```bash
ufw allow "${VPS_SSH_PORT}/tcp"
ufw allow 9999/udp
ufw --force enable
ufw status verbose
```

Restart SSH:

```bash
systemctl restart ssh
```

Some Ubuntu images use `systemd` socket activation for SSH. In that case, `sshd_config` can be valid but SSH still listens on port `22` because `ssh.socket` owns the listening port. Check what is listening:

```bash
ss -ltnp | grep ssh
```

If you only see `:22` and do not see the new port, create a socket override:

```bash
mkdir -p /etc/systemd/system/ssh.socket.d

cat >/etc/systemd/system/ssh.socket.d/override.conf <<EOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:${VPS_SSH_PORT}
EOF

systemctl daemon-reload
systemctl restart ssh.socket
systemctl restart ssh.service
ss -ltnp | grep ssh
```

You should see SSH listening on `0.0.0.0:<new-port>` before continuing. If it only shows `[::]:<new-port>`, IPv4 clients may still get `Connection refused`.

Open a new terminal on your own computer and verify the new SSH path before closing the root session:

```bat
ssh -i "%LOCAL_KEY%" -p %VPS_SSH_PORT% jam@%VPS_HOST%
```

After that works, remove old SSH port `22` from the firewall:

```bash
ufw delete allow 22/tcp || true
ufw status verbose
```

## 3. Upload or clone the project

Option A: clone from git on the VPS as `jam`:

```bash
cd /home/jam
git clone https://github.com/MiamiMetro/jam.git jam
cd /home/jam/jam
```

Option B: upload the local working tree from your computer.

Windows `cmd` does not include `rsync` by default, so use Option A unless you have another upload method. If you need a pure `cmd` upload flow later, use `scp`, but it is slower and easier to get wrong for large trees.

## 4. Build the server

Run on the VPS as `jam`:

```bash
cd /home/jam/jam

# VPS builds only need the server target. The desktop client pulls in
# workstation-only dependencies, so disable it before configuring CMake.
sed -i 's/^include(cmake\/client.cmake)/# include(cmake\/client.cmake)/' CMakeLists.txt

cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target server
```

Verify the binary exists:

```bash
ls -lh /home/jam/jam/build/server
```

## 5. Create the systemd service

Run on the VPS as `root`:

```bash
export SERVER_ID="istanbul-test"
export JOIN_SECRET="replace-with-a-long-random-secret"

install -d -m 750 -o jam -g jam /etc/jam

cat >/etc/jam/server.env <<EOF
SERVER_ID=${SERVER_ID}
JOIN_SECRET=${JOIN_SECRET}
EOF

chown root:jam /etc/jam/server.env
chmod 640 /etc/jam/server.env

cat >/etc/systemd/system/jam-server.service <<'EOF'
[Unit]
Description=Jam native UDP SFU
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=jam
Group=jam
WorkingDirectory=/home/jam/jam
EnvironmentFile=/etc/jam/server.env
ExecStart=/home/jam/jam/build/server --port 9999 --server-id ${SERVER_ID} --join-secret ${JOIN_SECRET}
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/home/jam/jam

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now jam-server
```

Check status and logs:

```bash
systemctl status jam-server --no-pager
journalctl -u jam-server -f
```

Expected log line:

```text
Starting SFU server on 0.0.0.0:9999
```

## 6. Generate friend join commands

Run locally from this project folder. Use the VPS public IP/DNS and the same `SERVER_ID` / `JOIN_SECRET` used in `/etc/jam/server.env`:

```bat
node tools\dev-join-token.mjs --secret "%JOIN_SECRET%" --server-id "%SERVER_ID%" --server "%VPS_HOST%" --port 9999 --room room1 --user friend1 --display-name Friend1
```

Share only the generated client command with that friend.

## 7. Update after code changes

If using git:

```bash
ssh -i "$LOCAL_KEY" -p "$VPS_SSH_PORT" jam@"$VPS_HOST"
cd /home/jam/jam
git pull
cmake --build build --target server
sudo systemctl restart jam-server
sudo systemctl status jam-server --no-pager
```

If using `rsync`, upload again, then rebuild and restart:

```bash
cmake --build /home/jam/jam/build --target server
sudo systemctl restart jam-server
```

## 8. Useful checks

Firewall:

```bash
sudo ufw status verbose
```

Service logs:

```bash
sudo journalctl -u jam-server -n 100 --no-pager
```

Listening UDP sockets:

```bash
sudo ss -lunp | grep 9999
```

Restart:

```bash
sudo systemctl restart jam-server
```

Stop:

```bash
sudo systemctl stop jam-server
```

## Notes

- Do not use `--allow-insecure-dev-joins` on a public VPS.
- Rotate `JOIN_SECRET` for each serious test session.
- AWS, Hetzner, OVH, Vultr, and similar providers may also have provider-level firewalls. Open UDP `9999` there too.
- If you change `VPS_SSH_PORT`, update both `/etc/ssh/sshd_config.d/99-jam.conf` and the VPS/provider firewall rules.
