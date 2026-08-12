# SMO Deployment Guide — Real-Verified Distributed Mesh

**Version:** v0.0.3  
**Topology:** 1 Cloud + N Local (OpenVPN L3 network)  
**Protocol:** SMO Mesh (custom TCP framing + UDP discovery)

> **⚠️ v0.0.3 blockers — test ngày 2026-08-11:**
> 1. `smo` CLI crash khi `SMO_DATA_DIR` chưa set (getenv → nullptr → std::string) — **đã fix** ở `cmd/smo/main.cpp:12`
> 2. `smo genesis create` tạo recovery.pkg KHÔNG có encrypted keypair → `generate-invite` fail với *"recovery package has no encrypted keypair"* — **chưa fix**
> 3. Genesis join codes `SMO-BOOT-<name>-000` chỉ là số index slot, KHÔNG có mã thật; `smo join SMO-BOOT-...` không có handler — join thật phải dùng `smo-admin generate-invite` → `SMO-JOIN-...`
>
> Join-token path hiện BLOCKED (bug #2). Workaround: dùng CSR path — `smo-node --export` → `smo-admin sign` → `smo-node --import`. Chi tiết section 14.

---

## 1. Kiến Trúc Mạng

```
Internet                          Cloud VPS (public IP)
                                    │
                                    OpenVPN server (udp/1194)
                                    │
                              10.8.0.0/24
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                10.8.0.1        10.8.0.2        10.8.0.3
              Cloud Node        Local A          Local B
              smo-node          smo-node         smo-node
              authority=true    worker           worker
              relay=n/a         relay=n/a        relay=n/a
```

SMO chỉ thấy địa chỉ OpenVPN (`10.8.0.x`). Mạng L3 trong suốt — SMO không biết NAT, không cần STUN/ICE.

---

## 2. 3-Node Topology (Tối Thiểu)

### Yêu cầu

| Machine | Spec | OS | Vai trò |
|---------|------|----|---------|
| Cloud VPS | 2GB RAM, 1 CPU, public IP | Ubuntu 22.04+ | Authority + mesh seed |
| Local A | 1GB RAM, Linux | Ubuntu 22.04+ | Worker |
| Local B | 1GB RAM, Linux | Ubuntu 22.04+ | Worker |

### Step 1: Cloud VPS

```bash
# SSH vào VPS
ssh root@<vps-public-ip>

# Chạy deploy script
bash deploy.sh cloud <vps-public-ip>
```

Script này tự động:
1. Cài OpenVPN + easy-rsa
2. Gen PKI (CA, server cert, client certs)
3. Cấu hình OpenVPN server (AES-256-GCM, client-to-client)
4. Build SMO từ source (Release + PQC)
5. Tạo mesh genesis
6. Publish mesh (bootstrap endpoints)
7. Gen join token (Worker, 168h expire)
8. Copy hệ thống systemd unit

Output:
```
/root/join-token.txt                 ← Join token cho local nodes
/root/openvpn-clients/local-a/       ← OpenVPN certs cho Local A
/root/openvpn-clients/local-b/       ← OpenVPN certs cho Local B
```

### Step 2: Local Machines

```bash
# Copy OpenVPN certs từ cloud VPS
scp -r root@<vps-ip>:/root/openvpn-clients/local-a/* ./openvpn-client/
scp root@<vps-ip>:/root/join-token.txt .

# Copy deploy scripts
scp root@<vps-ip>:/root/smoframework/scripts/deploy.sh .
scp root@<vps-ip>:/root/smoframework/scripts/deploy-local.sh .

# Chạy deploy local
bash deploy.sh local <vps-ip> "$(cat join-token.txt)"
```

Lặp lại cho Local B (với `openvpn-clients/local-b/`).

### Step 3: Verify

```bash
# Trên cloud node
smo mesh --health

# Trên local node
smo mesh --health
smo-node --data /var/lib/smo --pubkey

# Ping thử giữa các node qua OpenVPN
ping 10.8.0.2
ping 10.8.0.3
```

### Checklist verification

```
☐ 3 nodes: sao chép và join thành công
☐ smo mesh --health hiển thị 3/3 online
☐ heartbeat: ping/pong giữa các node
☐ gossip: membership table đồng bộ
☐ anti-entropy: delta sync hoạt động
```

---

## 3. Chi Tiết Từng File Script

### `scripts/deploy-cloud.sh`

```
1/8  Installing dependencies     (openvpn, easy-rsa, build-essential, cmake, ninja)
2/8  Setting up EasyRSA PKI      (CA, server cert, DH params, ta.key)
3/8  Deploying OpenVPN config     (server.conf → /etc/openvpn/)
4/8  Generating client certs      (local-a, local-b → /root/openvpn-clients/)
5/8  Building SMO from source     (cmake Release + PQC, ninja)
6/8  Creating SMO mesh            (smo-node --init → smo mesh --create)
7/8  Generating join token        (smo-admin generate-invite, 168h)
8/8  Installing systemd service   (smo-node.service → /etc/systemd/system/)
```

### `scripts/deploy-local.sh`

```
1/5  Installing dependencies     (openvpn, build-essential, cmake, ninja)
2/5  Setting up OpenVPN client    (client.ovpn → /etc/openvpn/client/)
3/5  Building SMO from source     (cmake Release + PQC)
4/5  Joining mesh                 (smo-node --join <token>)
5/5  Installing systemd service   (smo-node.service)
```

### `scripts/chaos-test.sh`

Test execution order (skip destructive tests with `--quick`):
```
A.1  3 nodes online check
A.2  Mesh join verified
A.3  Heartbeat check
A.4  Gossip propagation
A.5  Anti-entropy sync
B.1  smo exec (echo contract)
B.2  Governance proposal/vote
B.3  Audit log
C.1  Kill authority → restart → converge
C.2  Kill worker → restart → converge
C.3  Network partition → heal → converge
C.4  Epoch change proposal
```

---

## 4. Quy Trình Production Deployment

### Deployment steps

**Giai đoạn 1 — Cloud VPS:**

```bash
# 1.1 Provision VPS
# Ubuntu 22.04, 2GB RAM, mở port 1194/udp + 7777/tcp

# 1.2 SSH và deploy
ssh root@<vps-ip>
apt-get update && apt-get install -y git
git clone https://github.com/D-O-T-Solutions/smoframework.git
cd smoframework
bash scripts/deploy.sh cloud <vps-ip>
```

**Giai đoạn 2 — Local machines:**

```bash
# 2.1 Copy credentials từ cloud
scp -r root@<vps-ip>:/root/openvpn-clients/<hostname>/* ./
scp root@<vps-ip>:/root/join-token.txt ./
scp root@<vps-ip>:/root/smoframework/scripts/*.sh ./

# 2.2 Deploy
sudo bash deploy-local.sh <vps-ip> "$(cat join-token.txt)"
```

### Daily operations

```bash
# Check mesh health
smo mesh --health

# List nodes
smo mesh --list

# Node info
smo-node --data /var/lib/smo --pubkey

# Logs
journalctl -u smo-node -f --since "10 minutes ago"

# Governance
smo governance --status
smo governance --propose <proposal>

# Audit
smo history
```

### Backup

```bash
# Backup mesh config (root keys không được lưu disk!)
cp -r /var/lib/smo /backup/smo-$(date +%Y%m%d)

# Quan trọng: recovery package
ls /var/lib/smo/meshes/*/recovery.pkg

# Export recovery passphrase
echo "$SMO_RECOVERY_PASSPHRASE" > /backup/recovery-passphrase.txt
```

### Recovery

```bash
# Soft recovery (giữ nguyên identity)
systemctl restart smo-node

# Hard recovery (từ recovery package)
smo recovery --restore /backup/recovery.pkg
```

---

## 5. Mở Rộng: 5-Node Topology

Từ 3-node lên 5-node: thêm 2 worker nữa.

```
Cloud VPS  (10.8.0.1)    ← authority + seed
├── Local A (10.8.0.2)   ← worker
├── Local B (10.8.0.3)   ← worker
├── Local C (10.8.0.4)   ← worker (thêm mới)
└── Local D (10.8.0.5)   ← worker (thêm mới)
```

```bash
# Trên cloud: gen cert cho node mới
cd /etc/openvpn/easy-rsa
./easyrsa gen-req local-c nopass
./easyrsa sign-req client local-c
# ... tương tự local-d

# Trên local machine mới: giống hệt Step 2 ở trên
```

**Gossip tuning khuyến nghị:**
```
fanout: 3       (mặc định, phù hợp)
heartbeat interval: 5000ms (5s)
anti-entropy cycle: 30min
```

---

## 6. Mở Rộng: 10-Node Topology

```
10.8.0.0/24 subnet — đủ cho 10 node (254 addresses)

Cloud VPS (10.8.0.1)   ← authority + seed
├── N01 (10.8.0.2)     ← worker
├── N02 (10.8.0.3)     ← worker
├── ...
└── N09 (10.8.0.10)    ← worker
```

**Subnet segmentation** (nếu cần nhiều hơn):
```
/24 → /23: 10.8.0.0/23 (510 addresses)
Thêm OpenVPN server directive: server 10.8.0.0 255.255.254.0
```

**Scaling notes:**
- Gossip O(log N) scaling — 10 nodes không cần tuning
- Heartbeat: 4KB/cycle/node, TCP
- Storage: SQLite per node, ~100MB cho 10k events

---

## 7. Mở Rộng: 20-Node Topology

```
OpenVPN subnet: 10.8.0.0/24 (254 addresses, đủ)
```

**Khuyến nghị:**
```
anti-entropy cycle: 15min (từ 30min)
heartbeat timeout: 8000ms (từ 5000ms)
gossip fanout: 4 (từ 3)
```

**Cân nhắc:**
- Không dùng 1 authority cho 20+ worker
- Cân nhắc multiple authorities (multi-region)
- Monitoring: `smo mesh --health` + journald

---

## 8. 100-Node Topology (Tham Khảo)

**Lưu ý:** 100-node chưa được verify. Đây là thiết kế kỳ vọng.

```
OpenVPN subnet: 10.8.0.0/22 (1022 addresses)
```

**Thiết kế kỳ vọng:**
- Multi-authority: 3–5 authority nodes
- Mỗi authority quản lý ~20–30 workers
- Gossip fanout: 6
- Heartbeat interval: 10s
- Anti-entropy: 10min
- TCP connection pool: duy trì kết nối đến peers thường xuyên

**Benchmark expectations:**
- Memory: ~50MB/daemon
- CPU: <5% idle, ~20% under load
- Network: ~10KB/s/node baseline
- Discovery convergence: <60s

---

## 9. Failure Scenarios

| Scenario | Dấu hiệu | Hành động |
|----------|----------|-----------|
| Authority die | `smo mesh --health` → DEGRADED | `systemctl restart smo-node` trên cloud |
| Worker die | Node không heartbeat | `systemctl restart smo-node` trên local |
| OpenVPN server die | Mất kết nối VPN | `systemctl restart openvpn@server` |
| OpenVPN client die | tun0 down | `systemctl restart openvpn-client@client` |
| Network partition | Gossip không converge | Chờ auto-recover (anti-entropy) |
| Split-brain | Hai partition riêng | Rejoin → merge qua anti-entropy |
| Disk full | SQLite write fail | `df -h`, cleanup old audit logs |
| Identity loss | `smo-node --init` báo error | Restore từ backup, re-enroll |
| Join token expired | `smo-node --join` báo error | Tạo lại: `smo-admin generate-invite Worker` |

### Quick recovery commands

```bash
# Smo-node crash
systemctl restart smo-node

# OpenVPN restart
systemctl restart openvpn@server        # cloud
systemctl restart openvpn-client@client # local

# Full service restart (không mất identity)
systemctl restart openvpn@server smo-node

# Full system rebuild (mất identity — cần re-enroll)
bash scripts/deploy-cloud.sh <vps-ip>   # re-run
```

---

## 10. Operations Checklist

### Hàng ngày

```
☐ smo mesh --health (tất cả node online?)
☐ journalctl -u smo-node --since "1 hour ago" | grep -i "error|warn"
☐ df -h (disk usage)
☐ ping 10.8.0.1 (VPN connectivity)
```

### Hàng tuần

```
☐ Chaos test: bash chaos-test.sh --quick
☐ Governance: kiểm tra epoch hiện tại
☐ Audit: smo history
☐ Backup: cp -r /var/lib/smo /backup/
```

### Hàng tháng

```
☐ Full chaos test: bash chaos-test.sh
☐ Update SMO: git pull && cmake --build
☐ Rotate join tokens (nếu cần)
☐ Kiểm tra recovery.pkg passphrase còn hoạt động không
☐ Review logs: journalctl -u smo-node --since "30 days ago" | grep -i error | sort | uniq -c
```

### Pre-production checklist

```
☐ Port 1194/udp mở trên cloud VPS firewall
☐ Port 7777/tcp mở trên cloud VPS firewall
☐ IP forwarding enabled: sysctl net.ipv4.ip_forward = 1
☐ NAT rule: iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
☐ SMO_RECOVERY_PASSPHRASE set (env hoặc prompted)
☐ 24 PCT tests pass
☐ clang-tidy zero errors
```

---

## 11. Troubleshooting

### "Connection refused" khi join

```bash
# Kiểm tra firewall trên cloud
ufw status
iptables -L -n | grep 7777

# Kiểm tra smo-node đang chạy
systemctl status smo-node
journalctl -u smo-node -n 50

# Kiểm tra seed node listen
nc -zv <cloud-ip> 7777
```

### "No route to host"

```bash
# Kiểm tra OpenVPN
ip addr show tun0
systemctl status openvpn@server
ping 10.8.0.1

# Kiểm tra routing
ip route
traceroute 10.8.0.1
```

### Gossip không converge

```bash
# Kiểm tra membership table
smo mesh --health

# Restart gossip
systemctl restart smo-node

# Kiểm tra anti-entropy log
journalctl -u smo-node | grep -i "anti.entropy|sync|delta"
```

### Join token expired

```bash
# Trên cloud: gen token mới (168h = 7 days)
smo-admin generate-invite Worker --expire 168h --endpoint <cloud-ip>:7777 \
    > /root/join-token-new.txt

# Trên local: re-join với token mới
smo-node --join "$(cat join-token-new.txt)" --data /var/lib/smo --name $(hostname) --port 7777
```

---

## 12. SMO Cluster State Reference

| State | Ý nghĩa | Hành động |
|-------|---------|-----------|
| ONLINE | Authority hoạt động, bootstrap configured | Normal |
| DEGRADED | Authority không reachable, gossip vẫn chạy | Kiểm tra cloud VPS |
| OFFLINE | Node không heartbeat trong timeout | Restart node |
| CONVERGED | Anti-entropy đồng bộ xong | Normal |
| PARTITIONED | Network split, hai cluster riêng | Chờ auto-heal, kiểm tra network |

---

## 13. Architecture Decision Records (cho v0.0.3)

| Decision | Lựa chọn | Alternative | Lý do |
|----------|----------|-------------|-------|
| VPN | OpenVPN | WireGuard | Dễ cấu hình, PKI built-in, nhiều docs |
| Subnet | 10.8.0.0/24 | 10.0.0.0/8 | Mặc định của OpenVPN, tránh conflict |
| Auth flow | Join token (signed) | CSR manual | Zero-touch enrollment |
| Systemd | Restart on-failure | Docker | Direct integration, simpler debug |
| Chaos test | Shell script | Ansible/Python | No dependency, run anywhere |
| Deploy script | Shell | Ansible/Chef/Puppet | Zero dependencies, readable |
| Package | DEB (CPack) | Custom build | Tận dụng CMake build system |

---

## 14. Workaround: CSR Path (khi join-token bị block)

Cho tới khi bug recovery.pkg được fix, dùng CSR path:

```bash
# Trên node worker (local machine)
smo-node --init --name local-a --data /var/lib/smo          # tạo identity + CSR
smo-node --export /var/lib/smo/node.csr.smor --data /var/lib/smo

# Chuyển CSR sang cloud node (scp / copy)
scp /var/lib/smo/node.csr.smor root@<vps-ip>:/tmp/

# Trên cloud node (authority) — sign CSR
smo-admin --mesh SOC-Production sign /tmp/node.csr.smor -o /tmp/node.cert.smoc

# Chuyển cert ngược về worker
scp root@<vps-ip>:/tmp/node.cert.smoc /var/lib/smo/

# Trên worker — import cert
smo-node --import /var/lib/smo/node.cert.smoc --data /var/lib/smo

# Chạy daemon
smo-node --daemon --port 7777 --data /var/lib/smo --name local-a --seed 10.8.0.1:7777
```

Lặp lại cho từng local machine.

---

> Deployment Guide này là output chính của v0.0.3.  
> Mục tiêu: bất kỳ ai có VPS + 2 máy Linux đều có thể deploy SMO mesh trong <30 phút.
