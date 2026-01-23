# SIEM Lab (OpenSearch + Suricata) — Hướng dẫn cài đặt chi tiết

Dự án này dựng một lab SIEM tối giản để thu thập & phân tích log Suricata:

- **Lab tấn công/phòng thủ (Docker Compose)**: OpenSearch cluster, OpenSearch Dashboards, Logstash, DVWA (victim), Kali (attacker), router (kết nối 2 mạng), MailHog (nhận email alert).
- **Network Security Sensor (máy Linux)**: Suricata + Filebeat gửi `eve.json` về Logstash.

## 1) Yêu cầu môi trường

### Hệ điều hành
- Khuyến nghị: **Ubuntu/Debian Linux** (có `systemd`, `iptables`).

### Phần mềm bắt buộc
- **Docker Engine** và **Docker Compose** (plugin `docker compose` hoặc binary `docker-compose`).
- `bash`, `curl`, `python3`.

Gợi ý (để khỏi phải `sudo docker`):

```bash
sudo usermod -aG docker "$USER"
# đăng xuất/đăng nhập lại để group có hiệu lực
```

### Cổng sử dụng

- `9200/tcp`: OpenSearch (HTTPS)
- `5601/tcp`: OpenSearch Dashboards
- `5044/tcp`: Logstash Beats input (Filebeat → Logstash)
- `5000/tcp`: Logstash TCP input (dùng cho `simulate_usecases.sh`)
- `8080/tcp`: DVWA
- `8025/tcp`: MailHog Web UI
- `1025/tcp`: MailHog SMTP (publish ra host; trong docker dùng hostname `mailhog`) 

### Kernel/sysctl (hay bị thiếu)

OpenSearch thường yêu cầu `vm.max_map_count` đủ lớn (nếu không container có thể crash/không lên ổn định).

```bash
sudo sysctl -w vm.max_map_count=262144
```

Để cấu hình bền vững sau reboot:

```bash
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-opensearch.conf >/dev/null
sudo sysctl --system >/dev/null
```

### Tài nguyên khuyến nghị
- RAM: tối thiểu ~ **6–8GB** (OpenSearch chạy nhiều node).
- Đĩa: tối thiểu **15GB** trống.

## 2) Tổng quan kiến trúc & luồng dữ liệu

1. Suricata (sensor) ghi log: `/var/log/suricata/eve.json` và `/var/log/suricata/fast.log`.
2. Filebeat đọc `eve.json` và gửi về **Logstash Beats input** (`5044`).
3. Logstash parse/enrich (TI + GeoIP mock) và đẩy vào **OpenSearch ingest node**.
4. OpenSearch Alerting monitors + Notifications gửi email alert sang **MailHog**.

## 3) Cấu trúc repo (quan trọng)

- `docker-compose.yml`: dựng OpenSearch/Logstash/Dashboards/DVWA/Kali/router/MailHog.
- `logstash/pipeline/logstash.conf`: pipeline ingest (Beats 5044 + TCP 5000) → OpenSearch.
- `configs/suricata.yaml`, `configs/custom.rules`: cấu hình & rule Suricata (HOME/EXTERNAL cho lab).
- `deploy-configs.sh`: copy configs Suricata vào `/etc/suricata/...`.
- `scripts/enable_lab_routing.sh`: bật routing giữa 2 bridge Docker (giữ nguyên source IP).
- `sensor/deploy.sh`: deploy Filebeat module + TI + restart services.
- `setup_index_templates.sh`, `setup_email.sh`, `setup_monitors.sh`: cấu hình OpenSearch template/Notifications/Alerting.
- `simulate_usecases.sh`: mô phỏng an toàn (không tấn công thật) để kiểm thử end-to-end.

## 4) Cài đặt nhanh (khuyến nghị)

### Bước 0 — Tạo file `.env` (bắt buộc)

Dự án dùng biến môi trường để các script gọi OpenSearch.
Tạo file `.env` tại thư mục root (cùng cấp `docker-compose.yml`):

```bash
cat > .env <<'EOF'
# Bắt buộc: mật khẩu admin cho OpenSearch (dùng khi container khởi tạo)
OPENSEARCH_INITIAL_ADMIN_PASSWORD=ChangeMe_ReallyStrong_123

# Tuỳ chọn (các script mặc định như bên dưới)
OPENSEARCH_URL=https://localhost:9200
OPENSEARCH_USER=admin
# OPENSEARCH_PASSWORD=ChangeMe_ReallyStrong_123

# Khi chạy simulate_usecases.sh (TCP input của Logstash)
LOGSTASH_HOST=127.0.0.1
LOGSTASH_PORT=5000

# MailHog UI/API
MAILHOG_API=http://127.0.0.1:8025
EOF
```

Lưu ý:
- `OPENSEARCH_INITIAL_ADMIN_PASSWORD` **bắt buộc** (compose sẽ dùng biến này).
- Các script dùng `-k` để bỏ qua kiểm tra TLS khi gọi `https://localhost:9200`.

Nạp biến môi trường từ `.env` vào phiên shell hiện tại (để các lệnh `curl ...${OPENSEARCH_INITIAL_ADMIN_PASSWORD}` chạy được):

```bash
set -a
source .env
set +a
```

### Bước 1 — Start Docker Compose

Tại thư mục root:

```bash
# Nếu máy bạn cần sudo cho docker
# sudo docker compose up -d

docker compose up -d
```

Lưu ý: lần khởi động đầu tiên, OpenSearch có thể mất 1–3 phút để sẵn sàng.

Health-check nhanh:

```bash
docker compose ps

# OpenSearch (đăng nhập bằng admin + OPENSEARCH_INITIAL_ADMIN_PASSWORD)
curl -k -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" https://localhost:9200

# Xem các index đã có (nếu OpenSearch đã sẵn sàng)
curl -k -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" "https://localhost:9200/_cat/indices?v" | head
```

Kiểm tra nhanh:
- OpenSearch: `https://localhost:9200`
- Dashboards: `http://localhost:5601`
- DVWA: `http://localhost:8080`
- MailHog: `http://localhost:8025`

Thông tin đăng nhập:
- OpenSearch Dashboards: user `admin`, password = `OPENSEARCH_INITIAL_ADMIN_PASSWORD` trong `.env`

Lưu ý TLS:
- OpenSearch chạy HTTPS với chứng chỉ self-signed; khi dùng `curl` hãy dùng `-k` như các ví dụ.

### Bước 2 — Bật routing lab (để Kali ↔ DVWA thông nhau)

Dự án tạo 2 mạng bridge:
- `attacker-net`: `172.30.10.0/24` (Kali: `172.30.10.10`)
- `server-net`: `172.30.20.0/24` (DVWA: `172.30.20.10`)

Bật forwarding qua `DOCKER-USER` (không NAT, giữ nguyên source IP):

```bash
sudo bash scripts/enable_lab_routing.sh
```

Test nhanh từ container Kali (sau khi bật routing):

```bash
docker exec -it kali-attacker bash -lc 'apt-get update -qq >/dev/null 2>&1 || true; command -v curl >/dev/null 2>&1 || apt-get install -y -qq curl >/dev/null 2>&1; curl -I http://172.30.20.10/ | head -n 1'
```

Tắt routing khi cần:

```bash
sudo bash scripts/disable_lab_routing.sh
```

### Bước 3 — (Trên máy sensor) Cài Suricata + Filebeat

Nếu bạn chạy sensor **trên cùng máy** với Docker Compose thì mọi thứ đơn giản nhất.
Nếu sensor là máy khác, vẫn làm tương tự nhưng **phải chỉnh `output.logstash.hosts`** trong Filebeat trỏ về IP máy chạy compose.

Yêu cầu:
- Dịch vụ `suricata` và `filebeat` chạy bằng `systemd`.
- Log Suricata có `eve.json` ở `/var/log/suricata/eve.json`.

#### Cài Suricata + Filebeat trên Ubuntu/Debian (apt)

Các lệnh dưới đây phù hợp cho Ubuntu/Debian (cần quyền `sudo`). Tùy distro, version Suricata/Filebeat có thể khác nhau; miễn là có `eve.json` và Filebeat gửi được về Logstash là dùng được.

1) Cài Suricata:

```bash
sudo apt-get update
sudo apt-get install -y suricata

# kiểm tra
suricata -V
sudo systemctl enable --now suricata
```

2) Cài Filebeat (Elastic Beats) bằng APT repo:

```bash
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg

# Import GPG key
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /etc/apt/keyrings/elastic.gpg
sudo chmod 0644 /etc/apt/keyrings/elastic.gpg

# Add repository
echo "deb [signed-by=/etc/apt/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/elastic-8.x.list >/dev/null

sudo apt-get update
sudo apt-get install -y filebeat
sudo systemctl enable --now filebeat
```

Sau khi cài xong Suricata/Filebeat, làm tiếp **Bước 4** (deploy cấu hình Suricata) và **Bước 5** (deploy cấu hình Filebeat) bên dưới.

### Bước 4 — Deploy cấu hình Suricata (HOME/EXTERNAL cho lab)

`configs/suricata.yaml` đã cấu hình capture `af-packet` trên 2 bridge Docker:
- `br-attacker-net`
- `br-server-net`

Quan trọng:
- Bước này phù hợp khi sensor chạy **trên đúng máy Docker host** (vì mới có 2 interface bridge như trên).
- Nếu sensor là **máy khác** (không có `br-attacker-net/br-server-net`), bạn cần chỉnh capture interface trong `/etc/suricata/suricata.yaml` về NIC thật của sensor (ví dụ `eth0`, `ens160`, ...), hoặc dùng cấu hình Suricata phù hợp môi trường của bạn.

Deploy configs:

```bash
sudo bash deploy-configs.sh
```

Nếu Suricata không start do thiếu runtime dir `/run/suricata`, dùng script fix:

```bash
sudo bash scripts/fix_suricata_systemd_runtime.sh
```

### Bước 5 — Deploy cấu hình sensor (Filebeat module + TI)

```bash
sudo bash sensor/deploy.sh
```

Nếu sensor chạy khác máy với Logstash:
- Sửa `output.logstash.hosts` trong `sensor/filebeat/filebeat.yml` (hoặc trực tiếp `/etc/filebeat/filebeat.yml`) từ `127.0.0.1:5044` thành `IP_MAY_DOCKER:5044`.
- Restart: `sudo systemctl restart filebeat`.

## 5) Thiết lập OpenSearch (template/email/monitors)

Các script dưới đây đọc `.env` ở root.

Khuyến nghị đợi OpenSearch lên hẳn trước khi chạy setup:

```bash
set -a; source .env; set +a
until curl -k -s -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" https://localhost:9200 >/dev/null; do
  echo "Waiting for OpenSearch..."; sleep 2;
done
```

```bash
bash setup_index_templates.sh
bash setup_email.sh
bash setup_monitors.sh
```

Kiểm tra nhanh sau khi setup:

```bash
# template
curl -k -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" https://localhost:9200/_index_template/siem-suricata-template | head

# monitors (danh sách)
curl -k -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" -XPOST https://localhost:9200/_plugins/_alerting/monitors/_search \
  -H 'Content-Type: application/json' -d '{"size":50,"query":{"match_all":{}}}' | head
```

Gợi ý kiểm tra email alert:
- Mở MailHog: `http://localhost:8025`

## 6) Kiểm thử end-to-end (khuyến nghị)

### Cách A — Mô phỏng an toàn (không tấn công thật)

Script `simulate_usecases.sh` sẽ:
- ensure index template
- tạo Notifications email channel (MailHog)
- tạo Alerting monitors
- gửi **sự kiện Suricata giả lập** vào Logstash TCP input (`5000/tcp`)
- execute monitors ngay để bạn thấy email trong MailHog

Chạy:

```bash
bash simulate_usecases.sh
```

### Cách B — Tạo traffic tấn công từ Kali tới DVWA

1) Mở một terminal để theo dõi alert Suricata trên máy sensor:

```bash
sudo bash verify_detection.sh
```

2) Tạo traffic tấn công (script sẽ `docker exec` vào container Kali):

```bash
bash attack_traffic.sh
```

Dừng bằng `Ctrl+C`.

Ngoài ra có các script theo use-case trong `attack_scripts/` (ví dụ `attack_scripts/uc01_sqli.sh`). Một số script (như `uc06_port_scan.sh`) cần tool như `nmap` trong môi trường chạy script.

Gợi ý nếu muốn chạy `nmap` bên trong Kali container:

```bash
docker exec -it kali-attacker bash -lc 'apt-get update && apt-get install -y nmap'
```

## 7) Troubleshooting nhanh

- **OpenSearch không lên / crash**: kiểm tra `vm.max_map_count` đã set `262144` chưa (mục “Kernel/sysctl”).
- **Không có bridge `br-attacker-net` / `br-server-net`**: đảm bảo `docker compose up -d` đã chạy trước khi `enable_lab_routing.sh`.
- **Suricata không start**: thử `sudo bash scripts/fix_suricata_systemd_runtime.sh` rồi `sudo systemctl status suricata`.
- **Filebeat không gửi log**:
  - kiểm tra `/var/log/filebeat/filebeat` và `sudo systemctl status filebeat`
  - kiểm tra `output.logstash.hosts` trỏ đúng IP/port `5044`
  - kiểm tra Logstash publish port `5044` trong compose.
- **Không thấy index `siem-suricata-*`**: kiểm tra pipeline Logstash (`logstash/pipeline/logstash.conf`) và xem stdout logs của container Logstash.

Xem logs nhanh:

```bash
docker logs --tail=200 logstash
docker logs --tail=200 opensearch-manager
docker logs --tail=200 opensearch-dashboards
```

## 8) Reset/Cleanup lab (tuỳ chọn)

```bash
# Stop toàn bộ stack
docker compose down

# Xoá cả volume dữ liệu OpenSearch (mất dữ liệu index)
docker compose down -v
```

---

Tài liệu sensor chi tiết xem thêm: [sensor/README.md](sensor/README.md)
