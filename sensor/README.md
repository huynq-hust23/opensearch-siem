# Network Security Sensor (Suricata + Filebeat)

Tài liệu này hướng dẫn cài đặt/triển khai **máy sensor** (Linux) để thu thập log mạng bằng **Suricata** và đẩy log sang **Logstash** bằng **Filebeat**.

Hướng dẫn dựng toàn bộ lab (Docker Compose + OpenSearch/Logstash/DVWA/Kali/MailHog) xem: [README.md](../README.md)

## Cấu trúc thư mục

```
sensor/
├── filebeat/
│   ├── filebeat.yml           # Cấu hình chính Filebeat
│   └── modules.d/
│       ├── suricata.yml       # Module Suricata
├── suricata/
│   └── suricata.yaml          # Copy từ /etc/suricata/suricata.yaml
├── threat-intel/
│   ├── spamhaus_drop.txt      # Spamhaus DROP list
│   └── blocklist_de.txt       # blocklist.de IP list
├── deploy.sh                  # Script deploy cấu hình
├── update-ti.sh               # Script cập nhật Threat Intelligence
└── README.md                  # File này
```

## Cài đặt nhanh

```bash
# Deploy Filebeat module + Threat Intel + restart services
sudo ./deploy.sh

# (Tuỳ chọn) Cập nhật Threat Intelligence
sudo ./update-ti.sh
```

## Điều kiện tiên quyết

- Máy Linux có `systemd`.
- Đã cài và chạy được các dịch vụ:
	- `suricata` (ghi log về `/var/log/suricata/eve.json`)
	- `filebeat`
- Logstash (ở máy SIEM) đã mở cổng **5044** (beats input).

## Cấu hình Logstash output (quan trọng)

File cấu hình Filebeat trong repo đặt ở: `sensor/filebeat/filebeat.yml`.

- Mặc định đang để:
	- `output.logstash.hosts: ["127.0.0.1:5044"]`
- Nếu sensor chạy **khác máy** với Logstash, hãy sửa thành IP máy chạy Docker Compose, ví dụ:
	- `output.logstash.hosts: ["192.168.1.10:5044"]`

Sau đó deploy lại hoặc sửa trực tiếp `/etc/filebeat/filebeat.yml` rồi restart:

```bash
sudo systemctl restart filebeat
```

## Thông tin dịch vụ

| Dịch vụ | Phiên bản | Log Path |
|---------|-----------|----------|
| Suricata | 8.0.2 | /var/log/suricata/eve.json |
| Filebeat | 8.19.9 | /var/log/filebeat/ |

## Deploy cấu hình

Script `deploy.sh` sẽ:

1) Copy Filebeat config + Suricata module vào:
- `/etc/filebeat/filebeat.yml`
- `/etc/filebeat/modules.d/suricata.yml`

2) Copy Threat Intelligence vào:
- `/var/lib/threat-intel/`

3) Restart & enable auto-start:
- `systemctl restart suricata filebeat`
- `systemctl enable suricata filebeat`

## Threat Intelligence

- **Spamhaus DROP:** IP ranges độc hại
- **blocklist.de:** IP các attacker đã biết

## Kiểm tra nhanh

- Trạng thái dịch vụ:

```bash
systemctl --no-pager -l status suricata
systemctl --no-pager -l status filebeat
```

- Log Suricata:
	- `/var/log/suricata/eve.json`
	- `/var/log/suricata/fast.log`

- Log Filebeat:
	- `/var/log/filebeat/`
