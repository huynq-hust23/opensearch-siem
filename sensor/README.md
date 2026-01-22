# Network Security Sensor Configuration

Cấu hình máy Linux làm Network Security Sensor cho hệ thống SIEM.

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
# Deploy tất cả cấu hình
sudo ./deploy.sh  

# Cập nhật Threat Intelligence
sudo ./update-ti.sh
```

## Thông tin dịch vụ

| Dịch vụ | Phiên bản | Log Path |
|---------|-----------|----------|
| Suricata | 8.0.2 | /var/log/suricata/eve.json |
| Filebeat | 8.19.9 | /var/log/filebeat/ |

## Output Logstash

- **Host:** IP máy chạy Docker Compose (ví dụ: `127.0.0.1` nếu sensor chạy cùng máy với Logstash publish port `5044`)
- **Port:** 5044

## Threat Intelligence

- **Spamhaus DROP:** IP ranges độc hại
- **blocklist.de:** IP các attacker đã biết
