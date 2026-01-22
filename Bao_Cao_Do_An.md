# BÁO CÁO ĐỒ ÁN TỐT NGHIỆP
## ĐỀ TÀI: XÂY DỰNG HỆ THỐNG GIÁM SÁT AN TOÀN MẠNG (SIEM) TẬP TRUNG SỬ DỤNG OPENSEARCH VÀ SURICATA TRÊN NỀN TẢNG CONTAINER

---

**Sinh viên thực hiện:** [Tên Sinh Viên]
**Mã sinh viên:** [Mã Sinh Viên]
**Lớp:** [Lớp]
**Giảng viên hướng dẫn:** [Tên Giảng Viên]

---

## MỤC LỤC

1.  [CHƯƠNG 1: TỔNG QUAN VỀ ĐỀ TÀI](#chương-1-tổng-quan-về-đề-tài)
2.  [CHƯƠNG 2: CƠ SỞ LÝ THUYẾT VÀ CÔNG NGHỆ](#chương-2-cơ-sở-lý-thuyết-và-công-nghệ)
3.  [CHƯƠNG 3: PHÂN TÍCH VÀ THIẾT KẾ HỆ THỐNG](#chương-3-phân-tích-và-thiết-kế-hệ-thống)
    *   3.1. Phân tích yêu cầu và Đặc tả kỹ thuật
    *   3.2. Thiết kế Kiến trúc Hệ thống (System Architecture)
    *   3.3. Thiết kế Luồng dữ liệu và Pipeline xử lý (Data Flow Design)
    *   3.4. Thiết kế Cơ sở dữ liệu và Quy hoạch Index (Database Design)
    *   3.5. Thiết kế Kịch bản Giám sát và Cảnh báo (Detection Logic)
4.  [CHƯƠNG 4: TRIỂN KHAI VÀ CẤU HÌNH](#chương-4-triển-khai-và-cấu-hình)
5.  [CHƯƠNG 5: KIỂM THỬ VÀ ĐÁNH GIÁ](#chương-5-kiểm-thử-và-đánh-giá)
6.  [KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN](#kết-luận-và-hướng-phát-triển)

---

## CHƯƠNG 1: TỔNG QUAN VỀ ĐỀ TÀI

*(Giữ nguyên nội dung đã viết ở phiên bản trước)*

---

## CHƯƠNG 2: CƠ SỞ LÝ THUYẾT VÀ CÔNG NGHỆ

*(Giữ nguyên nội dung đã viết ở phiên bản trước)*

---

## CHƯƠNG 3: PHÂN TÍCH VÀ THIẾT KẾ HỆ THỐNG

### 3.1. Phân tích yêu cầu và Đặc tả kỹ thuật

Hệ thống SIEM được thiết kế để giải quyết bài toán giám sát an ninh mạng trong môi trường doanh nghiệp hiện đại, ứng dụng công nghệ container để tối ưu hóa khả năng mở rộng và vận hành.

#### 3.1.1. Yêu cầu chức năng (Functional Requirements)
Hệ thống cần đáp ứng các nhóm chức năng cốt lõi sau:
1.  **Thu thập dữ liệu đa nguồn (Multi-source Collection):**
    *   Hỗ trợ thu thập log từ network sensor (Suricata) qua định dạng chuẩn JSON.
    *   Hỗ trợ mở rộng thu thập log từ hệ điều hành (Syslog, Winlogbeat) trong tương lai.
2.  **Chuẩn hóa và Tương quan dữ liệu (Normalization & Correlation):**
    *   Dữ liệu thô phải được mapping về chuẩn ECS (Elastic Common Schema) để thống nhất tên trường (ví dụ: `src_ip` -> `source.ip`).
    *   Thực hiện tương quan sự kiện: Kết hợp nhiều log rời rạc để xác định một cuộc tấn công phức hợp (ví dụ: Brute Force = nhiều lần đăng nhập sai liên tiếp).
3.  **Làm giàu dữ liệu thời gian thực (Real-time Enrichment):**
    *   **GeoIP Lookup:** Tự động phân giải IP công cộng thành thông tin địa lý (Quốc gia, Thành phố, Tọa độ) phục vụ vẽ bản đồ Threat Map.
    *   **Threat Intel Integration:** Tích hợp các nguồn tin tình báo (OSINT) như AlienVault, Blocklist.de để phát hiện sớm các IP/Domain độc hại.
4.  **Cảnh báo tức thời (Real-time Alerting):**
    *   Gửi cảnh báo qua đa kênh (Email, Slack, Webhook) khi phát hiện sự kiện có độ nghiêm trọng cao (Severity level 1).
    *   Hỗ trợ ngưỡng kích hoạt (Threshold): Ví dụ chỉ cảnh báo khi có > 50 request/phút.

#### 3.1.2. Yêu cầu phi chức năng (Non-functional Requirements)
*   **Hiệu năng (Performance):** Đảm bảo xử lý được lưu lượng log đầu vào tối thiểu 1000 EPS (Events Per Second) mà không bị mất gói tin. Độ trễ hiển thị (Ingestion Lag) < 5 giây.
*   **Tính sẵn sàng (Availability):** Kiến trúc Cluster cho phép hệ thống hoạt động liên tục ngay cả khi một node xử lý gặp sự cố.
*   **An toàn bảo mật (Security):** Toàn bộ giao tiếp giữa các thành phần (Filebeat -> Logstash -> OpenSearch) phải được mã hóa TLS. Dữ liệu lưu trữ phải được phân quyền truy cập (RBAC).

---

### 3.2. Thiết kế Kiến trúc Hệ thống (System Architecture)

Hệ thống được thiết kế theo mô hình **Microservices Architecture**, trong đó mỗi thành phần chạy trong một Container riêng biệt, giao tiếp với nhau qua Docker Network. Kiến trúc này bao gồm 3 lớp chính:

#### 3.2.1. Lớp Thu thập và Cảm biến (Sensing & Collection Layer)
*   **Network Sensor (Suricata):**
    *   Hoạt động ở chế độ *Passive Sniffing* (Promiscuous mode) trên lớp mạng vật lý hoặc ảo.
    *   Sử dụng thư viện `AF_PACKET` v3 (Linux Kernel) để bắt gói tin tốc độ cao với cơ chế Zero-copy.
    *   Deep Packet Inspection (DPI): Phân tích sâu nội dung gói tin (Payload) để phát hiện chữ ký tấn công (Signature Matching).
*   **Log Shipper (Filebeat):**
    *   Đảm nhiệm vai trò vận chuyển log tin cậy (Reliable shipping).
    *   Cơ chế *Backpressure*: Tự động giảm tốc độ gửi log nếu Logstash/OpenSearch bị quá tải, tránh mất dữ liệu.

#### 3.2.2. Lớp Xử lý trung tâm (Core Processing Layer)
*   **Logstash Cluster:**
    *   Hoạt động như một ETL Engine (Extract-Transform-Load).
    *   Sử dụng kiến trúc Pipeline đa luồng (Worker Threads) để xử lý song song các sự kiện.
    *   Tích hợp bộ nhớ đệm (In-memory Lookup) để thực hiện làm giàu dữ liệu (GeoIP, Threat Intel) với độ trễ cực thấp O(1).

#### 3.2.3. Lớp Lưu trữ và Phân tích (Storage & Analytics Layer)
*   **OpenSearch Cluster:**
    *   Lưu trữ dữ liệu dưới dạng các Shard (phân mảnh) phân tán trên các node.
    *   Kiến trúc Master-Data Node tách biệt:
        *   *Master Node:* Quản lý trạng thái Cluster, không chứa dữ liệu.
        *   *Data Node:* Chứa dữ liệu và thực hiện các truy vấn tìm kiếm/tính toán nặng.
*   **OpenSearch Dashboards:**
    *   Giao diện trực quan hóa, kết nối tới OpenSearch qua REST API.

---

### 3.3. Thiết kế Luồng dữ liệu và Pipeline xử lý (Data Flow Design)

Luồng dữ liệu (Data Pipeline) được thiết kế chi tiết như sau:

**Bước 1: Packet Capture & Decoding**
*   Suricata bắt gói tin Ethernet Frame từ interface `br-attacker-net`.
*   Decode các giao thức tầng dưới (TCP/UDP/ICMP) và tầng ứng dụng (HTTP/DNS/TLS).
*   Kết quả phân tích được serialize thành định dạng JSON và ghi vào `/var/log/suricata/eve.json`.

**Bước 2: Log Ingestion & Buffering**
*   Filebeat đọc file `eve.json` (Input: Log).
*   Thêm các metadata định danh (ví dụ: `agent.version`, `host.name`).
*   Gửi dữ liệu qua giao thức `Lumberjack` (TCP/5044) tới Logstash.

**Bước 3: Data Transformation (Logstash Logic)**
Quá trình xử lý tại Logstash diễn ra qua 3 bộ lọc chính:
1.  **JSON Filter:** Parse chuỗi JSON thành object.
2.  **Date Filter:** Đồng bộ hóa trường `@timestamp` của log với thời gian thực của sự kiện (thay vì thời gian log được ingestion).
3.  **GeoIP & Threat Intelligence Filter:**
    *   *Logic:* Sử dụng plugin `translate` để so khớp IP với cơ sở dữ liệu mối đe dọa.
    *   *Thực thi (Implementation):*
        ```ruby
        if [source][ip] in [blacklist] {
          mutate { add_tag => "threat_matched" }
        }
        ```

**Bước 4: Indexing & Storage**
*   Dữ liệu sau xử lý được đẩy vào OpenSearch qua Bulk API (gửi theo lô 500-1000 document/lần để tối ưu IOPS).
*   Dữ liệu được ghi vào Index tương ứng, ví dụ `siem-suricata-2023.10.25`.

---

### 3.4. Thiết kế Cơ sở dữ liệu và Quy hoạch Index (Database Design)

Khác với RDBMS truyền thống, OpenSearch là cơ sở dữ liệu hướng tài liệu (Document-oriented). Việc thiết kế tập trung vào quy hoạch Index và Mapping.

#### 3.4.1. Chiến lược quản lý Index (Index Lifecycle Management - ISM)
Hệ thống sử dụng chiến lược Hot-Warm-Delete để quản lý vòng đời dữ liệu:
*   **Hot Phase (0-7 ngày):** Index được lưu trên SSD, ưu tiên tốc độ ghi và đọc. Cấu hình 1 Primary Shard, 1 Replica Shard.
*   **Delete Phase (>30 ngày):** Tự động xóa Index để giải phóng không gian lưu trữ.

#### 3.4.2. Đặc tả cấu trúc dữ liệu (Schema Definition)
Sử dụng chuẩn ECS (Elastic Common Schema) để chuẩn hóa dữ liệu:

| Tên trường (Field) | Kiểu (Type) | Mô tả (Description) | Ví dụ giá trị |
| :--- | :--- | :--- | :--- |
| `@timestamp` | `date` | Thời gian xảy ra sự kiện | `2023-10-25T14:30:00Z` |
| `event.module` | `keyword` | Module sinh ra log | `suricata` |
| `event.category` | `keyword` | Phân loại sự kiện | `intrusion_detection` |
| `source.ip` | `ip` | Địa chỉ IP nguồn | `172.30.10.10` |
| `destination.ip` | `ip` | Địa chỉ IP đích | `172.30.20.10` |
| `source.geo.country_name` | `keyword` | Quốc gia nguồn | `Russia` |
| `suricata.alert.severity` | `integer` | Mức độ nghiêm trọng (1-4) | `1` |
| `suricata.alert.signature` | `text` | Tên chữ ký phát hiện | `ET SQL Injection` |

---

### 3.5. Thiết kế các Kịch bản Giám sát và Cảnh báo (Detection Logic)

Hệ thống được thiết kế để phát hiện diện rộng các hành vi bất thường. Tập luật giám sát được chia thành 4 nhóm chính với tổng cộng 15 Use Cases chi tiết:

#### Nhóm 1: Tấn công Ứng dụng Web (Web Application Attacks)

**UC01: SQL Injection (SQLi)**
*   *Mô tả:* Phát hiện nỗ lực chèn mã SQL vào tham số đầu vào HTTP (GET/POST) để thao tác cơ sở dữ liệu trái phép.
*   *Logic:* `suricata.alert.signature` chứa "SQL Injection" HOẶC `http.url` khớp regex `(union|select|insert|delete|update).*`.
*   *Severity:* Critical (1).

**UC02: Cross-Site Scripting (XSS)**
*   *Mô tả:* Phát hiện nỗ lực chèn mã script độc hại (Javascript) vào ứng dụng web.
*   *Logic:* `http.url` hoặc `http.request.body` chứa thẻ `<script>` hoặc các hàm `alert()`, `document.cookie`.
*   *Severity:* High (2).

**UC03: Path Traversal / LFI**
*   *Mô tả:* Phát hiện nỗ lực truy cập file hệ thống trái phép bằng cách sử dụng các ký tự `../` hoặc `%2e%2e`.
*   *Logic:* `http.url` chứa `../`, `..%2f` hoặc truy cập các file nhạy cảm như `/etc/passwd`.
*   *Severity:* High (2).

**UC04: Web Shell Upload**
*   *Mô tả:* Phát hiện hành vi tải lên các file mã độc (php, asp, jsp) để chiếm quyền điều khiển server.
*   *Logic:* Phương thức `POST` tới các endpoint upload file VÀ nội dung file chứa signature của web shell (ví dụ: `cmd.exe`, `eval()`).
*   *Severity:* Critical (1).

**UC05: Web Scanner Activity**
*   *Mô tả:* Phát hiện các công cụ rà quét lỗ hổng tự động (Nikto, Acunetix, Burp Suite).
*   *Logic:* `http.user_agent` khớp danh sách đen các User-Agent của tool scan.
*   *Severity:* Medium (3).

#### Nhóm 2: Thăm dò và Tấn công Mạng (Network Recon & Attacks)

**UC06: Port Scanning (Vertical Scan)**
*   *Mô tả:* Một nguồn IP cố gắng kết nối tới nhiều cổng khác nhau trên cùng một đích để tìm dịch vụ mở.
*   *Logic:* Aggregation: Count `destination.port` > 20 (distinct) trong 1 phút TỪ cùng một `source.ip`.
*   *Severity:* Medium (3).

**UC07: Host Sweeping (Horizontal Scan)**
*   *Mô tả:* Một nguồn IP cố gắng kết nối tới cùng một cổng (ví dụ 445 SMB) trên nhiều máy đích khác nhau.
*   *Logic:* Aggregation: Count `destination.ip` > 20 (distinct) trong 1 phút TỪ cùng một `source.ip`.
*   *Severity:* Medium (3).

**UC08: SSH Brute Force**
*   *Mô tả:* Phát hiện nỗ lực đoán mật khẩu SSH.
*   *Logic:* Nhiều kết nối SSH (`destination.port: 22`) có lưu lượng bytes nhỏ (chỉ bắt tay, không truyền dữ liệu) liên tiếp trong thời gian ngắn.
*   *Severity:* High (2).

**UC09: DoS/DDoS Attempt**
*   *Mô tả:* Phát hiện lưu lượng bất thường làm quá tải hệ thống.
*   *Logic:* Volume based: Số lượng gói tin (Packet count) từ một IP > 1000/giây (ICMP flood hoặc SYN flood).
*   *Severity:* Critical (1).

#### Nhóm 3: Mã độc và C2 (Malware & C2 Communication)

**UC10: C2 Beaconing**
*   *Mô tả:* Phát hiện malware gửi tín hiệu định kỳ (heartbeat) về máy chủ điều khiển (C2).
*   *Logic:* Các kết nối HTTP/DNS outbound có tính chu kỳ chính xác (Jitter thấp) tới một domain lạ.
*   *Severity:* Critical (1).

**UC11: DNS Tunneling/Exfiltration**
*   *Mô tả:* Phát hiện hành vi tuồn dữ liệu ra ngoài qua giao thức DNS.
*   *Logic:* `dns.question.name` có độ dài bất thường (> 180 ký tự) hoặc chứa chuỗi entropy cao (dữ liệu mã hóa).
*   *Severity:* High (2).

**UC12: Threat Intel Matched**
*   *Mô tả:* Kết nối tới IP/Domain nằm trong danh sách đen (Blacklist).
*   *Logic:* `tags: threat_matched` do Logstash gán.
*   *Severity:* Critical (1).

#### Nhóm 4: Bất thường địa lý và Hành vi (Anomaly & Behavior)

**UC13: Geofencing Violation**
*   *Mô tả:* Truy cập từ quốc gia bị cấm (Sanctioned Countries).
*   *Logic:* `source.geo.country_name` nằm trong danh sách cấm (VD: North Korea, Iran, hoặc Russia theo kịch bản).
*   *Severity:* High (2).

**UC14: Impossible Travel**
*   *Mô tả:* Một user đăng nhập từ 2 vị trí địa lý quá xa nhau trong thời gian ngắn (không thể di chuyển vật lý kịp).
*   *Logic:* Vận tốc di chuyển ảo > 1000km/h. (Yêu cầu tương quan log đăng nhập).
*   *Severity:* High (2).

**UC15: Data Exfiltration via HTTP**
*   *Mô tả:* Tuồn dữ liệu lượng lớn ra ngoài.
*   *Logic:* Kết nối Outbound HTTP có kích thước `http.request.body.bytes` cực lớn (> 100MB) tới IP lạ.
*   *Severity:* High (2).

---

## CHƯƠNG 4: TRIỂN KHAI VÀ CẤU HÌNH HE THỐNG TRÊN MÔI TRƯỜNG LAB

Chương này trình bày chi tiết quy trình triển khai hệ thống SIEM trên môi trường thực nghiệm. Nội dung bao gồm việc chuẩn bị hạ tầng ảo hóa, cấu hình chuyên sâu các phân hệ thu thập (Sensor), xử lý (Pipeline) và hiển thị (Dashboard), đồng thời giải thích các quyết định kỹ thuật (Design Decisions) đằng sau mỗi cấu hình.

### 4.1. Chuẩn bị và Quy hoạch Môi trường Thực nghiệm

Để đảm bảo tính khả thi và khả năng kiểm soát trong quá trình nghiên cứu, mô hình triển khai được xây dựng trên nền tảng ảo hóa với sự cô lập mạng nghiêm ngặt.

#### 4.1.1. Mô hình Mạng và Quy hoạch IP (Network Topology)
Hệ thống mạng được chia thành 3 phân vùng (Zone) riêng biệt, được phân tách bởi Router mềm (Software Router) để mô phỏng sát nhất với môi trường doanh nghiệp thực tế:

1.  **Attacker Zone (`attacker-net`):**
    *   **Subnet:** `172.30.10.0/24`
    *   **Thành phần:** Máy Kali Linux (Attacker - `172.30.10.10`).
    *   **Mục đích:** Giả lập môi trường Internet/External, nơi xuất phát các cuộc tấn công thâm nhập.

2.  **DMZ/Server Zone (`server-net`):**
    *   **Subnet:** `172.30.20.0/24`
    *   **Thành phần:** DVWA Web Server (Victim - `172.30.20.10`).
    *   **Mục đích:** Chứa các dịch vụ công khai cần được bảo vệ. Đây là vùng trọng tâm (Points of Interest) mà hệ thống SIEM sẽ giám sát.

3.  **Management/SIEM Zone (`opensearch-net`):**
    *   **Subnet:** `172.20.0.0/16` (Default Bridge).
    *   **Thành phần:** Cluster OpenSearch, Logstash, Dashboards.
    *   **Mục đích:** Vùng backend (Out-of-Band Management), tách biệt hoàn toàn với lưu lượng tấn công để đảm bảo an toàn cho dữ liệu log.

#### 4.1.2. Yêu cầu Tài nguyên Hệ thống (Hardware Requirements)
Hệ thống SIEM, đặc biệt là OpenSearch (nền tảng dựa trên Java/JVM), đòi hỏi tài nguyên tính toán đáng kể để hoạt động ổn định.

*   **Host OS:** Ubuntu Server 22.04 LTS Kernel 5.15+ (Hỗ trợ eBPF và AF_PACKET v3).
*   **CPU:** Tối thiểu 4 vCPU. Suricata cần ít nhất 2 luồng xử lý riêng biệt (1 cho Capture, 1 cho Analysis) để tránh hiện tượng rớt gói (Packet Loss) khi lưu lượng cao.
*   **RAM:** Tối thiểu 10GB.
    *   *OpenSearch Heap:* Cấu hình 512MB - 1GB Heap Size cho mỗi node (`-Xms512m -Xmx512m`) để tránh lỗi `OOMKilled`.
    *   *Suricata:* Cần bộ nhớ lớn cho bảng trạng thái Flow Table và TCP Reassembly.

#### 4.1.3. Công nghệ Ảo hóa Container (Containerization Strategy)
Đồ án sử dụng **Docker** và **Docker Compose** làm nền tảng triển khai. Việc lựa chọn công nghệ này dựa trên các lý do khoa học sau:
*   **Isolation (Cách ly):** Cô lập tiến trình tấn công, ngăn chặn mã độc lây lan ra máy chủ vật lý (Host).
*   **Reproducibility (Tính tái lập):** Toàn bộ cấu hình hạ tầng được định nghĩa dưới dạng code (IaC - Infrastructure as Code) trong file `docker-compose.yml`, giúp việc triển khai lại môi trường lab chỉ mất < 5 phút.

---

### 4.2. Triển khai và Tối ưu hóa Suricata Sensor

Sensor là thành phần tuyến đầu (Front-end), quyết định chất lượng dữ liệu đầu vào. Cấu hình Suricata tập trung vào hiệu năng bắt gói tin và độ chính xác của luật phát hiện.

#### 4.2.1. Biến môi trường mạng (Network Variables)
File cấu hình `configs/suricata.yaml` định nghĩa các biến quan trọng để Engine hiểu bối cảnh mạng:

```yaml
vars:
  address-groups:
    # Định nghĩa chính xác dải mạng cần bảo vệ.
    # Quan trọng cho các luật có hướng (Directional Rules) như "alert tcp $EXTERNAL_NET any -> $HOME_NET 80"
    HOME_NET: "[172.30.20.0/24]"
    
    # Định nghĩa mạng bên ngoài (Internet/Attacker)
    EXTERNAL_NET: "[172.30.10.0/24]"
```
*Giải thích:* Việc định nghĩa chính xác `HOME_NET` giúp giảm thiểu False Positives. Nếu cấu hình sai thành `any`, Suricata sẽ tốn tài nguyên xử lý cả các gói tin nội bộ không cần thiết và có thể cảnh báo sai hướng tấn công.

#### 4.2.2. Cơ chế Thu thập gói tin (Packet Capture Engine)
Thay vì sử dụng thư viện `libpcap` truyền thống (vốn có hạn chế về hiệu năng do việc copy dữ liệu từ Kernel Space sang User Space), đồ án sử dụng **AF_PACKET** (Address Family Packet).

**Ưu điểm của AF_PACKET:**
*   **Zero-Copy (mmap):** Giảm thiểu việc sao chép dữ liệu bộ nhớ, tăng tốc độ xử lý gói tin lên 20-30% so với PCAP.
*   **Cluster Flow:** Hỗ trợ cân bằng tải lưu lượng (Load Balancing) trên nhiều luồng CPU dựa trên Flow ID, đảm bảo một luồng TCP luôn được xử lý bởi cùng một CPU Core, tránh hiện tượng Packet Reordering.

Cấu hình chi tiết `suricata.yaml`:
```yaml
af-packet:
  - interface: br-attacker-net   # Interface ảo của Docker Bridge Attacker
    cluster-id: 98
    cluster-type: cluster_flow   # Hash mode dựa trên 5-tuple của gói tin
    defrag: yes                  # Bật chống phân mảnh IP (IP Defragmentation)
  - interface: br-server-net     # Interface ảo của Docker Bridge Server
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
```

#### 4.2.3. Quản lý Luật phát hiện (Signature Management)
Hệ thống tích hợp bộ luật **Emerging Threats (ET) Open**, một trong những bộ luật cộng đồng uy tín và cập nhật nhất hiện nay. Quy trình cập nhật được tự động hóa:
1.  **Công cụ:** `suricata-update`.
2.  **Nguồn:** `https://rules.emergingthreats.net/open/suricata-7.0.2/`.
3.  **Merge:** Tự động hợp nhất luật cộng đồng và luật tùy chỉnh (`custom.rules`) vào file `suricata.rules` duy nhất, loại bỏ trùng lặp.

---

### 4.3. Thiết kế Pipeline Xử lý Dữ liệu (Logstash & OpenSearch)

Pipeline xử lý log không chỉ đơn thuần là chuyển tiếp dữ liệu, mà còn đóng vai trò chuẩn hóa (Normalization) và làm giàu thông tin (Enrichment).

#### 4.3.1. Kiến trúc Cluster OpenSearch
Mặc dù là môi trường Lab, hệ thống vẫn được thiết kế theo mô hình Cluster thu nhỏ để mô phỏng khả năng chịu lỗi (Fault Tolerance):
*   **3 Node Data Cluster:** `opensearch-manager`, `opensearch-data1`, `opensearch-data2`.
*   **Quorum:** Cấu hình `discovery.seed_hosts` đảm bảo cơ chế bầu chọn Master Node hoạt động đúng (Quorum = N/2 + 1), tránh tình trạng "Split-brain" gây mất dữ liệu.

#### 4.3.2. Cấu hình ETL Logstash
File `logstash/pipeline/logstash.conf` thực hiện chu trình ETL (Extract - Transform - Load):

**1. Extract (Input):**
Sư dụng `beats` input plugin để nhận log từ Filebeat qua giao thức Lumberjack (TCP/5044) có mã hóa TLS nếu cần.

**2. Transform (Filter):**
Đây là giai đoạn quan trọng nhất, áp dụng logic nghiệp vụ:
*   **JSON Parsing:** Suricata xuất log dạng JSON (EVE format). Filter `json` giúp Logstash hiểu cấu trúc này, chuyển đổi từ chuỗi text vô nghĩa thành các Object có thể truy vấn (ví dụ: `src_ip`, `proto`, `alert.signature`).
*   **GeoIP Enrichment:**
    *   *Vấn đề:* Môi trường lab sử dụng IP Private (RFC1918), không thể GeoIP Lookup thực tế.
    *   *Giải pháp:* Sử dụng `mutate` filter để "gán cứng" tọa độ địa lý. IP `172.30.10.x` (Attacker) được gán IP Nga (Russia), `172.30.20.x` (Server) được gán IP Việt Nam. Điều này cho phép kiểm thử tính năng Threat Map trên Dashboard.
*   **Threat Intel Lookup:**
    Sử dụng filter `translate` với từ điển `blocklist_de.yml`. Cơ chế tra cứu Hash Table (O(1)) giúp so khớp nhanh hàng triệu IP độc hại mà không làm chậm luồng xử lý log.

**3. Load (Output):**
Log được router tới các Index khác nhau dựa trên nguồn gốc để tối ưu hóa lưu trữ (Hot/Warm Architecture):
*   Log bảo mật: `siem-suricata-YYYY.MM.DD`
*   Log hệ thống: `siem-metricbeat-YYYY.MM.DD`

---

### 4.4. Cấu hình Giám sát và Cảnh báo (Dashboard & Alerting)

Kết quả cuối cùng của hệ thống là khả năng hiển thị sự cố trực quan cho người quản trị (SOC Analyst).

#### 4.4.1. Metrics quan trọng trên Dashboard
Dashboard được thiết kế tập trung vào 3 câu hỏi nghiệp vụ:
1.  **"Chúng ta có đang bị tấn công không?":** Biểu đồ **Timeline** (Line Chart) theo dõi tổng lượng Alert theo thời gian. Một sự gia tăng đột biến (Spike) là dấu hiệu rõ ràng của tấn công brute-force hoặc DoS.
2.  **"Ai đang tấn công?":** Biểu đồ **Donut Chart** phân loại `alert.category` và `source.ip`. Giúp xác định nhanh Top Talkers (IP gửi nhiều request nhất).
3.  **"Tấn công từ đâu?":** **Region Map** hiển thị phân bố địa lý. Cho phép phát hiện các bất thường về địa lý (ví dụ: truy cập quản trị từ quốc gia lạ).

#### 4.4.2. Cơ chế Alerting thời gian thực
Hệ thống sử dụng **Monitor** của OpenSearch (chạy định kỳ 1 phút/lần) để quét dữ liệu mới nhất.
*   **Trigger Script (Painless):**
    ```java
    // Kích hoạt nếu có bất kỳ log alert nào có severity level 1 (Critical)
    ctx.results[0].hits.total.value > 0
    ```
*   **Notification:** Tích hợp Webhook để gửi cảnh báo tới Slack/Email, cung cấp ngữ cảnh tức thì (IP nguồn, loại tấn công) giúp đội ứng cứu sự cố (Incident Response) phản ứng ngay lập tức.

---

*(Các chương tiếp theo giữ nguyên)*
