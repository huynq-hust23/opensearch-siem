#!/bin/bash

echo "------------------------------------------------"

# Xử lý tham số -stop
if [[ "$1" == "-stop" ]]; then
    echo "🛑 Đang tắt Cloudflare Tunnel..."
    sudo systemctl stop cloudflared
    if ! systemctl is-active --quiet cloudflared; then
        echo "✅ Tunnel đã được tắt thành công."
    else
        echo "❌ Có lỗi khi tắt Tunnel."
    fi
    echo "------------------------------------------------"
    exit 0
fi

# Tự lấy IP hiện tại để bạn quản lý máy từ xa nếu cần
CURRENT_IP=$(curl -s --max-time 2 https://ifconfig.me)
echo "🌐 IP Public hiện tại: ${CURRENT_IP:-'Không lấy được IP'}"

echo "🚀 Đang mở đường truyền cho OpenSearch Dashboard..."

# Khởi động service
sudo systemctl start cloudflared

# Đợi 2 giây để tunnel thiết lập kết nối
sleep 2

# Kiểm tra trạng thái
if systemctl is-active --quiet cloudflared; then
    echo "✅ Tunnel ONLINE!"
    echo "🔗 Truy cập ngay tại tên miền bạn đã cấu hình trên Cloudflare."
    echo "💡 Gợi ý: OpenSearch Dashboard thường chạy tại localhost:5601"
else
    echo "❌ Có lỗi khi khởi động Tunnel."
fi
echo "------------------------------------------------"