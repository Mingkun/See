#!/bin/bash
# see 采集器一键安装 —— 在懒猫微服 LightOS 实例的终端里跑这一条就行：
#
#   curl -fsSL https://5130599.best/see/downloads/collector/install.sh | bash
#
# 它会：下载脚本 -> 装到 /opt/see -> 自动取密钥写 /etc/see/api-key(600)
#      -> 自检三项 -> 装 systemd 服务并启动
set -e
BASE="https://5130599.best/see/downloads/collector"
API="https://5130599.best/see"

echo "==> [1/6] 下载脚本到 /tmp/see-collector"
rm -rf /tmp/see-collector && mkdir -p /tmp/see-collector && cd /tmp/see-collector
for f in see_collector.py see-collector.service; do
  curl -fsSLO "$BASE/$f"
done

echo "==> [2/6] 安装到 /opt/see"
sudo mkdir -p /opt/see /etc/see
sudo install -m 755 see_collector.py /opt/see/see_collector.py

echo "==> [3/6] 取密钥写入 /etc/see/api-key（从 see 网页读取，不经过命令行参数）"
KEY="$(curl -fsS "$API/" | grep -o "SEE_KEY = '[^']*'" | head -1 | cut -d"'" -f2)"
if [ -z "$KEY" ]; then echo "!! 取密钥失败，检查能否访问 $API/"; exit 1; fi
printf '%s' "$KEY" | sudo tee /etc/see/api-key >/dev/null
sudo chmod 600 /etc/see/api-key
echo "    密钥长度 ${#KEY}，已写入（不回显内容）"

echo "==> [4/6] 自检（三项必须全 ✓）"
sudo python3 /opt/see/see_collector.py --api-base "$API" --key-file /etc/see/api-key --selfcheck

echo "==> [5/6] 装 systemd 服务"
sudo cp see-collector.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now see-collector

echo "==> [6/6] 状态"
sleep 3
systemctl status see-collector --no-pager | head -12 || true

echo
echo "✅ 完成。看实时日志： journalctl -u see-collector -f"
echo "❗ 别忘了去手机 app 把「实时设备」开关关掉，否则数据翻倍。"
