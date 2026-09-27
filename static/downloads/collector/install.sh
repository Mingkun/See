#!/bin/bash
# see 采集器一键安装 —— 在懒猫微服 LightOS 实例的终端里跑这一条就行：
#
#   curl -fsSL https://5130599.best/see/downloads/collector/install.sh | bash
#
# 如果直连报 TLS 错误（unexpected eof / handshake failure），改用：
#   curl -4 --tlsv1.2 --tls-max 1.2 -fsSL \
#     https://5130599.best/see/downloads/collector/install.sh -o /tmp/i.sh && bash /tmp/i.sh
#
# 它会：下载脚本 -> 装到 /opt/see -> 自动取密钥写 /etc/see/api-key(600)
#      -> 自检三项 -> 装 systemd 服务并启动
set -e
BASE="https://5130599.best/see/downloads/collector"
API="https://5130599.best/see"

# 自动判断要不要 sudo：已经是 root、或没装 sudo 时不加前缀（LightOS 实例里常见）
if [ "$(id -u)" = "0" ] || ! command -v sudo >/dev/null 2>&1; then SUDO=""; else SUDO="sudo"; fi
echo "==> 当前用户 $(id -un) (uid=$(id -u))，sudo 前缀: '${SUDO:-无}'"

# 下载函数：先按默认参数试，失败再强制 IPv4 + TLS1.2（NAT/中间设备常把 TLS1.3 谈崩）
dl() {
  local url="$1" out="$2"
  if curl -fsSL --retry 2 --connect-timeout 10 "$url" -o "$out" 2>/dev/null; then return 0; fi
  echo "    直连失败，改用 IPv4 + TLS1.2 重试…"
  curl -4 -fsSL --retry 3 --connect-timeout 15 --tlsv1.2 --tls-max 1.2 "$url" -o "$out"
}

echo "==> [1/7] 下载脚本到 /tmp/see-collector"
rm -rf /tmp/see-collector && mkdir -p /tmp/see-collector && cd /tmp/see-collector
for f in see_collector.py see-collector.service; do
  echo "    - $f"
  dl "$BASE/$f" "$f"
done

echo "==> [2/7] 确认 python3"
if ! command -v python3 >/dev/null 2>&1; then
  echo "    未发现 python3，自动安装（顺带装 ca-certificates，采集器要 HTTPS 上传）…"
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update -qq && $SUDO apt-get install -y -qq python3 ca-certificates
  elif command -v apk >/dev/null 2>&1; then
    $SUDO apk add --no-cache python3 ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf install -y python3 ca-certificates
  else
    echo "!! 找不到包管理器，请手动装 python3 后重跑"; exit 1
  fi
fi
python3 -V

echo "==> [2/7] 安装到 /opt/see"
$SUDO mkdir -p /opt/see /etc/see
$SUDO install -m 755 see_collector.py /opt/see/see_collector.py

echo "==> [4/7] 取密钥写入 /etc/see/api-key（从 see 网页读取，不经过命令行参数）"
dl "$API/" homepage.html
KEY="$(grep -m1 'SEE_KEY' homepage.html | cut -d\' -f2)"
KEY="$(printf '%s' "$KEY" | tr -d ' \r\n')"
if [ -z "$KEY" ]; then
  echo "!! 取密钥失败，诊断信息："
  echo "   下载字节数: $(wc -c < homepage.html)"
  echo "   含 SEE_KEY 的行数: $(grep -c SEE_KEY homepage.html || true)"
  echo "   文件开头 300 字节:"; head -c 300 homepage.html; echo
  exit 1
fi
printf '%s' "$KEY" | $SUDO tee /etc/see/api-key >/dev/null
$SUDO chmod 600 /etc/see/api-key
echo "    密钥长度 ${#KEY}，已写入（不回显内容）"

echo "==> [5/7] 自检（三项必须全 ✓）"
$SUDO python3 /opt/see/see_collector.py --api-base "$API" --key-file /etc/see/api-key --selfcheck

echo "==> [6/7] 装 systemd 服务"
$SUDO cp see-collector.service /etc/systemd/system/
$SUDO systemctl daemon-reload
$SUDO systemctl enable --now see-collector

echo "==> [7/7] 状态"
sleep 3
systemctl status see-collector --no-pager | head -12 || true

echo
echo "✅ 完成。看实时日志： journalctl -u see-collector -f"
echo "❗ 别忘了去手机 app 把「实时设备」开关关掉，否则数据翻倍。"
