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

echo "==> [3/7] 安装到 /opt/see"
$SUDO mkdir -p /opt/see /etc/see
$SUDO install -m 755 see_collector.py /opt/see/see_collector.py

echo "==> [4/7] 写入 /etc/see/api-key（采集器密钥）"
# 密钥不再放在公开网页里了（那是以前的安全漏洞）。三种来源，都不会进命令行参数：
#   1) 环境变量 SEE_KEY（适合自动化）   2) 已有的 /etc/see/api-key（重跑时复用）
#   3) 交互输入（默认，不回显）
KEY="${SEE_KEY:-}"
if [ -z "$KEY" ] && $SUDO test -s /etc/see/api-key; then
  KEY="$($SUDO cat /etc/see/api-key 2>/dev/null || true)"
  [ -n "$KEY" ] && echo "    复用已有的 /etc/see/api-key"
fi
while [ -z "$KEY" ]; do
  echo "    请粘贴「采集器密钥」后回车（输入不回显）："
  echo "    位置：https://5130599.best/see/ → ⚙ 设置 → 访问与安全 → 采集器密钥（需先登录）"
  if [ -t 0 ]; then
    printf '    密钥: '; read -r -s KEY < /dev/tty || KEY=""; echo
  else
    echo "!! 非交互环境：请改用 SEE_KEY=xxx bash install.sh，或先登录网页取密钥"; exit 1
  fi
  KEY="$(printf '%s' "$KEY" | tr -d ' \r\n')"
done
if [ ${#KEY} -lt 16 ]; then
  echo "!! 密钥长度 ${#KEY}，看着不对（正常 32 位十六进制），请重新复制再跑"; exit 1
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
