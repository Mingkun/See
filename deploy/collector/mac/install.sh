#!/bin/bash
# see 采集器 · Mac mini 一键安装
# 用法：解压后 sudo bash install.sh
set -e
echo "== see 采集器安装（Mac mini）=="

# 1) 权限
if [ "$(id -u)" != "0" ]; then echo "请用 sudo 运行：sudo bash install.sh"; exit 1; fi

# 2) python3 检查（macOS 无开发者工具时会弹安装窗）
if ! /usr/bin/python3 --version >/dev/null 2>&1; then
  echo "系统缺少 python3（命令行开发者工具）"
  echo "→ 点开 终端 输入 xcode-select --install，在弹窗里点「安装」，装完重新运行本脚本"
  exit 1
fi
echo "python3: $(/usr/bin/python3 --version)"

# 3) 安装位置
SEE_DIR=/usr/local/see
mkdir -p "$SEE_DIR"
cp see_collector.py "$SEE_DIR/"

# 4) 密钥（只在首次安装时询问）
if [ ! -s "$SEE_DIR/api-key" ]; then
  echo ""
  echo "需要机器密钥：用浏览器打开 https://5130599.best/see/"
  echo "登录后点 ⚙ 齿轮 → 「访问与安全」→ 复制机器密钥"
  read -r -p "粘贴密钥（输入不回显）: " KEY
  [ -z "$KEY" ] && { echo "密钥为空，退出"; exit 1; }
  printf '%s' "$KEY" > "$SEE_DIR/api-key"
fi
chmod 600 "$SEE_DIR/api-key"

# 5) 自检（网关登录/解析/配置 三项全过才继续）
echo ""
echo "== 自检 =="
/usr/bin/python3 "$SEE_DIR/see_collector.py" \
  --api-base https://5130599.best/see \
  --key-file "$SEE_DIR/api-key" \
  --selfcheck || { echo "自检未全过，先解决上面的 ✗ 再重跑"; exit 1; }

# 6) 电源：禁睡眠 + 来电自动开机（显示器照常可关）
echo ""
echo "== 电源设置：不睡眠、来电自动开机 =="
pmset -a sleep 0 disksleep 0 autorestart 1 || true

# 7) launchd 常驻（开机自启 + 崩溃秒拉）
cat > /Library/LaunchDaemons/com.see.collector.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.see.collector</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/python3</string>
    <string>/usr/local/see/see_collector.py</string>
    <string>--api-base</string><string>https://5130599.best/see</string>
    <string>--key-file</string><string>/usr/local/see/api-key</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/usr/local/see/collector.log</string>
  <key>StandardErrorPath</key><string>/usr/local/see/collector.log</string>
</dict>
</plist>
PLIST
chmod 644 /Library/LaunchDaemons/com.see.collector.plist
launchctl bootout system/com.see.collector 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/com.see.collector.plist 2>/dev/null \
  || launchctl load -w /Library/LaunchDaemons/com.see.collector.plist

# 8) 验证
sleep 6
echo ""
echo "== 最近日志（应有采样/上传记录）=="
tail -5 "$SEE_DIR/collector.log" 2>/dev/null || echo "（日志稍等片刻再 tail 查看）"
echo ""
echo "安装完成 ✓ 常驻 + 开机自启 + 崩溃自动拉起 + 不睡眠 + 停电来电自动开机"
echo "日志：tail -f /usr/local/see/collector.log"
echo "卸载：sudo launchctl bootout system/com.see.collector && sudo rm /Library/LaunchDaemons/com.see.collector.plist"
