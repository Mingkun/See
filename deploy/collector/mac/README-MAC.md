# see 采集器 · Mac mini 部署（3 分钟）

## 步骤

1. **下载并解压**（Safari 打开）：
   https://5130599.best/see/downloads/see-collector-mac.zip
   双击解压得到 `see-collector-mac/` 文件夹

2. **打开「终端」**（聚焦搜索 ⌘+空格 输入 Terminal），进入文件夹并安装：
   ```bash
   cd ~/Downloads/see-collector-mac
   sudo bash install.sh
   ```

3. 按提示**粘贴机器密钥**（先在浏览器开 https://5130599.best/see/ → 登录 → ⚙ 齿轮 → 「访问与安全」→ 复制机器密钥）

4. 等**自检三项全 ✓** → 脚本自动装好一切（常驻服务 + 开机自启 + 崩溃自动拉起 + 禁睡眠 + 停电来电自动开机）

## 可能遇到

- **提示要装 python3**：终端里跑 `xcode-select --install`，弹窗点安装（约几分钟），完事重跑 `sudo bash install.sh`
- **自检 ✗ 网关登录失败**：确认 Mac mini 连的是家里主路由的网（网段 192.168.1.x，和光猫同一层）；别走 VPN

## 装完验证

```bash
tail -f /usr/local/see/collector.log     # 看到每10秒采样、每60秒上传即正常
```
再打开 See 网页「监控页」，设备实时数据回来了就是成功。

## 收尾：停掉懒猫微服的旧采集器（重要！）

Mac mini 稳定跑半天后，去懒猫微服的 LightOS 实例终端：
```bash
sudo systemctl disable --now see-collector
```
（两台同时跑会产生重复样本）

## 日常

- 日志：`/usr/local/see/collector.log`（嫌大可 `sudo sh -c '> /usr/local/see/collector.log'` 清空）
- 卸载：`sudo launchctl bootout system/com.see.collector && sudo rm /Library/LaunchDaemons/com.see.collector.plist`
- 显示器关了没关系，**别让 Mac 睡眠**（安装脚本已设置 `pmset sleep 0`，以后若手动改回睡眠设置要再关掉）
