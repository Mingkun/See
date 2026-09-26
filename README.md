# see · 局域网/WiFi 客户端监控

统计、监控同一局域网（WiFi）内所有客户端：实时接入、在线状态、上传/下载数据量，以及每台设备访问的应用/目标（基于端口 + DNS + TLS SNI 识别）。

## 两种运行模式

| 模式 | 判定 | 能力 |
|---|---|---|
| **网关模式** | 主机已开启 `ip_forward`（作为路由器/软转发），或 `see.json` 设 `"gateway": true` | 全部功能：设备发现 + 每设备实时↑↓速度、历史流量、应用/目标识别 |
| **观察模式** | 普通局域网主机 | 设备发现、接入/在线/离线动态（看不到他人流量） |

## 运行

```bash
pip3 install -r requirements.txt
python3 run.py            # 默认 0.0.0.0:5040
```

浏览器打开 `http://<本机IP>:5040/`。

## 部署为服务

```bash
sudo cp -r . /opt/see
sudo cp deploy/see.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now see
```

## 说明

- ARP 全网段扫描默认 10 秒一轮（`see.json` 可调 `scan_interval`）。
- 流量按分钟入库（`data/see.db`），支持当日汇总与近 90 分钟曲线。
- 应用识别：已知端口表 + DNS 应答缓存 + TLS ClientHello SNI，无需解密内容。
- 厂商信息来自 macvendors.com（联网查询并缓存）。
- 在 OpenWrt/树莓派/软路由上以网关模式运行效果最佳。

## 手机部署（Termux，免 root，观察模式）

1. 安装 [Termux](https://f-droid.org/packages/com.termux/)（建议 F-Droid 版）
2. 在 Termux 中：
   ```bash
   pkg update && pkg install python iputils-ping
   # 把 see 项目拷到手机（git clone / 下载 zip 解压均可）
   pip install -r requirements.txt
   python run.py
   ```
3. 手机浏览器打开 `http://127.0.0.1:5050/`

说明：
- 手机上为**观察模式**：自动回退为 ping+ARP 表扫描（免 root），可看设备接入/上线/离线动态。
- 每设备的**流量统计与应用识别**需要在**网关设备**（路由器/软路由/树莓派）上运行才生效，手机无法充当网关。
- WiFi 需关闭「AP 隔离/客户端隔离」，否则手机看不到其他客户端。
