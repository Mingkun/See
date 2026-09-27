# see 采集器（内网常驻设备版）

把「手机采集」换成**家里 WiFi 里一台常开的小设备**。手机可以关机、断网、被 ROM 冻结，
采集都不受影响；分析页照样有数据。

## 为什么值得搬

| | 手机（现状） | 内网常驻设备 |
|---|---|---|
| 断档风险 | 高：Doze / 省电 / 重启 / 忘插电 | 无（有线网 + 常电） |
| 观察页（ARP 发现） | 新安卓读不到 `/proc/net/arp`，只剩 ping | 有 root，`arp-scan` 全量发现 |
| 换网/切流量 | 一断就停 | 不受影响 |
| 维护 | 要人管 | 装完不用管 |

## 硬件怎么选

0. **手里已经有懒猫微服 → 直接用它（0 元，见下节）**，不用再买。
1. **树莓派 4B/5（2GB）+ 有线接主网关 LAN 口** —— 稳、有千兆网口、功耗 3~5W。
   树莓派 Zero 2 W 也行，但**没有网口**，要么 USB 网卡要么只用 WiFi，不推荐做长期采集。
2. **更便宜：GL.iNet 之类自带 OpenWrt 的小路由**（MT3000/MT2500 等） —— 有网口、常开、能跑 Python，体积小。
3. **看看现有 NAS 能不能用** —— 家里有华为 AS6020（`192.168.1.15`）。
   若它允许 SSH / Docker，就 0 元。华为 NAS 一般比较封闭，**先确认再买**。
4. **顺带升级：N100 小主机** —— 既当采集器又能当软路由/旁路由。

## 懒猫微服（推荐：已有设备直接用）

> 📄 **详细分步操作见 [LAZYCAT-LightOS.md](./LAZYCAT-LightOS.md)**（含建实例每页怎么选、进终端、自检、自启动、验证）。

懒猫微服（LazyCat，跑 lzcos）本身完全够用，但它有个**必须绕开的坑**：

> ⚠️ **lzcos 的 SSH 环境是 read-only 系统**，官方明确写「重启后通过 SSH 对系统做的变动会丢失」、
> 「不适合用来直接安装系统软件提供服务」。
> **所以别直接 SSH 进微服装脚本/服务 —— 重启就没了。**

正确姿势是用 **LightOS**（微服应用商店里的入口应用）：它建的实例是**完整、持久的 Linux 环境**，
官方就是拿它替代「直接 SSH 装软件」这条路的。

### 路线 A：LightOS 实例里直接跑（最省事）

1. 微服客户端 → 应用商店 → 搜索安装 **LightOS**，创建一个实例。
2. 从 LightOS 页面打开实例终端（WebShell）。
3. 把脚本传进去（`scp`、粘贴均可），密钥写到 `/etc/see/api-key`，然后：
   ```bash
   sudo mkdir -p /opt/see && sudo cp see_collector.py /opt/see/
   echo '<你的 SEE_KEY>' | sudo tee /etc/see/api-key >/dev/null && sudo chmod 600 /etc/see/api-key
   python3 /opt/see/see_collector.py --key-file /etc/see/api-key --selfcheck   # 先自检
   ```
4. 自检三项都 ✓ 后，装成服务常驻（LightOS 实例是完整 Linux，systemd 可用）：
   ```bash
   sudo cp see-collector.service /etc/systemd/system/ && sudo systemctl daemon-reload
   sudo systemctl enable --now see-collector
   ```

### 路线 B：LightOS 里用 Docker（官方推荐给自用服务）

```bash
# 在 LightOS 实例内
echo '<你的 SEE_KEY>' > api-key && chmod 600 api-key
# 把 Dockerfile / docker-compose.yml / see_collector.py 放到同一目录
docker compose up -d
docker compose logs -f
```

> 需要「微服网络里跑 Docker」时官方明确指向 **Docker in LightOS**，不要在 lzcos 上折腾。

### 顺带确认两件事

- **位置**：微服要接在**主网关同一层网**（LAN 口），能访问 `192.168.1.1`。
  如果它现在挂在级联路由下面，要么换口，要么等 AP 模式改造。
- **架构**：采集器是纯标准库 Python，ARM / x86 都跑，不用装 pip 包。

> ⚠️ **位置比型号重要**：采集设备必须和**主网关同一个二层网络**（`192.168.1.x`），
> 接在主网关的 LAN 口/交换机上。如果家里还留着级联路由（双重 NAT），
> 采集器**不要**接在级联路由下面，否则看到的又是另一张表。

## 装（3 步）

```bash
# 1) 放脚本（/opt/see 随便换，跟 service 里保持一致即可）
sudo mkdir -p /opt/see /etc/see
sudo cp see_collector.py /opt/see/
sudo chmod 755 /opt/see/see_collector.py

# 2) 写密钥文件（密钥就是网页里那份 data/api-key.txt 的内容）
echo '<你的 SEE_KEY>' | sudo tee /etc/see/api-key >/dev/null
sudo chmod 600 /etc/see/api-key

# 3) 注册服务并启动
sudo cp see-collector.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now see-collector
systemctl status see-collector --no-pager
journalctl -u see-collector -f        # 看实时日志
```

## 先自检，别急着开服务

```bash
python3 /opt/see/see_collector.py --api-base https://5130599.best/see \
        --key-file /etc/see/api-key --selfcheck
```
三项全打 ✓ 才算通：配置读得到、网关登得上、allInfo 解析得出设备。
任何一项 ✗ 会直接告诉你卡在哪（含 HTTP 状态码和响应开头），不用猜。

只采一次、不上传（纯排查）：
```bash
python3 /opt/see/see_collector.py --key-file /etc/see/api-key --once --no-upload
```

## 数据格式（与服务端完全对齐，服务端无需改动）

上传 `POST /api/gw/samples`（头 `X-See-Key`）：
```json
{"samples": [[ts, devkey, name, ip, present, up, down], ...]}
```
- `devkey` = 设备 **IP**（网关的 `pc1/wifi1` 是槽位会漂移，不能用）
- `present=1` 在场；设备从网关表消失后 **25 小时内**继续补 `present=0`（休眠/离线看得出来）
- 每 10 秒采一轮、每 60 秒批量上传；上传失败会保留缓冲下次重传

## ⚠️ 两个采集器会打架

服务端唯一索引是 `(devkey, ts)`，**只能防"同一秒重复"**。手机和采集器同时跑会各写一行 → 数据翻倍。

**上线采集器后，去 app 里把「实时设备」开关关掉**（`on=false`），只留一个采集源。
分析页里历史数据不受影响，新旧数据无缝衔接（同一张表、同一个 devkey）。

## 还没做（下一步可选）

- **观察页搬到服务端**：现在设备发现结果只存在手机本地库里，服务端没有对应接口。
  要让"不装 app 也能看"，需要加服务端 `/api/devices` 存储 + 接口。
- **实时监控页搬到服务端**：现在监控页是 app 本地服务去连网关；采集器上线后
  可以让它每轮把最新设备表也上传，服务端就能自己渲染 —— 手机 app 彻底退化为看板。
