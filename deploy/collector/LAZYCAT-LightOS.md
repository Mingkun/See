# 懒猫微服部署步骤（LightOS 路线）

> 依据懒猫官方文档整理：LightOS 攻略（lazycat.cloud/playground/guideline/1537）、
> 开发者手册 ssh / advanced-lightos / dockerd-support / network-config。
> 界面版本可能变化，以你微服上的实际界面为准。

## 0. 先确认两件事

1. **位置**：微服要接在**主网关 `192.168.1.1` 同一层网**（接它的 LAN 口）。
   挂在级联路由下面 → 采到的是另一张表。
2. **密钥**：登录 see 网页 → ⚙ 设置 → 「访问与安全」→ **采集器密钥**（点复制）。
   网页里已不再内嵌密钥（2026-09-27 加固）；服务器上仍可在 `/work/see/data/api-key.txt` 看到。

> ⚠️ **别 SSH 进微服系统装东西**。lzcos 的 SSH 环境是 **read-only**，官方原话
> 「重启后通过 SSH 对系统做的变动会丢失」「不适合用来直接安装系统软件提供服务」。
> 所有动作都在 **LightOS 实例**里做。

## 1. 装 LightOS 并创建实例

应用商店入口：<https://appstore.lazycat.cloud/#/shop/detail/cloud.lazycat.lightos.entry>
（或在微服客户端的应用商店里搜 **LightOS**）

新建实例 → 分三步设置：

### 基础页面
| 项 | 选 |
|---|---|
| 系统镜像 | **Debian Stable** |
| 镜像仓库 | **registry.lazycat.cloud**（官方源） |
| 基础软件包 | 勾「**常用 CLI 工具**」（git/curl/wget/vim/jq/rsync） |
| 国内源 | **USTC** |
| 桌面环境 | **不选**（只用命令行；选桌面占资源，还可能抢 HDMI） |

### 网络页面
| 项 | 选 |
|---|---|
| 网络模式 | **NAT** |
| SSH | **保持开启** |
| 挂载 /lzcsys/data/document | 不勾 |
| /dev | 不勾 |

**为什么是 NAT 不是 Host**：采集器只需要**出站**（访问 `192.168.1.1` 和
`5130599.best`），NAT 完全够用。官方明确说 Host 模式「能力更强，但操作不当可能
影响主机网络」—— 没必要冒这个险。（以后想让网页直接访问实例里的端口，再加端口转发。）

### 身份页面
| 项 | 填 |
|---|---|
| 操作系统名称 | `see-collector`（随意） |
| 用户名 | 自定义，⚠️ **不要用纯数字**（官方说会出错） |
| 密码 | 自己设一个 |
| 语言 | 中文（简体） |

等构建完成 → 点「知道了」回主页面。

## 2. 打开「自动启动」❗

实例主页面 → **自动启动** → 开启。

不开的话，微服一重启、实例不启动，采集就断了 —— 那你搬这一趟就白搬了。

## 3. 进终端

主页面 → **命令行界面**（WebShell，浏览器里直接开终端，手机也能用）。
或点主页面的「**SSH 复制**」拿到连接命令，在本地终端 ssh 进去。

## 4. 确认有 python3

```bash
python3 -V
```

没有就装（选过 USTC 源，apt 可用）：

```bash
sudo apt-get update && sudo apt-get install -y python3
```

## 5. 放脚本 + 密钥

WebShell 支持**上传文件到实例 `/tmp`**（上传成功会自动复制文件路径）。
把 `see_collector.py`、`see-collector.service` 传上去，然后：

```bash
sudo mkdir -p /opt/see
sudo mv /tmp/see_collector.py /opt/see/          # 路径按实际上传的文件名改
sudo chmod 755 /opt/see/see_collector.py
echo '<你的 SEE_KEY>' | sudo tee /etc/see/api-key >/dev/null
sudo chmod 600 /etc/see/api-key
```

> 密钥写进文件、`chmod 600`，**不要**写进命令行参数（`ps` 能看到）。

## 6. 先自检，再开服务（必做）

```bash
python3 /opt/see/see_collector.py --api-base https://5130599.best/see \
        --key-file /etc/see/api-key --selfcheck
```

三项全 ✓ 才继续。哪项 ✗ 会直接说卡在哪（配置 / 登录 / 解析），并带 HTTP 状态码和响应开头。

只想采一次、不上传看看：
```bash
python3 /opt/see/see_collector.py --key-file /etc/see/api-key --once --no-upload
```

## 7. 装成常驻服务

```bash
sudo cp /tmp/see-collector.service /etc/systemd/system/   # 按实际上传路径改
sudo systemctl daemon-reload
sudo systemctl enable --now see-collector
systemctl status see-collector --no-pager
journalctl -u see-collector -f          # 实时日志，Ctrl+C 退出
```

官方文档里出现过 `sudo systemctl disable --now lightdm.service` 这类命令，
说明 LightOS 实例内是带 systemd 的。**万一你那儿 `systemctl` 不可用**，退回后台进程：

```bash
nohup python3 /opt/see/see_collector.py --api-base https://5130599.best/see \
      --key-file /etc/see/api-key >> /var/log/see-collector.log 2>&1 &
```

代价是重启后不会自动拉起 —— 所以能 systemd 就 systemd。

## 8. 验证真的在采（别只看服务"active"）

微服上：
```bash
journalctl -u see-collector -n 20 --no-pager     # 应看到「已上传 N 条」
```

服务器侧（让我查也行）：`gw_samples` 表最新时间戳是不是刚刚。
正常节奏是每 10 秒采一轮、每 60 秒上传一次。

## 9. ⚠️ 关掉手机端采集

去 app 里把「**实时设备**」开关**关掉**。

两个采集器同时跑 = 数据翻倍（服务端唯一索引只防"同一秒重复"，挡不住两行）。
历史数据不受影响，新旧无缝衔接。

## 常见问题

- **NAT 下访问不到 `192.168.1.1`？** 先在实例里 `ping 192.168.1.1`。
  NAT 是出站转发，正常能到；不通说明微服本身没接在主网关那层网。
- **上传报 401 / unauthorized**：`/etc/see/api-key` 内容不对，
  确认它就是网页 ⚙「采集器密钥」复制出来的原文（别带换行以外的空格）。
- **重启微服后采集停了**：实例「自动启动」没开，或 systemd 没 `enable`。
- **日志里全是"网关未返回数据"**：多半是网关密码不对，或微服不在网关局域网内。

## 备选：Docker 路线（LightOS 内用 Docker）

官方把"Docker in LightOS"列为自用服务的推荐方式。同目录已备
`Dockerfile` + `docker-compose.yml`：

```bash
echo '<你的 SEE_KEY>' > api-key && chmod 600 api-key
docker compose up -d
docker compose logs -f
```
