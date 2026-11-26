#!/usr/bin/env python3
"""设备休息监控：判定选定设备进入/结束「休息」，供 OpenClaw 定时触发调用。

口径与流量负载分析一致：
- 每分钟取该分钟内最高一次采样的上行+下行合计（库内单位=字节/10秒，繁忙线 25000 = 20Kbps）
- 繁忙=peak>=25000；低位=在线且<25000；离线/无采样=静默但不计在线低位
- 休息启动：最近 10 个完整分钟全部无繁忙，且其中 >=5 分钟「在线低位」或「夜间离线」
  （夜间离线=23:00-08:59 设备不在网上、且其他设备仍在采样=采集器活着；白天出门离线不报）
  （启动时间=往前回溯最近一个繁忙分钟的后一分钟，最多回看 12 小时）
- 休息中设备离线不误判结束；结束=自上次检查(含10分钟重叠)以来出现 >=3 个繁忙分钟
  （结束时间=该窗口内第一个繁忙分钟；孤立 1-2 分钟的抖动不触发）
状态文件 data/rest-watch-state.json：{devkey, name, resting, since, checked_at}
输出一行 JSON：{action: start|stop|none, message, state, checked_at}
测试：--now <epoch> --state-file <path>（不影响生产状态文件）
"""
from __future__ import annotations

import argparse
import datetime
import json
import sqlite3
import sys
import time

ROOT = "/work/see"
DB = ROOT + "/data/see.db"
STATE_FILE = ROOT + "/data/rest-watch-state.json"
BUSY = 25000          # 繁忙线（字节/10秒）= 合计峰值 20Kbps
START_MIN = 10        # 休息启动：连续静默分钟数（用户 2026-11-26 起改为 10 分钟）
START_ONLINE = 5      # 其中需「在线低位」的分钟数（防采集器停报误判）
END_BUSY = 3          # 休息结束：窗口内繁忙分钟数（滤掉 1-2 分钟的孤立抖动）
OFFLINE_NIGHT = (23, 9)  # 离线视同休息的夜间窗口（本地小时：23:00-08:59；白天出门不算）
LOOKBACK = 12 * 3600  # 启动时间回溯上限
TZ = datetime.timezone(datetime.timedelta(hours=8))


def fmt_hm(ts: int) -> str:
    return datetime.datetime.fromtimestamp(ts, TZ).strftime("%m-%d %H:%M")


def fmt_dur(sec: float) -> str:
    m = int(sec // 60)
    h, m = divmod(m, 60)
    return (f"{h} 小时 {m} 分钟" if h else f"{m} 分钟")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--now", type=int, default=None)
    ap.add_argument("--state-file", default=STATE_FILE)
    ap.add_argument("--devkey", default=None)
    args = ap.parse_args()
    now = args.now or int(time.time())
    try:
        st = json.load(open(args.state_file, encoding="utf-8"))
    except Exception:
        st = {}
    devkey = args.devkey or st.get("devkey")
    if not devkey:
        print(json.dumps({"action": "none", "message": "", "state": st,
                          "checked_at": now, "note": "未配置 devkey"}, ensure_ascii=False))
        return 0

    conn = sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=20)
    name = st.get("name") or ""
    if not name:
        r = conn.execute("SELECT MAX(name) FROM gw_samples WHERE devkey=?", (devkey,)).fetchone()
        name = (r[0] if r and r[0] else "") or devkey
    rows = {r[0]: (r[1] or 0, r[2] or 0) for r in conn.execute(
        "SELECT (ts/60)*60 m, MAX(up+down) peak, MAX(present) pres "
        "FROM gw_samples WHERE devkey=? AND ts>=? AND ts<=? GROUP BY m",
        (devkey, now - LOOKBACK, now + 60))}
    other_minutes = {
        r[0] for r in conn.execute(
            "SELECT DISTINCT (ts/60)*60 FROM gw_samples WHERE devkey<>? AND ts>=? AND ts<=?",
            (devkey, now - 60 * (START_MIN + 10), now + 60))}
    conn.close()

    def verdict(m: int) -> str:
        v = rows.get(m)
        if v is None or not v[1]:
            return "none"
        return "busy" if v[0] >= BUSY else "low"

    def night(m: int) -> bool:
        h = datetime.datetime.fromtimestamp(m, TZ).hour
        return h >= OFFLINE_NIGHT[0] or h < OFFLINE_NIGHT[1]

    def qualify(m: int) -> bool:
        v = verdict(m)
        if v == "low":
            return True
        return v == "none" and night(m) and m in other_minutes

    m0 = (now // 60) * 60          # 当前（未完整）分钟
    end_m = m0 - 60                # 最后一个完整分钟
    action, message = "none", ""
    resting = bool(st.get("resting"))
    since = int(st.get("since") or 0)

    if not resting:
        # —— 休息启动检测：最近 30 个完整分钟 ——
        window = [end_m - 60 * i for i in range(START_MIN)]
        vs = [verdict(m) for m in window]
        if "busy" not in vs and sum(1 for m in window if qualify(m)) >= START_ONLINE:
            start = None
            for m in range(end_m, end_m - LOOKBACK, -60):
                if verdict(m) == "busy":
                    start = m + 60
                    break
            if start is None:
                start = end_m - 60 * (START_MIN - 1)
            quiet = [rows[m][0] for m in range(start, end_m + 60, 60)
                     if m in rows and rows[m][1]]
            avg_k = (sum(quiet) / len(quiet) / 10 * 8 / 1000) if quiet else 0
            seg_txt = f"段内均值 {avg_k:.2f} Kbps" if quiet else "设备已离线"
            action = "start"
            message = (f"😴 休息监控：{name} 于 {fmt_hm(start)} 进入休息"
                       f"（已连续静默 {(end_m - start) // 60 + 1} 分钟，{seg_txt}）")
            resting, since = True, start
    else:
        # —— 休息结束检测：自上次检查（往前重叠 10 分钟）以来 ——
        since_chk = min(int(st.get("checked_at") or since or now - 600), now)
        win_lo = ((min(since_chk, m0) - 600) // 60) * 60
        busy_ms = [m for m in range(win_lo, m0 + 60, 60) if verdict(m) == "busy"]
        if len(busy_ms) >= END_BUSY:
            end = busy_ms[0]
            action = "stop"
            dur = fmt_dur(end - since) if since else "?"
            message = (f"⏰ 休息监控：{name} 于 {fmt_hm(end)} 结束休息"
                       f"（本次休息 {dur}）")
            resting = False

    new_state = {"devkey": devkey, "name": name, "resting": resting,
                 "since": since if resting else 0, "checked_at": now}
    if args.state_file == STATE_FILE:
        try:
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(new_state, f, ensure_ascii=False)
        except OSError:
            pass
    print(json.dumps({"action": action, "message": message,
                      "state": new_state, "checked_at": now}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
