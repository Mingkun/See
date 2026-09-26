# coding: utf-8
"""Traffic → app/label heuristics: port map + domain keyword rules."""

PORT_APPS = {
    53: 'DNS', 80: 'HTTP网页', 443: 'HTTPS', 853: 'DNS(DoT)', 123: 'NTP时间',
    22: 'SSH', 23: 'Telnet', 3389: '远程桌面', 5900: 'VNC',
    1935: 'RTMP直播', 8000: 'RTSP/流', 554: 'RTSP流',
    3074: 'Xbox游戏', 27015: 'Steam游戏', 25565: 'Minecraft',
    3724: '暴雪游戏', 1119: '暴雪战网', 1200: 'Destiny游戏',
    3478: '游戏NAT', 7000: '飞机ACARS?',
    5228: 'Google推送', 5223: 'Apple推送', 2195: 'Apple推送',
    8009: 'Chromecast', 32400: 'Plex', 1900: 'SSDP/投屏', 5353: 'mDNS',
    445: 'SMB文件共享', 139: 'NetBIOS', 548: 'AFP共享',
    5060: 'SIP通话', 5061: 'SIP通话', 1723: 'VPN(PPTP)', 1194: 'VPN(OpenVPN)',
    3306: 'MySQL', 6379: 'Redis', 27017: 'MongoDB',
}

DOMAIN_RULES = [
    ('youtube', 'YouTube'), ('googlevideo', 'YouTube视频'), ('ytimg', 'YouTube'),
    ('bilibili', 'B站'), ('biliapi', 'B站'), ('hdslb', 'B站'),
    ('douyin', '抖音'), ('tiktokv', 'TikTok'), ('tiktok', 'TikTok'),
    ('weixin', '微信'), ('wechat', '微信'), ('wx.qq.com', '微信'),
    ('qq.com', '腾讯QQ'), ('tencent', '腾讯'), ('gtimg', '腾讯'),
    ('netflix', 'Netflix'), ('nflxvideo', 'Netflix'),
    ('taobao', '淘宝'), ('alicdn', '阿里CDN'), ('aliyun', '阿里云'), ('alipay', '支付宝'),
    ('jd.com', '京东'), ('pingxx', '支付'), ('pinduoduo', '拼多多'),
    ('apple.com', 'Apple服务'), ('icloud', 'iCloud'), ('mzstatic', 'Apple'),
    ('microsoft', '微软服务'), ('windowsupdate', 'Windows更新'), ('msftconnecttest', '微软联网检测'),
    ('live.com', '微软服务'), ('office.com', '微软Office'), ('xboxlive', 'Xbox'),
    ('steamcontent', 'Steam下载'), ('steampowered', 'Steam'), ('steamserver', 'Steam游戏'),
    ('epicgames', 'Epic游戏'), ('unrealengine', 'Epic游戏'),
    ('minecraft', 'Minecraft'), ('netease', '网易'), ('minecraftpe', 'Minecraft'),
    ('huya', '虎牙直播'), ('douyu', '斗鱼直播'), ('pandatv', '直播'),
    ('zhihu', '知乎'), ('weibo', '微博'), ('xiaohongshu', '小红书'), ('xhslink', '小红书'),
    ('baidu', '百度'), ('bdstatic', '百度'), ('bdimg', '百度'),
    ('bytedance', '字节跳动'), ('byteoversea', '字节跳动'), ('snssdk', '字节跳动'),
    ('cloudflare', 'Cloudflare CDN'), ('cdn', 'CDN'), ('akamai', 'Akamai CDN'),
    ('telegram', 'Telegram'), ('whatsapp', 'WhatsApp'), ('discord', 'Discord'),
    ('zoom.us', 'Zoom会议'), ('tencentmeeting', '腾讯会议'), ('dingtalk', '钉钉'),
    ('feishu', '飞书'), ('notion', 'Notion'), ('github', 'GitHub'),
    ('gstatic', 'Google静态资源'), ('googleapis', 'Google服务'), ('google', 'Google'),
    ('amplitude', '统计分析'), ('umeng', '友盟统计'), ('app-measurement', '应用统计'),
    ('ntp.org', 'NTP时间'), ('pool.ntp', 'NTP时间'),
]


def app_label(remote_ip, port, proto, dns_map=None, sni_map=None):
    """Return a human label for a flow."""
    dns_map = dns_map or {}
    sni_map = sni_map or {}
    domain = (sni_map.get(remote_ip) or dns_map.get(remote_ip) or '').lower()
    if domain:
        for key, label in DOMAIN_RULES:
            if key in domain:
                return label
        # unknown domain: show a trimmed domain as label
        dom = domain if len(domain) <= 28 else domain[:26] + '…'
        return dom
    if proto == 'icmp':
        return 'Ping'
    if port and port in PORT_APPS:
        return PORT_APPS[port]
    if proto == 'udp':
        return 'UDP其他'
    if port:
        if port in (80, 8080, 8000, 8888):
            return 'HTTP网页'
        if port == 443 or 8000 <= port < 9000:
            return 'HTTPS'
        return f'端口{port}'
    return '其他'
