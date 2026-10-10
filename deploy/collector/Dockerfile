# see 采集器容器镜像（纯标准库 Python，无需 pip，ARM/x86 通吃）
# 适用：懒猫微服 LightOS 里的 Docker / 任何装了 Docker 的常开设备
FROM python:3.11-alpine

# 时区（日志时间戳可读；不需要可删）
RUN apk add --no-cache tzdata && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo "Asia/Shanghai" > /etc/timezone

WORKDIR /app
COPY see_collector.py /app/see_collector.py

# 不写死任何密钥；运行时用环境变量或挂载 /etc/see/api-key
ENV SEE_API=https://5130599.best/see \
    SEE_KEY_FILE=/etc/see/api-key \
    PYTHONUNBUFFERED=1

# 只做采集，不需要 root
# 健康检查：自检失败即视为不健康（docker 会重启它）
HEALTHCHECK --interval=5m --timeout=30s --start-period=30s --retries=2 \
    CMD python3 /app/see_collector.py --api-base "$SEE_API" --key-file "$SEE_KEY_FILE" --selfcheck || exit 1

ENTRYPOINT ["python3", "/app/see_collector.py"]
