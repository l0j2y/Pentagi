#!/bin/bash
cd /mnt/e/Pentagi/pentagi-main/pentagi-main || exit 1
LOG=/mnt/e/Pentagi/pentagi-main/pentagi-main/restart_verify.log
echo "=== 启动时间 $(date) ===" > "$LOG"
echo "docker 启动前: $(systemctl is-active docker)" >> "$LOG"

# 确保 docker 运行
systemctl start docker 2>&1 >> "$LOG"
sleep 3
echo "docker 启动后: $(systemctl is-active docker)" >> "$LOG"

echo "" >> "$LOG"
echo "=== 启动容器 ===" >> "$LOG"
docker compose up -d >> "$LOG" 2>&1

echo "" >> "$LOG"
echo "=== 容器状态 ===" >> "$LOG"
docker compose ps --format "{{.Service}} {{.Status}}" >> "$LOG" 2>&1

echo "" >> "$LOG"
echo "=== 连通性 ===" >> "$LOG"
curl -sk -o /dev/null -w "主页 HTTP %{http_code}\n" https://127.0.0.1:8443/ >> "$LOG" 2>&1
echo "DONE" >> "$LOG"
