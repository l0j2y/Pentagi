#!/bin/bash
# PentAGI 镜像拉取 + 启动脚本（断点续传，自动重试）
cd /mnt/e/Pentagi/pentagi-main/pentagi-main || exit 1

echo "===== 开始拉取镜像 $(date) ====="
for i in $(seq 1 80); do
  echo "===== pull attempt $i ($(date)) ====="
  if docker compose pull; then
    echo "===== PULL SUCCESS ====="
    break
  fi
  echo "===== attempt $i failed, sleep 20s ====="
  sleep 20
done

echo "===== 启动容器 $(date) ====="
docker compose up -d
echo "===== DONE $(date) ====="
docker compose ps
