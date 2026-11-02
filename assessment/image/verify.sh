#!/usr/bin/env bash
# 深度自检：apt 锁死、testssl 运行、nuclei 模板规模、镜像大小
set -u
echo "== apt/dpkg lock (expect Permission denied) =="
docker run --rm pentagi-assess:latest bash -c 'apt-get install -y hydra 2>&1 | head -1; dpkg -l 2>&1 | head -1' || true
echo
echo "== scanners runnable =="
docker run --rm pentagi-assess:latest bash -c '
  nmap --version | head -1; testssl.sh --version 2>&1 | head -2 | tail -1;
  nuclei -version 2>&1 | head -1;
  echo "nuclei yaml templates: $(find /root/nuclei-templates -name "*.yaml" | wc -l)"'
echo
docker images pentagi-assess:latest --format 'image: {{.Repository}}:{{.Tag}} {{.Size}}'
