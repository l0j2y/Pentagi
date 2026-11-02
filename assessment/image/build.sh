#!/usr/bin/env bash
# 在 WSL (Ubuntu) 中执行：bash assessment/image/build.sh
# 构建漏洞检测专用镜像 pentagi-assess:latest（基础镜像本地已存在，无需拉取）。
set -euo pipefail
cd "$(dirname "$0")"

echo "==> 构建 pentagi-assess:latest（nuclei 模板更新步骤可能耗时数分钟）..."
docker build -t pentagi-assess:latest .

echo "==> 验证：扫描工具应存在，利用工具应 MISSING"
docker run --rm pentagi-assess:latest bash -c '
ok=1
check_keep() { command -v "$1" >/dev/null 2>&1 && echo "KEEP   $1 => $(command -v "$1")" || { echo "MISSING(keep!) $1"; ok=0; }; }
check_gone() { if command -v "$1" >/dev/null 2>&1; then echo "STILL-PRESENT(gone!) $1"; ok=0; else echo "GONE   $1"; fi; }
check_keep nmap; check_keep masscan; check_keep nuclei; check_keep nikto
check_keep whatweb; check_keep httpx; check_keep katana; check_keep ffuf
check_keep sslscan; check_keep testssl.sh; check_keep sqlmap
check_gone msfconsole; check_gone msfvenom; check_gone hydra
check_gone evil-winrm; check_gone netexec; check_gone weevely
check_gone john; check_gone hashcat; check_gone impacket-smbclient
test -d /root/nuclei-templates && echo "nuclei-templates: present ($(ls /root/nuclei-templates | wc -l) entries)" \
                                 || echo "nuclei-templates: MISSING"
[ "$ok" = 1 ] && echo "==> ALL CHECKS PASSED" || { echo "==> CHECKS FAILED"; exit 1; }
'
