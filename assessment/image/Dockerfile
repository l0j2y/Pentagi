# PentAGI 漏洞检测专用镜像（L2：能力面物理收窄）
# 基于本地已缓存的 vxcontrol/kali-linux，保留侦察/扫描类工具，
# 移除利用、爆破、横向移动、凭据破解类工具并锁定包管理器。
FROM vxcontrol/kali-linux:latest

ENV DEBIAN_FRONTEND=noninteractive
# Go 系工具（nuclei/httpx/katana/naabu/ffuf）装在 /root/go/bin
ENV PATH=/root/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# ---------------------------------------------------------------------------
# 1) 物理移除利用/攻击类工具（即使提示词越界，容器内也没有这些武器）
#    保留：nmap masscan nuclei nikto whatweb httpx katana naabu
#          ffuf gobuster dirsearch sslscan sqlmap wpscan searchsploit smbclient
# ---------------------------------------------------------------------------
RUN set -eu; \
    rm -f /usr/bin/msfconsole /usr/bin/msfvenom /usr/bin/msfrpcd \
          /usr/bin/hydra /usr/bin/medusa /usr/bin/ncrack \
          /usr/bin/evil-winrm /usr/bin/netexec /usr/bin/crackmapexec \
          /usr/bin/weevely /usr/sbin/responder /usr/sbin/john \
          /usr/bin/hashcat /usr/bin/mimikatz 2>/dev/null || true; \
    find /usr/bin /usr/local/bin -maxdepth 1 \
          \( -name 'msf-*' -o -name 'impacket-*' \) -delete 2>/dev/null || true; \
    rm -rf /usr/share/metasploit-framework /usr/share/metasploit* \
           /opt/metasploit* /root/.msf4 /root/.local/share/mimikatz 2>/dev/null || true; \
    echo "[assess] exploitation tools removed"

# ---------------------------------------------------------------------------
# 2) 构建期固化 nuclei 模板（版本随镜像固定，运行时不再联网更新）
# ---------------------------------------------------------------------------
RUN nuclei -update-templates -silent || echo "[assess] nuclei templates update skipped"

# ---------------------------------------------------------------------------
# 3) testssl.sh（TLS/SSL 配置检测）。直连 GitHub 不稳定，依次尝试加速镜像
# ---------------------------------------------------------------------------
RUN set -eu; \
    rm -rf /opt/testssl.sh; \
    for base in \
        "https://kkgithub.com/testssl/testssl.sh" \
        "https://github.com/testssl/testssl.sh" \
        "https://gitee.com/mirrors/testssl.sh" \
        "https://ghfast.top/https://github.com/testssl/testssl.sh" \
        "https://gh-proxy.com/https://github.com/testssl/testssl.sh"; do \
      echo "[assess] trying $base"; \
      if git clone --depth 1 "$base" /opt/testssl.sh; then break; fi; \
      rm -rf /opt/testssl.sh; \
    done; \
    test -f /opt/testssl.sh/testssl.sh \
    && chmod +x /opt/testssl.sh/testssl.sh \
    && ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh \
    && echo "[assess] testssl.sh installed" \
    || { echo "[assess] testssl.sh download failed from all mirrors"; exit 1; }

# 4) 检测产物目录
RUN mkdir -p /opt/assessment/findings /opt/assessment/scans

# ---------------------------------------------------------------------------
# 5) 补齐 testssl.sh 运行依赖 hexdump（bsdextrautils），用国内 kali 镜像源
# ---------------------------------------------------------------------------
RUN set -eu; \
    mkdir -p /etc/apt/sources.list.d/disabled; \
    mv /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/disabled/ 2>/dev/null || true; \
    for mirror in mirrors.tuna.tsinghua.edu.cn mirrors.ustc.edu.cn; do \
      echo "deb https://$mirror/kali kali-rolling main contrib non-free" > /etc/apt/sources.list; \
      if apt-get update; then break; fi; \
    done; \
    apt-get install -y --no-install-recommends bsdextrautils; \
    command -v hexdump; \
    rm -rf /var/lib/apt/lists/*; \
    echo "[assess] hexdump installed"

# ---------------------------------------------------------------------------
# 6) 锁定包管理器：运行时无法 apt/dpkg 把利用工具装回来
#    （pip/git 保留，扫描器自身更新与证据采集需要；提示词层另有约束）
# ---------------------------------------------------------------------------
RUN chmod 000 /usr/bin/apt /usr/bin/apt-get /usr/bin/dpkg \
              /usr/bin/apt-config /usr/bin/apt-key 2>/dev/null || true; \
    echo "[assess] package managers locked"

LABEL org.opencontainers.image.title="pentagi-assess" \
      org.opencontainers.image.description="PentAGI non-destructive vulnerability assessment image"
