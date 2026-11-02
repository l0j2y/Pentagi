#!/usr/bin/env python3
"""
一键启用 / 回退 PentAGI「非破坏性漏洞检测模式」(L1 提示词层)。

原理：把 assessment/prompts/ 下的三个覆盖模板写入 pentagidb.prompts 表
      （PentAGI 官方支持的用户级提示词覆盖机制，按 user_id 隔离）。
      - pentester      渗透测试员  -> 非破坏性漏洞检测员（白名单工具 + 证据/防误报规则）
      - reporter       任务评估员  -> 漏洞检测报告格式（风险统计/证据/修复/复测）
      - image_chooser  镜像选择器  -> 安全类任务强制使用 pentagi-assess:latest 收窄镜像

生效：无需重启 pentagi，提示词在「新建 Flow」时从数据库加载；已有 Flow 不受影响。
前提：L2 镜像 pentagi-assess:latest 已构建（bash assessment/image/build.sh）。

用法（在 WSL Ubuntu 中，项目根目录）：
    python3 install_assessment_prompts.py              # 启用检测模式（覆盖写入）
    python3 install_assessment_prompts.py --uninstall  # 回退为官方默认（恢复渗透能力）
    python3 install_assessment_prompts.py --user-id 1  # 指定用户 id
"""
import argparse
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROMPT_DIR = BASE_DIR / "assessment" / "prompts"
DB_CONTAINER = "pgvector"
DB_USER = "postgres"
DB_NAME = "pentagidb"

# (模板类型, 文件名)
TEMPLATES = [
    ("pentester", "pentester.tmpl"),
    ("reporter", "reporter.tmpl"),
    ("image_chooser", "image_chooser.tmpl"),
]


def sql_quote(s: str) -> str:
    """PostgreSQL 标准字符串转义：单引号加倍（standard_conforming_strings=on）。"""
    return "'" + s.replace("'", "''") + "'"


def run_psql(sql: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "exec", DB_CONTAINER, "psql", "-U", DB_USER, "-d", DB_NAME,
         "-v", "ON_ERROR_STOP=1", "-c", sql],
        capture_output=True, text=True,
    )


def install(user_id: int) -> int:
    values = []
    for ptype, fname in TEMPLATES:
        fpath = PROMPT_DIR / fname
        if not fpath.exists():
            print(f"ERROR: template not found: {fpath}", file=sys.stderr)
            return 1
        body = fpath.read_text(encoding="utf-8")
        values.append(f"({user_id}, {sql_quote(ptype)}, {sql_quote(body)})")
        print(f"  loaded {ptype:<14} <- {fname} ({len(body)} chars)")

    sql = (
        "INSERT INTO prompts (user_id, type, prompt) VALUES\n"
        + ",\n".join(values)
        + "\nON CONFLICT (type, user_id) DO UPDATE SET prompt = EXCLUDED.prompt;"
    )
    res = run_psql(sql)
    if res.returncode != 0:
        print("FAILED to write prompts:\n" + res.stderr, file=sys.stderr)
        return 1
    print("\n" + res.stdout.strip())
    return verify(user_id)


def uninstall(user_id: int) -> int:
    types = ", ".join(sql_quote(t) for t, _ in TEMPLATES)
    res = run_psql(
        f"DELETE FROM prompts WHERE user_id = {user_id} AND type IN ({types});"
    )
    if res.returncode != 0:
        print("FAILED to delete prompts:\n" + res.stderr, file=sys.stderr)
        return 1
    print(res.stdout.strip())
    print("Assessment prompt overrides removed; built-in pentest prompts restored.")
    return verify(user_id)


def verify(user_id: int) -> int:
    types = ", ".join(sql_quote(t) for t, _ in TEMPLATES)
    res = run_psql(
        f"SELECT type, length(prompt) AS chars FROM prompts "
        f"WHERE user_id = {user_id} AND type IN ({types}) ORDER BY type;"
    )
    if res.returncode != 0:
        print(res.stderr, file=sys.stderr)
        return 1
    print("Current assessment overrides in DB:")
    print(res.stdout.strip() if res.stdout.strip() else "(none - using built-in defaults)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Toggle PentAGI vulnerability-assessment prompt mode")
    ap.add_argument("--uninstall", action="store_true", help="remove overrides and restore defaults")
    ap.add_argument("--user-id", type=int, default=1, help="PentAGI user id (default: 1 = admin)")
    args = ap.parse_args()

    if not PROMPT_DIR.exists() and not args.uninstall:
        print(f"ERROR: prompt directory not found: {PROMPT_DIR}", file=sys.stderr)
        return 1

    print("=== UNINSTALL assessment mode ===" if args.uninstall
          else "=== INSTALL vulnerability-assessment mode ===")
    return uninstall(args.user_id) if args.uninstall else install(args.user_id)


if __name__ == "__main__":
    sys.exit(main())
