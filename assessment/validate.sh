#!/usr/bin/env bash
# 渲染健全性检查：修改 assessment/prompts/*.tmpl 后运行
# bash assessment/validate.sh
set -euo pipefail
cd "$(dirname "$0")"
docker run --rm -v "$PWD:/t" -w /t -e GOCACHE=/tmp/gocache -e GO111MODULE=off \
  golang:1.26-bookworm go run validate_templates.go
