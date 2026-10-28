#!/usr/bin/env bash
# 전체 검증 진입점: 문법 검사 + 테스트.  사용: scripts/check.sh [pytest 인자]
set -euo pipefail
cd "$(dirname "$0")/.."
python -m compileall -q certpilot_core certpilot_api certpilot_cli certdeploy
python -m pytest "$@"
