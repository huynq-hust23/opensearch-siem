#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

ENV_FILE="$PROJECT_ROOT/.env"
if [[ -f "$ENV_FILE" ]]; then
    echo ">>> Loading environment from $ENV_FILE"
    set -a
    source "$ENV_FILE"
    set +a
else
    echo ">>> WARNING: $ENV_FILE not found – using defaults"
fi

export OPENSEARCH_URL="${OPENSEARCH_URL:-https://localhost:9200}"
export OPENSEARCH_USER="${OPENSEARCH_USER:-admin}"
export OPENSEARCH_PASS="${OPENSEARCH_INITIAL_ADMIN_PASSWORD:-${OPENSEARCH_PASS:-123456}}"
export RULES_DIR="${RULES_DIR:-configs/sigma_rules}"
export WORKERS="${WORKERS:-10}"

echo ">>> Environment:"
echo "    OPENSEARCH_URL  = $OPENSEARCH_URL"
echo "    OPENSEARCH_USER = $OPENSEARCH_USER"
echo "    OPENSEARCH_PASS = ****"
echo "    RULES_DIR       = $RULES_DIR"
echo "    WORKERS         = $WORKERS"

VENV_DIR="$PROJECT_ROOT/.venv"
if [[ -f "$VENV_DIR/bin/activate" ]]; then
    echo ">>> Activating virtualenv: $VENV_DIR"
    source "$VENV_DIR/bin/activate"
else
    echo ">>> ERROR: Virtualenv not found at $VENV_DIR"
    echo "   Tạo venv trước:  python3 -m venv .venv && source .venv/bin/activate"
    echo "   Cài dependencies: pip install -r requirements.txt"
    exit 1
fi

PYSIGMA_SCRIPT="$PROJECT_ROOT/configs/sigma_rules/pySigma.py"
if [[ ! -f "$PYSIGMA_SCRIPT" ]]; then
    echo ">>> ERROR: Script not found: $PYSIGMA_SCRIPT"
    exit 1
fi

echo ""
echo "=============================================="
echo "  Running deploy sigma rules"
echo "=============================================="
echo ""

cd "$PROJECT_ROOT"
python "$PYSIGMA_SCRIPT" "$@"
