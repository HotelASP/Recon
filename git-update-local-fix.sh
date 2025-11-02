#!/usr/bin/env bash
set -euo pipefail

# Configurar remoto/branch por argumento ou usar origin/main
REMOTE=${1:-origin}
BRANCH=${2:-main}

cd "$(git rev-parse --show-toplevel)"

echo "[0] Removendo estado de rebase pendente (se existir)..."
rm -rf .git/rebase-merge .git/rebase-apply || true

echo "[1] Forçando fetch do remoto ${REMOTE}..."
git fetch --prune "${REMOTE}"

echo "[2] Reset hard para ${REMOTE}/${BRANCH} (PERMANENTE)..."
git reset --hard "${REMOTE}/${BRANCH}"

echo "[3] Limpeza de ficheiros não rastreados e ignorados (PERMANENTE)..."
git clean -fdx

echo "[4] Verificação final"
git status --short
git log --oneline -n 5

echo "Feito. O repositório local agora corresponde a ${REMOTE}/${BRANCH}."
