#!/usr/bin/env bash
set -euo pipefail

# Configurações
REMOTE="${REMOTE:-origin}"
BRANCH="${BRANCH:-main}"

# Verifica se é um repositório git
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
  echo "Erro: este diretório não é um repositório Git."
  exit 1
}

echo "[1/3] Fetch do remoto..."
git fetch "$REMOTE" --prune

echo "[2/3] Rebase com a branch remota..."
git pull --rebase "$REMOTE" "$BRANCH"

echo "[3/3] Atualização concluída."
