#!/usr/bin/env bash
set -euo pipefail

# Configuráveis
REMOTE="${REMOTE:-origin}"
BRANCH="${BRANCH:-main}"
MSG="${MSG:-auto sync: $(date -Iseconds) $(hostname) $USER}"

# Garante que estamos num repo
git rev-parse --is-inside-work-tree >/dev/null

echo "[1/4] Add & commit"
git add -A
if git diff --cached --quiet; then
  echo "Nada para commitar."
else
  git commit -m "$MSG"
fi

echo "[2/4] Fetch"
git fetch "$REMOTE" --prune

echo "[3/4] Pull --rebase"
git pull --rebase "$REMOTE" "$BRANCH"

echo "[4/4] Push"
git push "$REMOTE" HEAD:"$BRANCH"

echo "✔ Sync concluído."
