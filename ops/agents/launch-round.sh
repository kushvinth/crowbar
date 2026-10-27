#!/usr/bin/env bash
# Launch one round of gnhf agents, one pane per brief, in a new zellij tab or tmux window.
#   launch-round.sh <round> [tab-name]     from the repo root (a NON-gnhf branch); briefs in ops/agents/<round>/
#   launch-round.sh <round> run <n>        run agent <n> in the current terminal (what each pane does)
#   launch-round.sh <round> status         alive?, last commit and last status line per agent (read-only)
#   launch-round.sh <round> prune <into>   remove finished worktrees + branches whose commits are all in <into> (and clean)
# Briefs: ops/agents/<round>/00-common.md (shared rules) + <n>-<slug>.md (one per agent, n = 1..9), committed.
# Every agent gets its own git worktree branched from the current branch.
# Env: GNHF_MAX_TOKENS (200M), GNHF_MAX_ITER (60), GNHF_STAGGER seconds between starts (30),
#      GNHF_AGENT (claude), GNHF_MUX (zellij|tmux; default: whichever you are inside, else zellij).
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"
round="${1:?usage: launch-round.sh <round> [tab-name] | <round> run <n>}"
dir="ops/agents/$round"
[ -d "$dir" ] || { echo "no briefs in $dir" >&2; exit 1; }
self="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

run_agent() {
  local n=$1 brief prompt
  brief=$(ls "$dir/$n"-*.md)
  prompt="$(cat "$dir/00-common.md")

$(cat "$brief")

You are round $round agent $n. Your status file is ops/agents/status/$round-$n.md."
  echo "== $round agent $n: $(head -1 "$brief" | sed 's/^# //')"
  export NOTIFY_INSTANCE="gnhf $round agent $n"      # so the phone ping from this agent's hooks says which one it is
  local wait=$(( (n - 1) * ${GNHF_STAGGER:-30} ))
  if [ "$wait" -gt 0 ]; then echo "starting in ${wait}s…"; sleep "$wait"; fi
  exec gnhf --agent "${GNHF_AGENT:-claude}" --worktree \
    --prevent-sleep on \
    --max-tokens "${GNHF_MAX_TOKENS:-200000000}" \
    --max-iterations "${GNHF_MAX_ITER:-60}" \
    --max-rate-limit-wait 3h \
    --stop-when "the last line of ops/agents/status/$round-$n.md is exactly ALL DONE" \
    "$prompt"
}

# worktree path + branch pairs of this repo's gnhf branches for a round (round name is part of the branch slug)
gnhf_worktrees() {
  git worktree list --porcelain | awk '/^worktree /{w=$2} /^branch refs\/heads\/gnhf\//{sub("refs/heads/","",$2); print w "|" $2}'
}

if [ "${2:-}" = status ]; then
  alive=$(pgrep -f "You are round $round agent" | wc -l | tr -d ' ')
  echo "round $round: $alive agent process(es) alive"
  for f in "$dir"/[1-9]*-*.md; do
    n=$(basename "$f" | cut -d- -f1); st="ops/agents/status/$round-$n.md"
    while IFS='|' read -r w b; do
      [ -f "$w/$st" ] || continue
      printf '  agent %s  %-40s last commit %-14s | %s\n' "$n" "$b" "$(git log -1 --format=%cr "$b")" "$(tail -1 "$w/$st" | cut -c1-90)"
    done < <(gnhf_worktrees)
  done
  exit 0
fi

if [ "${2:-}" = prune ]; then
  into="${3:?usage: launch-round.sh <round> prune <branch the work was merged into>}"
  ! pgrep -f "You are round $round agent" >/dev/null || { echo "Round $round agents are still running: stop them first." >&2; exit 1; }
  record="$root/../$(basename "$root")-gnhf-worktrees/pruned-branches-$(date +%F).txt"; mkdir -p "$(dirname "$record")"
  while IFS='|' read -r w b; do
    [ "$w" != "$root" ] || continue
    if ! git merge-base --is-ancestor "$b" "$into"; then echo "keep   $b (has commits that are not in $into)"; continue; fi
    if [ -n "$(git -C "$w" status --porcelain)" ]; then echo "keep   $b (uncommitted files in $w)"; continue; fi
    echo "$b $(git rev-parse --short "$b")" >> "$record"          # so a branch can be brought back
    git worktree remove "$w" && git branch -D -q "$b" && echo "pruned $b"
  done < <(gnhf_worktrees)
  git worktree prune; echo "names and commits saved in $record"; exit 0
fi

if [ "${2:-}" = run ]; then run_agent "${3:?usage: launch-round.sh <round> run <n>}"; fi
tab="${2:-gnhf-$round}"

branch=$(git rev-parse --abbrev-ref HEAD)
case "$branch" in gnhf/*) echo "On gnhf branch '$branch': run from a base or integration branch." >&2; exit 1;; esac
[ -z "$(git status --porcelain -- "$dir")" ] || { echo "Commit the briefs in $dir first (worktrees only see commits)." >&2; exit 1; }
! pgrep -f "You are round $round agent" >/dev/null || { echo "Round $round agents are already running." >&2; exit 1; }
command -v gnhf >/dev/null || { echo "gnhf is not installed." >&2; exit 1; }
if [ "${GNHF_AGENT:-claude}" = claude ] && command -v claude >/dev/null; then     # an expired login makes every agent die silently
  claude auth status 2>/dev/null | grep -q '"loggedIn": true' || { echo "Claude Code is not signed in: run 'claude' and /login first." >&2; exit 1; }
fi
briefs=("$dir"/[1-9]*-*.md)
[ -e "${briefs[0]}" ] || { echo "no agent briefs (<n>-<slug>.md) in $dir" >&2; exit 1; }

mux=${GNHF_MUX:-}
[ -n "$mux" ] || { [ -n "${TMUX:-}" ] && mux=tmux; } || true
mux=${mux:-zellij}

if [ "$mux" = tmux ]; then
  first=1
  for f in "${briefs[@]}"; do
    n=$(basename "$f" | cut -d- -f1)
    if [ "$first" = 1 ]; then tmux new-window -n "$tab" -c "$root" "bash '$self' '$round' run $n"; first=0
    else tmux split-window -t "$tab" -c "$root" "bash '$self' '$round' run $n"; tmux select-layout -t "$tab" tiled >/dev/null; fi
  done
else
  panes=""
  for f in "${briefs[@]}"; do
    n=$(basename "$f" | cut -d- -f1)
    title=$(head -1 "$f" | sed -e 's/^# //' -e 's/"//g' | cut -c1-60)
    panes+="    pane name=\"$round-$n: $title\" command=\"bash\" cwd=\"$root\" { args \"$self\" \"$round\" \"run\" \"$n\"; }
"
  done
  layout="layout {
  pane size=1 borderless=true { plugin location=\"zellij:tab-bar\"; }
  pane split_direction=\"vertical\" {
$panes  }
  pane size=2 borderless=true { plugin location=\"zellij:status-bar\"; }
}"
  if [ -n "${ZELLIJ:-}" ]; then zellij action new-tab --name "$tab" --cwd "$root" --layout-string "$layout"
  else zellij --session "${ZELLIJ_SESSION:-$(zellij list-sessions -s 2>/dev/null | head -1)}" action new-tab --name "$tab" --cwd "$root" --layout-string "$layout"; fi
fi
echo "Opened '$tab' ($mux) with ${#briefs[@]} agents from $branch. Status: ops/agents/status/$round-<n>.md"
