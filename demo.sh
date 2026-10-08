#!/usr/bin/env bash
# Runs the three scenarios of the talk, one after the other, on the same alert.
# Always restores the data, even if you stop it with Ctrl+C.
#   ./demo.sh            Spanish, step by step
#   ./demo.sh --lang en  English
#   ./demo.sh --fast     no pauses (for recording)
set -e
cd "$(dirname "$0")"
ARGS="$*"
restore() {
  [ -d data/workspace.off ] && mv data/workspace.off data/workspace
  rm -f data/siem/drive_events_extra.json
  return 0
}
trap restore EXIT
restore
banner() { printf '\n\033[1m\033[95m════════  %s  ════════\033[0m\n' "$1"; }
pause() { [[ "$ARGS" == *--fast* ]] || read -rp $'\033[90m  [enter]\033[0m' _; }

banner "1/3 · la alerta del viernes · Friday's alert"
python3 triage.py $ARGS
pause

banner "2/3 · apagamos Workspace · we take Workspace down"
echo "  $ mv data/workspace data/workspace.off"
mv data/workspace data/workspace.off
python3 triage.py $ARGS
mv data/workspace.off data/workspace
pause

banner "3/3 · un log que da órdenes · a log that gives orders"
echo "  $ cp scenarios/injection/drive_events_extra.json data/siem/"
cp scenarios/injection/drive_events_extra.json data/siem/
python3 triage.py $ARGS
