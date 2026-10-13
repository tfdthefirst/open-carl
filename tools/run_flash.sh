#!/bin/bash
DST="/home/battledoge/Games/open-carl/game-modded"
PROTON="/home/battledoge/.local/share/lutris/runners/wine/dw-proton-x86_64/proton"
export UMU_ID=0 SteamAppId=0 SteamGameId=0
export STEAM_COMPAT_DATA_PATH="/home/battledoge/Games/carl-proton"
export STEAM_COMPAT_CLIENT_INSTALL_PATH="/home/battledoge/Games/carl-proton"
export DXVK_LOG_LEVEL=none VKD3D_DEBUG=none WINEDLLOVERRIDES="winhttp=n,b"
export DISPLAY=:1 PROTON_ENABLE_WAYLAND=1
cd "$DST"
for attempt in 1 2 3 4; do
  echo "=== attempt $attempt ==="
  pkill -9 -f CARL.exe 2>/dev/null; pkill -9 -f dw-proton 2>/dev/null
  pkill -9 -f wineserver 2>/dev/null; pkill -9 -f umu 2>/dev/null
  sleep 10
  rm -f open-carl-flash.log
  setsid "$PROTON" waitforexitandrun "$DST/CARL.exe" -screen-fullscreen 0 -screen-width 1280 -screen-height 720 -force-d3d11 >/tmp/carl-flash.log 2>&1 &
  for i in $(seq 1 20); do
    sleep 3
    if grep -qE 'applied LoadImage' "$DST/open-carl-flash.log" 2>/dev/null; then
      echo "SUCCESS attempt $attempt at ~$((i*3))s"; cat "$DST/open-carl-flash.log"; exit 0
    fi
    if grep -qE 'missing|no png|no domain' "$DST/open-carl-flash.log" 2>/dev/null; then
      echo "LOGIC-ISSUE attempt $attempt"; cat "$DST/open-carl-flash.log"; exit 2
    fi
  done
  echo "attempt $attempt: no progress (log below)"; cat "$DST/open-carl-flash.log" 2>/dev/null
done
echo "ALL ATTEMPTS EXHAUSTED"
exit 1
