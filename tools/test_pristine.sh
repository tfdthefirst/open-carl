#!/bin/bash
DST="/home/battledoge/Games/open-carl/game-modded"
PROTON="/home/battledoge/.local/share/lutris/runners/wine/dw-proton-x86_64/proton"
MAIN="/home/battledoge/Games/carl-proton/pfx/drive_c/users/steamuser/AppData/LocalLow/Independent Prototype/Project C.A.R.L. 0.8.71/Player.log"
pkill -9 -f CARL.exe 2>/dev/null; pkill -9 -f dw-proton 2>/dev/null; pkill -9 -f wineserver 2>/dev/null; pkill -9 -f umu 2>/dev/null
sleep 8
# move version.dll aside -> pristine, no injection, no override
mv "$DST/version.dll" "$DST/../version.dll.bak" 2>/dev/null
export UMU_ID=0 SteamAppId=0 SteamGameId=0
export STEAM_COMPAT_DATA_PATH="/home/battledoge/Games/carl-proton"
export STEAM_COMPAT_CLIENT_INSTALL_PATH="/home/battledoge/Games/carl-proton"
export DXVK_LOG_LEVEL=none VKD3D_DEBUG=none
export DISPLAY=:1 PROTON_ENABLE_WAYLAND=1
cd "$DST"
setsid "$PROTON" waitforexitandrun "$DST/CARL.exe" -screen-fullscreen 0 -screen-width 1280 -screen-height 720 -force-d3d11 >/tmp/carl-pristine.log 2>&1 &
sleep 45
echo "=== PRISTINE (no injection) results ==="
grep -nE 'OFFICIAL_CONTENT|Crash!!!|LabSession:Awake|LabCursor' "$MAIN" 2>/dev/null | tail -8
echo "=== game still up? ==="; pgrep -f CARL.exe >/dev/null && echo "YES - pristine runs fine" || echo "NO - pristine also exits/crashes"
pkill -9 -f CARL.exe 2>/dev/null; pkill -9 -f dw-proton 2>/dev/null
# restore
mv "$DST/../version.dll.bak" "$DST/version.dll" 2>/dev/null
echo "(version.dll restored)"
