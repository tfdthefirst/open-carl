#!/bin/bash
# Launch the open-carl modded build.
# The version.dll injector swaps the main-menu logo image for text: "OPEN C.A.R.L."
GAME="$HOME/Games/open-carl/game-modded"
PROTON="$HOME/.local/share/lutris/runners/wine/dw-proton-x86_64/proton"
export UMU_ID=0 SteamAppId=0 SteamGameId=0
export STEAM_COMPAT_DATA_PATH="$HOME/Games/carl-proton"
export STEAM_COMPAT_CLIENT_INSTALL_PATH="$HOME/Games/carl-proton"
export DXVK_FRAME_RATE=60 DXVK_LOG_LEVEL=none VKD3D_DEBUG=none
export PROTON_ENABLE_WAYLAND=1
# Inject our code via version.dll (UnityPlayer imports it; the game doesn't rely on it).
export WINEDLLOVERRIDES="version=n,b"
GM=""; command -v gamemoderun >/dev/null && GM="gamemoderun"
cd "$GAME" || exit 1
exec $GM python3 "$PROTON" waitforexitandrun "$GAME/CARL.exe" \
  -screen-width 1600 -screen-height 900 -screen-fullscreen 1 -force-d3d11 "$@"
