L="$HOME/2XKO/.prefix-133/pfx/drive_c/users/steamuser/AppData/Local/Lion/Saved/Logs"
B="$L/Lion.log"
export DISPLAY=:0 WAYLAND_DISPLAY=wayland-1 XDG_RUNTIME_DIR=/run/user/1000
echo "--- mode / maps ---"
grep -aE 'EnterMajorMode|Bringing World|LogLoad: Game class' "$B" | tail -n 6 | cut -c1-120
echo "--- any vanguard fault? ---"
grep -ac 'VanguardFaulted' "$B"
echo "--- alive ---"
pgrep -c -f Lion-Win64-Shipping || true
grim /tmp/front.png 2>/dev/null && echo "shot $(stat -c%s /tmp/front.png)"