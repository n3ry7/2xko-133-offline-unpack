B="$HOME/2XKO/.prefix-133/pfx/drive_c/users/steamuser/AppData/Local/Lion/Saved/Logs/Lion.log"
echo "size: $(stat -c%s "$B")"
echo "--- tail ---"
tail -n 14 "$B" | cut -c1-150
echo "--- major mode / maps ---"
grep -aE 'MajorMode|Bringing World|LogLoad: Game class|Login' "$B" | tail -n 8 | cut -c1-140
echo "--- running ---"
pgrep -fa 'Lion-Win64' | head -n 2