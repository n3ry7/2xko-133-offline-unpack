B="$HOME/2XKO/.prefix-133/pfx/drive_c/users/steamuser/AppData/Local/Lion/Saved/Logs/Lion.log"
echo "--- dynamicconfig lines ---"
grep -ai 'dynamicconfig' "$B" | head -n 12 | cut -c1-150
echo "--- vanguard.required ---"
grep -ai 'vanguard.required\|vanguard.netrequired' "$B" | head -n 5 | cut -c1-150
echo "--- lionvanguard lines ---"
grep -a 'LogLionVanguard' "$B" | head -n 10 | cut -c1-150