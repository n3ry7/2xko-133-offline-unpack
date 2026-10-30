#!/usr/bin/env bash
B=/home/nery/2XKO/.prefix-133/pfx/drive_c/users/steamuser/AppData/Local/Lion/Saved/Logs/Lion.log
echo "size: $(stat -c%s "$B")"
echo "--- first 3 ---"
head -n 3 "$B"
echo "--- last 15 ---"
tail -n 15 "$B"
echo "--- level / mode markers ---"
grep -aiE 'Bringing World|MajorMode|FRELevel|RetailLevel|FrontendLevel|Game class' "$B" | tail -n 8
