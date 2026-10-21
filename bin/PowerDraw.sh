#!/usr/bin/env bash
# Waybar module: live battery power draw in watts.
# Discharging = what the laptop is consuming; Charging = charge rate going into the battery.
bat=/sys/class/power_supply/BAT0
[[ -r $bat/power_now ]] || { echo '{"text":"","class":"hidden"}'; exit 0; }
uw=$(<"$bat/power_now"); status=$(<"$bat/status")
w=$(awk -v u="$uw" 'BEGIN{printf "%.1f", u/1000000}')
case "$status" in
  Charging)    icon="󱐋"; cls="charging";   tip="Charging at ${w} W" ;;
  Discharging) icon="󰢜"; cls="discharging"; tip="Drawing ${w} W from the battery" ;;
  *)           icon="󰚥"; cls="idle";        tip="${status} (${w} W)" ;;
esac
awk -v w="$w" 'BEGIN{exit !(w+0 >= 25)}' && [[ $cls == discharging ]] && cls="high"
printf '{"text":"%s %s W","class":"%s","tooltip":"%s\\nProfile: %s"}\n' "$icon" "$w" "$cls" "$tip" "$(powerprofilesctl get 2>/dev/null)"
