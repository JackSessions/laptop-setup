#!/usr/bin/env python3
"""Make the wallust kitty theme readable.

- foreground: a light tint of the colour opposite (complement) to the wallpaper's accent hue
- ANSI colours: keep each hue but raise lightness until contrast with the background is >= 5:1
Rewrites ~/.config/hypr/UserConfigs/kitty-themes/01-Wallust.conf in place (idempotent).
"""
import colorsys, os, re, sys

path = os.path.expanduser("~/.config/hypr/UserConfigs/kitty-themes/01-Wallust.conf")
MIN_ANSI, MIN_FG = 5.0, 10.0

def hex2rgb(h): h = h.lstrip("#"); return tuple(int(h[i:i+2], 16) / 255 for i in (0, 2, 4))
def rgb2hex(c): return "#%02X%02X%02X" % tuple(round(max(0, min(1, v)) * 255) for v in c)
def lum(c):
    f = lambda v: v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = map(f, c); return 0.2126 * r + 0.7152 * g + 0.0722 * b
def contrast(a, b):
    la, lb = sorted((lum(a), lum(b)), reverse=True); return (la + 0.05) / (lb + 0.05)
def lift(c, bg, need):
    h, l, s = colorsys.rgb_to_hls(*c)
    while contrast(colorsys.hls_to_rgb(h, l, s), bg) < need and l < 0.97: l += 0.01
    return colorsys.hls_to_rgb(h, l, s)

text = open(path).read()
get = lambda k: re.search(rf"^{k}\s+(#[0-9A-Fa-f]{{6}})", text, re.M)
bg = hex2rgb(get("background").group(1))

# accent hue = most saturated of colour1-6
best = max((hex2rgb(get(f"color{i}").group(1)) for i in range(1, 7)),
           key=lambda c: colorsys.rgb_to_hls(*c)[2])
ah = colorsys.rgb_to_hls(*best)[0]
comp = (ah + 0.5) % 1.0
fg = lift(colorsys.hls_to_rgb(comp, 0.80, 0.45), bg, MIN_FG)
cursor = lift(colorsys.hls_to_rgb(comp, 0.65, 0.75), bg, MIN_ANSI)

def sub(key, val, t):
    return re.sub(rf"^({key}\s+)#[0-9A-Fa-f]{{6}}", lambda m: m.group(1) + rgb2hex(val), t, flags=re.M)

text = sub("foreground", fg, text)
text = sub("cursor", cursor, text)
text = sub("active_tab_background", fg, text)
text = sub("inactive_tab_foreground", fg, text)
text = sub("active_border_color", fg, text)
for i in list(range(1, 7)) + list(range(9, 15)):
    c = hex2rgb(get(f"color{i}").group(1))
    text = sub(f"color{i}", lift(c, bg, MIN_ANSI), text)
for i in (7, 15):  # light greys: keep readable but not equal to fg
    c = hex2rgb(get(f"color{i}").group(1))
    text = sub(f"color{i}", lift(c, bg, MIN_FG), text)
open(path, "w").write(text)
print("kitty contrast fixed; fg", rgb2hex(fg), "on bg", rgb2hex(bg), "ratio %.1f" % contrast(fg, bg))
