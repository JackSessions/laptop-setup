# Manual bits of the desktop look (not copied automatically; they live in vendor config files)
- Waybar: `UserModules` gets a `custom/powerdraw` module (exec PowerDraw.sh, interval 3, on-click `powermode cycle`),
  and `ModulesGroups` `group/laptop` lists it before `battery`.
- Hyprland keybinds (UserConfigs/user_keybinds.lua): see `dotfiles/user_keybinds.lua` (tap-Super app grid toggle,
  Super+Shift+I caffeine, Super+Shift+F10 power profile).
- WallustSwww.sh calls KittyContrast.py right after the kitty wallust run.
- ~/.zshrc: `$HOME/.local/bin/ff`, atuin init, eza aliases, yazi `y` function.

## Added later
- Waybar: `custom/siem` (SiemStats.sh, interval 10, click -> `soc`) sits after `network#speed` in `configs/TOP-Minimal-Laptop`; classes ok/alerts/high/off.
- `soc` (Super+Alt+K): floating translucent Kibana on workspace 9. This Hyprland takes Lua dispatchers:
  `hyprctl dispatch 'hl.dsp.window.move({ workspace = 9, follow = false, window = "address:0x.." })'` (plain `dispatch workspace 9` no longer works).
- Login screen: `sync-login-wallpaper` (root) is called from WallustSwww.sh so GDM follows the wallpaper.
- Neovim: transparent background + ASD dashboard header live in `~/.config/nvim/lua/plugins/kool.lua`.

## Floating bar, pinned apps, USB popup
- Bar: `configs/TOP-Icons-Laptop` (margins 10/18), glass pill via CSS (`window#waybar` translucent + border-radius) and a
  Hyprland layer rule `user-waybar-blur` in `UserConfigs/user_layer_rules.lua`.
- Pins: `barpin add "Name" <glyph> <command>` / `barpin rm` / `barpin ls`. They live behind one pin icon (hover). Compiled to
  `~/.config/hypr/waybar/PinModules`, included by the Waybar config.
- USB: `usbguard-prompt` (user service) shows an Allow once / Always allow / Keep blocked dialog when USBGuard blocks a device.
- Dock: auto-hides at the bottom edge by default (`~/.config/hypr/dock-mode` = `auto` or `always`); `dockpin add|rm|ls|mode`.
  Launch flags live in `~/.config/hypr/scripts/Dock.sh` (`-d` auto-hide, no `-x`, so windows use the full screen).
- Keys: Super+D compact launcher, Super+Shift+D frosted fullscreen grid (the tap-Super trigger was removed).
