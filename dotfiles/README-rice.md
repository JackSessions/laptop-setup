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
