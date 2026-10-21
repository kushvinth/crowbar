# Scheduling with nix-darwin (not launchctl)

This machine is declarative: config lives in `~/dotfiles/nix` and is applied
with `darnix` (`nh darwin switch`). Do **not** use `crowbar install-agent` - it
writes a LaunchAgent imperatively and will drift from the flake.

## Home Manager module

Add to `~/dotfiles/nix/modules/home/` (e.g. `crowbar.nix`) and import it:

```nix
{ config, pkgs, lib, ... }:
let
  home = config.home.homeDirectory;

  # Prefer the drive copy; fall back to a local checkout; do nothing otherwise.
  updater = pkgs.writeShellScript "crowbar-update" ''
    export PATH=/run/current-system/sw/bin:/usr/bin:/bin:/usr/sbin:/sbin
    HV="$HOME/.crowbar/bin/crowbar"
    [ -x "$HV" ] || HV="${home}/LocalStorage/Developer/personal/security/hacking/harness/bin/crowbar"
    [ -x "$HV" ] || exit 0
    exec "$HV" update --quiet --if-mounted
  '';in
{
  launchd.agents.crowbar = {
    enable = true;
    config = {
      Label = "sh.crowbar.update";
      ProgramArguments = [ "${updater}" ];
      StartInterval = 600;              # every 10 min
      WatchPaths = [ "/Volumes" ];      # and whenever a volume appears
      RunAtLoad = true;
      StandardOutPath = "${home}/Library/Logs/crowbar.log";
      StandardErrorPath = "${home}/Library/Logs/crowbar.log";
      EnvironmentVariables.PATH = "/run/current-system/sw/bin:/usr/bin:/bin:/usr/sbin:/sbin";
    };
  };
}
```

Then `darnix` and confirm:

```bash
launchctl print gui/$(id -u)/sh.crowbar.update | head
tail -f ~/Library/Logs/crowbar.log
```

## TCC caveat (verified 2026-10-20)

A launchd agent gets `EPERM` reading `/Volumes/...` on this macOS version:

```
ls: /Volumes/VAULT/crowbar: Operation not permitted
```

Two ways out:

1. **Mirror instead of hosting the live index** (recommended):
   keep `crowbar.db` on the internal disk and push a snapshot to the drive with
   `crowbar mirror /Volumes/VAULT/crowbar`. The timer never touches `/Volumes`,
   so no TCC grant is needed. (Command tracked in `TODO.md`.)
2. **Grant Full Disk Access** to the process the agent runs (`/bin/sh`, or the
   `/nix/store/...-crowbar-update` script) in
   System Settings → Privacy & Security → Full Disk Access, then restart the
   agent. This is a manual UI step and cannot be declared in nix.

Until either is done, run `~/.crowbar/bin/crowbar update` manually after plugging
the drive in.
