# Running Kasiru as a service

Both templates expect the package installed into a virtualenv (`VENV`) and the config in `~/.config/kasiru`.

## macOS (launchd)

```bash
sed -e "s#{{VENV}}#$HOME/.venv-kasiru#g" -e "s#{{HOME}}#$HOME#g" deploy/org.kasiru.gateway.plist.template \
  > ~/Library/LaunchAgents/org.kasiru.gateway.plist
launchctl load ~/Library/LaunchAgents/org.kasiru.gateway.plist
tail -f ~/Library/Logs/kasiru.log
```

## Linux (systemd --user)

```bash
sed -e "s#{{VENV}}#$HOME/.venv-kasiru#g" deploy/kasiru.service.template > ~/.config/systemd/user/kasiru.service
systemctl --user daemon-reload && systemctl --user enable --now kasiru
journalctl --user -u kasiru -f
```

## Behind a reverse proxy

Kasiru checks client keys itself, so a proxy is optional. If you terminate TLS or expose it on a LAN, keep `listen`
on `127.0.0.1` and proxy to it; do not strip the `Authorization` header.

## Backups

`~/.config/kasiru/` (config, keys, dictionary) and `~/.local/state/kasiru/` (tokens, quotas, cache, audit). The token
table is the file that turns pseudonyms back into people: back it up encrypted and nowhere else.
