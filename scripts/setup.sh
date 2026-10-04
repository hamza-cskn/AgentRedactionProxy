#!/usr/bin/env bash
# Keep execution inside main so an incomplete piped download cannot start setup.
main() {
  set -euo pipefail
  local action="${1:-install}"
  local project plugin receipt lock image container volume revision source
  local plugin_created=0 config_created=0 receipt_created=0 lock_created=0
  local opencode_created=0 plugins_created=0 container_created=0 container_started=0
  local completed=0 install_id=''
  project=$(pwd -P)
  plugin="$project/.opencode/plugins/openai-ipv4-proxy.js"
  receipt="$project/.opencode/.agent-redaction-proxy-install"
  lock="$project/.opencode/.agent-redaction-proxy-setup.lock"
  image='366366/agent-redaction-proxy:latest'
  container='agent-redaction-proxy'
  volume='agent-redaction-proxy-data'
  revision='48db0510c92dd7b152331498fd0d76651b5fe9bb'
  source="https://raw.githubusercontent.com/hamza-cskn/AgentRedactionProxy/$revision"

  fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }
  checksum() {
    if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d ' ' -f 1
    else shasum -a 256 "$1" | cut -d ' ' -f 1; fi
  }
  cleanup() {
    local status=$?
    trap - EXIT
    if [[ $completed == 0 && $action == install ]]; then
      if [[ $plugin_created == 1 ]] && cmp -s "$plugin" "$receipt/plugin.reference"; then rm "$plugin"; fi
      if [[ $config_created == 1 ]] && cmp -s "$project/opencode.jsonc" "$receipt/config.reference"; then rm "$project/opencode.jsonc"; fi
      if [[ $container_created == 1 ]] && [[ $(docker inspect --format '{{index .Config.Labels "io.agent-redaction-proxy.install-id"}}' "$container" 2>/dev/null || true) == "$install_id" ]]; then
        docker rm -f "$container" >/dev/null || printf 'Could not remove the newly created container.\n' >&2
      elif [[ $container_started == 1 ]]; then
        docker stop "$container" >/dev/null || printf 'Could not restore the previously stopped container.\n' >&2
      fi
      if [[ $receipt_created == 1 ]]; then
        rm -f "$receipt/plugin.reference" "$receipt/config.reference" "$receipt/plugin.staged" "$receipt/config.staged"
        rmdir "$receipt" || true
      fi
      if [[ $plugins_created == 1 ]]; then rmdir "$project/.opencode/plugins" 2>/dev/null || true; fi
    fi
    if [[ $lock_created == 1 ]]; then rmdir "$lock" || true; fi
    if [[ $completed == 0 && $opencode_created == 1 ]]; then rmdir "$project/.opencode" 2>/dev/null || true; fi
    exit "$status"
  }

  [[ $# -le 1 && ( $action == install || $action == uninstall ) ]] || fail 'Usage: bash setup.sh [install|uninstall]'
  case $(uname -s) in Darwin|Linux) ;; *) fail 'This installer supports macOS and Linux.' ;; esac
  [[ $project != / && $project != "$HOME" ]] || fail 'Go to your project directory before running setup.'
  for file in "$project/.opencode" "$project/.opencode/plugins" "$receipt" "$lock" "$plugin" "$project/opencode.json" "$project/opencode.jsonc"; do
    [[ ! -L $file ]] || fail 'Setup paths must not be symbolic links.'
  done
  if [[ $action == uninstall && ! -e $receipt ]]; then
    printf 'No managed installation in this project. Nothing changed.\n'
    return
  fi
  if [[ ! -d $project/.opencode ]]; then mkdir "$project/.opencode"; opencode_created=1; fi
  mkdir "$lock" 2>/dev/null || fail 'Another setup is running, or a setup lock remains. Nothing changed.'
  lock_created=1
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  if [[ -e $receipt ]]; then
    [[ -d $receipt && -f $receipt/plugin.reference && ! -L $receipt/plugin.reference ]] || fail 'Invalid installation receipt; refusing to modify files.'
    for file in "$receipt"/* "$receipt"/.[!.]* "$receipt"/..?*; do
      [[ -e $file || -L $file ]] || continue
      case $file in "$receipt/plugin.reference"|"$receipt/config.reference")
        [[ -f $file && ! -L $file ]] || fail 'Invalid installation receipt.' ;;
        *) fail 'Unexpected receipt files; refusing to modify files.' ;;
      esac
    done
    if [[ -e $plugin ]]; then cmp -s "$plugin" "$receipt/plugin.reference" || fail 'Installed plugin was modified; keep it or remove it manually.'; fi
    if [[ -e $receipt/config.reference && -e $project/opencode.jsonc ]]; then
      cmp -s "$project/opencode.jsonc" "$receipt/config.reference" || fail 'Installed config was modified; keep it or remove it manually.'
    fi
  elif [[ -e $plugin ]]; then
    fail 'An existing plugin is not managed by this installer. It will not be overwritten.'
  fi

  if [[ $action == uninstall ]]; then
    [[ ! -e $plugin ]] || rm "$plugin"
    if [[ -f $receipt/config.reference && -e $project/opencode.jsonc ]]; then rm "$project/opencode.jsonc"; fi
    rm -f "$receipt/plugin.reference" "$receipt/config.reference"
    rmdir "$receipt"
    completed=1
    printf 'Project integration removed. Existing config, credentials, shared proxy and mapping data were preserved.\n'
    cleanup
  fi

  for command in curl docker opencode cmp; do command -v "$command" >/dev/null || fail "Install $command first, then run setup again."; done
  command -v sha256sum >/dev/null || command -v shasum >/dev/null || fail 'A SHA-256 checksum tool is required.'
  docker info >/dev/null 2>&1 || fail 'Start Docker, then run setup again.'
  local auth_summary
  auth_summary=$(opencode auth list --pure 2>&1) || fail 'Cannot inspect OpenCode login. Existing credentials were not changed.'
  printf '%s\n' "$auth_summary" | grep -Eiq 'OpenAI.*oauth' || fail 'Sign in first: opencode auth login --provider openai --pure'

  if [[ ! -e $receipt ]]; then
    (umask 077; mkdir "$receipt")
    receipt_created=1
    curl -fsSL --proto '=https' --tlsv1.2 "$source/.opencode/plugins/openai-ipv4-proxy.js" -o "$receipt/plugin.reference"
    [[ $(checksum "$receipt/plugin.reference") == 6cdd0455045d2f42802127bc19eb17c9e72cfb74283149a2dc32f5064e983fb5 ]] || fail 'Plugin checksum mismatch. Nothing installed.'
    if [[ ! -e $project/opencode.json && ! -e $project/opencode.jsonc ]]; then
      curl -fsSL --proto '=https' --tlsv1.2 "$source/examples/opencode.jsonc" -o "$receipt/config.reference"
      [[ $(checksum "$receipt/config.reference") == 2b5b98a5f7d694cc699280a0d072030cae33c24819d294a5c36e57f90e48917e ]] || fail 'Config checksum mismatch. Nothing installed.'
    fi
  fi

  if docker inspect "$container" >/dev/null 2>&1; then
    [[ $(docker inspect --format '{{index .Config.Labels "io.agent-redaction-proxy.managed"}}' "$container") == 1 ]] || fail 'An unmanaged container already uses this name. Keep your existing setup or resolve the conflict manually.'
    [[ $(docker inspect --format '{{.Config.Image}}' "$container") == "$image" ]] || fail 'Existing container uses a different image.'
    [[ $(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' "$container") == "$volume" ]] || fail 'Existing container uses different mapping storage.'
    for port in 8787 8788; do
      [[ $(docker port "$container" "$port/tcp") == "127.0.0.1:$port" ]] || fail 'Existing container uses different port bindings.'
    done
    if [[ $(docker inspect --format '{{.State.Running}}' "$container") != true ]]; then
      docker start "$container" >/dev/null
      container_started=1
    fi
  else
    docker pull "$image"
    install_id="arp-$$-$(date +%s)"
    container_created=1
    docker run -d --name "$container" --init --read-only --cap-drop=ALL --security-opt=no-new-privileges \
      --label io.agent-redaction-proxy.managed=1 --label "io.agent-redaction-proxy.install-id=$install_id" \
      -p 127.0.0.1:8787:8787 -p 127.0.0.1:8788:8788 \
      -v "$volume:/data" --tmpfs /tmp:size=16m,mode=1777 "$image" >/dev/null
  fi
  local ready=0 attempt
  for attempt in {1..15}; do
    if docker exec "$container" node -e 'const net=require("node:net"); Promise.all([8787,8788].map(port=>new Promise((resolve,reject)=>{const socket=net.connect(port,"127.0.0.1"); socket.setTimeout(1000); socket.once("connect",()=>{socket.destroy();resolve();}); socket.once("error",reject); socket.once("timeout",()=>{socket.destroy();reject();});}))).then(()=>process.exit(0),()=>process.exit(1))' >/dev/null 2>&1; then ready=1; break; fi
    sleep 1
  done
  [[ $ready == 1 ]] || fail 'Proxy listeners did not start. Inspect Docker logs; no project integration was installed.'
  if [[ ! -d $project/.opencode/plugins ]]; then mkdir "$project/.opencode/plugins"; plugins_created=1; fi
  if [[ ! -e $plugin ]]; then
    cp "$receipt/plugin.reference" "$receipt/plugin.staged"
    ln "$receipt/plugin.staged" "$plugin"
    plugin_created=1
    rm "$receipt/plugin.staged"
    chmod 644 "$plugin"
  fi
  if [[ -f $receipt/config.reference && ! -e $project/opencode.json && ! -e $project/opencode.jsonc ]]; then
    cp "$receipt/config.reference" "$receipt/config.staged"
    ln "$receipt/config.staged" "$project/opencode.jsonc"
    config_created=1
    rm "$receipt/config.staged"
    chmod 644 "$project/opencode.jsonc"
  fi
  local models
  models=$(opencode models openai 2>/dev/null) || fail 'OpenCode could not load OpenAI models. Project changes will be rolled back.'
  printf '%s\n' "$models" | grep -q '^openai/' || fail 'Your existing configuration disables OpenAI models. Enable OpenAI before running setup again.'
  completed=1
  printf 'Ready. Restart OpenCode in this project and select an OpenAI model with /models.\n'
  cleanup
}

main "$@"
