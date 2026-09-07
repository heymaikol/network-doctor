#compdef netdoc

# zsh completion for netdoc(1). Installed as _netdoc on zsh's fpath.
#
# Hand-maintained: netdoc uses the stdlib flag package, which has no completion
# generator. Keep this in sync with the flags in main.go.

# Interface names only. -iface also takes a local IP address, which is not
# offered here: the useful ones are already on these links.
_netdoc_ifaces() {
  local -a ifaces
  ifaces=(/sys/class/net/*(N:t))
  (( $#ifaces )) && _describe -t interfaces 'interface' ifaces
}

# Stable probe IDs for -check and -skip. Both take a comma-separated list, so
# _values with a ',' separator completes each element and keeps the ones
# already typed. Kept in sync with StableProbes() by the packaging test.
_netdoc_probes() {
  _values -s , 'probe ID' iface internet_tcp quic_udp_443 proxy_connect dns dns_public dns_encrypted target_tcp path_mtu ssid tls http https ssh_banner smtp_banner
}

# Local snapshot files, for the flags whose positionals are .ndoc files rather
# than targets. `.ndoc` is offered as its own tag first because that is what
# these flags read, with every file behind it: netdoc does not require the
# extension, so a snapshot saved under another name must stay completable.
# Bash and Fish offer all files here, and this keeps the three in step.
_netdoc_snapshots() {
  _alternative \
    'snapshots:snapshot file:_files -g "*.ndoc"' \
    'files:file:_files'
}

# Positional arguments are normally targets -- hostnames, URLs and IP literals,
# none of them enumerable -- so completion offers nothing rather than local
# filenames. The exceptions are the two arguments of --compare, and of
# --two-sided when it is offline: those are local snapshots.
#
# `--two-sided --via` is the case worth stating, because it inverts: side B is
# then a live target, not a file, so file completion has to stay off. That is
# the same condition the Bash and Fish completions already carry. The value can
# be a separate word or joined with `=`, and both spellings mean the same run,
# so the pattern has to match `--via=host` as well as `--via host`.
_netdoc_wants_snapshots() {
  (( ${words[(I)(--compare|-compare)]} )) && return 0
  (( ${words[(I)(--two-sided|-two-sided)]} )) &&
    (( ! ${words[(I)(--via|-via)(|=*)]} )) && return 0
  return 1
}

# Which positional spec applies is decided here rather than inside a
# `*:target:` action, and that placement is the whole point. A rest-argument
# spec keeps consuming positionals, so when its action declines to add matches
# _arguments has nothing left to fall back to: `netdoc example.com <TAB>` then
# offers nothing at all, where it used to offer the flag list. Choosing the
# spec up front keeps the ordinary case exactly the single `:target:` it has
# always been, and the flags keep coming back.
local -a _netdoc_rest
if _netdoc_wants_snapshots; then
  _netdoc_rest=( '*:snapshot:_netdoc_snapshots' )
else
  _netdoc_rest=( ':target:' )
fi

# No -s: it would let single-letter options stack, and the single-dash long
# spellings below (-json) would be read as stacked letters.
# '=' after a value-taking option lets _arguments complete --flag=value as
# well as --flag value. Without it, only the separated form is offered.
_arguments \
  '(--toolbox -toolbox --json -json)'{--toolbox,-toolbox}'[start in toolbox mode]' \
  '(--json -json --toolbox -toolbox)'{--json,-json}'[run the checks headless and print a JSON report]' \
  '(--watch -watch)'{--watch,-watch}'[continuously re-run checks]' \
  '(--profile -profile)'{--profile,-profile}='[run a built-in service profile]:profile:(github ssh smtp web list)' \
  '(--save -save --support -support)'{--save,-save}='[write a diagnostic snapshot (.ndoc) to a file]:file:_files' \
  '(--support -support --save -save)'{--support,-support}='[write a sanitized support snapshot (.ndoc) to a file]:file:_files' \
  '(--compare -compare --two-sided -two-sided)'{--compare,-compare}'[compare two saved snapshots (.ndoc); runs no probes]' \
  '(--two-sided -two-sided --compare -compare)'{--two-sided,-two-sided}'[localize two saved snapshots, or local and --via live runs]' \
  '*'{--peer-listen,-peer-listen}='[listen for an authenticated peer on an exact IP\:port]:address:' \
  '(--peer-connect -peer-connect)'{--peer-connect,-peer-connect}'[read a temporary pairing string and run a two-ended diagnosis]' \
  '(--via -via)'{--via,-via}='[run remotely, or provide side B for live two-sided diagnosis]:destination:_hosts' \
  '(- *)'{--list-checks,-list-checks}'[list stable probe IDs and names, then exit]' \
  '*'{--check,-check}='[run stable probe IDs (comma-separated; repeatable)]:probe IDs:_netdoc_probes' \
  '*'{--skip,-skip}='[skip stable probe IDs (comma-separated; repeatable)]:probe IDs:_netdoc_probes' \
  '(--no-reference-egress -no-reference-egress)'{--no-reference-egress,-no-reference-egress}"[don't contact netdoc's own built-in reference services]" \
  '(--iface -iface)'{--iface,-iface}='[bind probes to an interface name or exact local IP]:interface:_netdoc_ifaces' \
  '(--public-dns -public-dns)'{--public-dns,-public-dns}='[second-opinion DNS resolver IP, empty to skip (default 8.8.8.8)]:ip address:' \
  '(--no-history -no-history)'{--no-history,-no-history}"[don't read or write the saved target history]" \
  '(--keys -keys)'{--keys,-keys}='[keybinding preset for the TUI (default: default)]:preset:(default vim)' \
  '(--timeout -timeout)'{--timeout,-timeout}='[per-check probe timeout (default 4s)]:duration:' \
  '(- *)'{--version,-version}'[print version and exit]' \
  '(- *)'{--help,-help,-h}'[print usage and exit]' \
  "${_netdoc_rest[@]}"
