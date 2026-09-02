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

# No -s: it would let single-letter options stack, and the single-dash long
# spellings below (-json) would be read as stacked letters.
# Targets are hostnames, URLs, and IP literals, none of them enumerable, so
# the positional completes to nothing rather than to local filenames. That
# holds for the two snapshot files of --compare and offline --two-sided too:
# one positional spec cannot be a target here and a filename there, and
# offering files for every target is the worse of the two mistakes.
_arguments \
  '(--toolbox -toolbox --json -json)'{--toolbox,-toolbox}'[start in toolbox mode]' \
  '(--json -json --toolbox -toolbox)'{--json,-json}'[run the checks headless and print a JSON report]' \
  '(--watch -watch)'{--watch,-watch}'[continuously re-run checks]' \
  '(--profile -profile)'{--profile,-profile}'[run a built-in service profile]:profile:(github ssh smtp web list)' \
  '(--save -save --support -support)'{--save,-save}'[write a diagnostic snapshot (.ndoc) to a file]:file:_files' \
  '(--support -support --save -save)'{--support,-support}'[write a sanitized support snapshot (.ndoc) to a file]:file:_files' \
  '(--compare -compare --two-sided -two-sided)'{--compare,-compare}'[compare two saved snapshots (.ndoc); runs no probes]' \
  '(--two-sided -two-sided --compare -compare)'{--two-sided,-two-sided}'[localize two saved snapshots, or local and --via live runs]' \
  '*'{--peer-listen,-peer-listen}'[listen for an authenticated peer on an exact IP\:port]:address:' \
  '(--peer-connect -peer-connect)'{--peer-connect,-peer-connect}'[read a temporary pairing string and run a two-ended diagnosis]' \
  '(--via -via)'{--via,-via}'[run remotely, or provide side B for live two-sided diagnosis]:destination:_hosts' \
  '(- *)'{--list-checks,-list-checks}'[list stable probe IDs and names, then exit]' \
  '*'{--check,-check}'[run stable probe IDs (comma-separated; repeatable)]:probe IDs:' \
  '*'{--skip,-skip}'[skip stable probe IDs (comma-separated; repeatable)]:probe IDs:' \
  '(--no-reference-egress -no-reference-egress)'{--no-reference-egress,-no-reference-egress}"[don't contact netdoc's own built-in reference services]" \
  '(--iface -iface)'{--iface,-iface}'[bind probes to an interface name or exact local IP]:interface:_netdoc_ifaces' \
  '(--public-dns -public-dns)'{--public-dns,-public-dns}'[second-opinion DNS resolver IP, empty to skip (default 8.8.8.8)]:ip address:' \
  '(--no-history -no-history)'{--no-history,-no-history}"[don't read or write the saved target history]" \
  '(--keys -keys)'{--keys,-keys}'[keybinding preset for the TUI (default: default)]:preset:(default vim)' \
  '(--timeout -timeout)'{--timeout,-timeout}'[per-check probe timeout (default 4s)]:duration:' \
  '(- *)'{--version,-version}'[print version and exit]' \
  '(- *)'{--help,-help,-h}'[print usage and exit]' \
  ':target:'
