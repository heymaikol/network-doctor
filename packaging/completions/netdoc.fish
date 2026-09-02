# fish completion for netdoc(1)
#
# Hand-maintained: netdoc uses the stdlib flag package, which has no completion
# generator. Keep this in sync with the flags in main.go.

# Targets are hostnames, URLs, and IP literals, none of them enumerable, so
# suppress the file completion fish would otherwise offer.
complete -c netdoc -f

# The stdlib flag package accepts both spellings of every flag, so each one is
# declared as a short option (-json) and a long option (--json).
complete -c netdoc -o toolbox -l toolbox -d 'Start in toolbox mode'
complete -c netdoc -o json -l json -d 'Run the checks headless and print a JSON report'
complete -c netdoc -o watch -l watch -d 'Continuously re-run checks'
complete -c netdoc -o profile -l profile -r -f -d 'Run a built-in service profile' \
    -a 'github ssh smtp web list'
# -F re-enables the file completion the -f above suppressed: this one value is
# paths to write, not targets.
complete -c netdoc -o save -l save -r -F -d 'Write a diagnostic snapshot (.ndoc) to a file'
complete -c netdoc -o support -l support -r -F -d 'Write a sanitized support snapshot (.ndoc) to a file'
complete -c netdoc -o compare -l compare -d 'Compare two saved snapshots (.ndoc); runs no probes'
complete -c netdoc -o two-sided -l two-sided -d 'Localize two saved snapshots, or local and --via live runs'
# The two arguments of --compare and offline --two-sided are local files, so
# file completion comes back only while --via is absent.
complete -c netdoc -n '__fish_seen_argument -o compare -l compare' -F
complete -c netdoc -n '__fish_seen_argument -o two-sided -l two-sided; and not __fish_seen_argument -o via -l via' -F
complete -c netdoc -o peer-listen -l peer-listen -r -d 'Listen for an authenticated peer on an exact IP:port (repeatable)'
complete -c netdoc -o peer-connect -l peer-connect -d 'Read a temporary pairing string and run a two-ended diagnosis'
complete -c netdoc -o via -l via -r -f \
    -a '(__fish_print_hostnames)' \
    -d 'Run remotely, or provide side B for live two-sided diagnosis'
complete -c netdoc -o list-checks -l list-checks -d 'List stable probe IDs and names, then exit'
complete -c netdoc -o check -l check -r -d 'Run stable probe IDs (comma-separated; repeatable)'
complete -c netdoc -o skip -l skip -r -d 'Skip stable probe IDs (comma-separated; repeatable)'
complete -c netdoc -o no-reference-egress -l no-reference-egress -d "Don't contact netdoc's own built-in reference services"
complete -c netdoc -o no-history -l no-history -d "Don't read or write the saved target history"
complete -c netdoc -o version -l version -d 'Print version and exit'
complete -c netdoc -s h -o help -l help -d 'Print usage and exit'

complete -c netdoc -o iface -l iface -r -d 'Bind probes to an interface name or exact local IP' \
    -a '(command ls /sys/class/net 2>/dev/null)'
complete -c netdoc -o public-dns -l public-dns -r -d 'Second-opinion DNS resolver IP, empty to skip (default 8.8.8.8)'
complete -c netdoc -o keys -l keys -r -d 'Keybinding preset for the TUI (default: default)' \
    -a 'default vim'
complete -c netdoc -o timeout -l timeout -r -d 'Per-check probe timeout (default 4s)'
