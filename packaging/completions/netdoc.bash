# bash completion for netdoc(1)
#
# Hand-maintained: netdoc uses the stdlib flag package, which has no completion
# generator. Keep this in sync with the flags in main.go.

_netdoc() {
    local cur prev
    cur=${COMP_WORDS[COMP_CWORD]}
    prev=${COMP_WORDS[COMP_CWORD-1]}

    case $prev in
        -iface | --iface)
            # Interface names only. -iface also takes a local IP address, which
            # is not offered here: the useful ones are already on these links.
            COMPREPLY=($(compgen -W "$(command ls /sys/class/net 2>/dev/null)" -- "$cur"))
            return
            ;;
        -timeout | --timeout | -check | --check | -skip | --skip | -peer-listen | --peer-listen)
            # These values have nothing useful to enumerate.
            return
            ;;
        -keys | --keys)
            COMPREPLY=($(compgen -W "default vim" -- "$cur"))
            return
            ;;
        -profile | --profile)
            COMPREPLY=($(compgen -W "github ssh smtp web list" -- "$cur"))
            return
            ;;
        -save | --save | -support | --support)
            # A path to write the snapshot to, so these values really are
            # local filenames.
            COMPREPLY=($(compgen -f -- "$cur"))
            return
            ;;
        -via | --via)
            # An SSH destination, so the same names ssh itself would take:
            # ~/.ssh/config aliases and known hosts, which bash enumerates.
            COMPREPLY=($(compgen -A hostname -- "$cur"))
            return
            ;;
        -public-dns | --public-dns)
            # An IP address, or the empty string to skip the check. Neither is
            # enumerable, so offer nothing rather than local filenames.
            return
            ;;
    esac

    # Targets are hostnames, URLs, and IP literals, none of them enumerable, so
    # a non-flag word completes to nothing rather than to local filenames. The
    # exceptions are --compare and offline --two-sided, whose two arguments
    # are local snapshot files. With --via, two-sided takes a target instead.
    if [[ $cur != -* ]]; then
        if [[ " ${COMP_WORDS[*]} " == *" -compare "* || " ${COMP_WORDS[*]} " == *" --compare "* ]]; then
            COMPREPLY=($(compgen -f -- "$cur"))
        elif [[ ( " ${COMP_WORDS[*]} " == *" -two-sided "* || " ${COMP_WORDS[*]} " == *" --two-sided "* ) &&
                " ${COMP_WORDS[*]} " != *" -via "* && " ${COMP_WORDS[*]} " != *" --via "* ]]; then
            COMPREPLY=($(compgen -f -- "$cur"))
        fi
        return
    fi

    COMPREPLY=($(compgen -W "
        -toolbox --toolbox
        -json --json
        -watch --watch
        -profile --profile
        -save --save
        -support --support
        -compare --compare
        -two-sided --two-sided
        -peer-listen --peer-listen
        -peer-connect --peer-connect
        -via --via
        -list-checks --list-checks
        -check --check
        -skip --skip
        -no-reference-egress --no-reference-egress
        -iface --iface
        -public-dns --public-dns
        -no-history --no-history
        -keys --keys
        -timeout --timeout
        -version --version
        -h -help --help
    " -- "$cur"))
}

complete -F _netdoc netdoc
