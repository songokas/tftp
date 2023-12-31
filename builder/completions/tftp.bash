_tftp() {
    local i cur prev opts cmd
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    cmd=""
    opts=""

    for i in ${COMP_WORDS[@]}
    do
        case "${cmd},${i}" in
            ",$1")
                cmd="tftp"
                ;;
            tftp,help)
                cmd="tftp__help"
                ;;
            tftp,receive)
                cmd="tftp__receive"
                ;;
            tftp,send)
                cmd="tftp__send"
                ;;
            tftp,server)
                cmd="tftp__server"
                ;;
            tftp,sync)
                cmd="tftp__sync"
                ;;
            tftp__help,help)
                cmd="tftp__help__help"
                ;;
            tftp__help,receive)
                cmd="tftp__help__receive"
                ;;
            tftp__help,send)
                cmd="tftp__help__send"
                ;;
            tftp__help,server)
                cmd="tftp__help__server"
                ;;
            tftp__help,sync)
                cmd="tftp__help__sync"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        tftp)
            opts="-v -h -V --verbosity --help --version send sync receive server help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --verbosity)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -v)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        tftp__help)
            opts="send sync receive server help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        tftp__help__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        tftp__help__receive)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        tftp__help__send)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        tftp__help__server)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        tftp__help__sync)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        tftp__receive)
            opts="-l -h --listen --request-timeout --block-size --window-size --retry-timeout --max-file-size --encryption-level --private-key --server-public-key --known-hosts --allow-server-port-change --encryption-key --local-path --help <ENDPOINT> <FILE>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --listen)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -l)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --request-timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --block-size)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --window-size)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --retry-timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-file-size)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --encryption-level)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --private-key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --server-public-key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-hosts)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --encryption-key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --local-path)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        tftp__send)
            opts="-l -r -h --listen --request-timeout --block-size --window-size --retry-timeout --max-file-size --encryption-level --private-key --server-public-key --known-hosts --allow-server-port-change --encryption-key --remote-path --prefer-seek --help <ENDPOINT> <FILE>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --listen)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -l)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --request-timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --block-size)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --window-size)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --retry-timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-file-size)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --encryption-level)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --private-key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --server-public-key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-hosts)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --encryption-key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --remote-path)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -r)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        tftp__server)
            opts="-a -h --allow-overwrite --max-connections --max-window-size --request-timeout --max-file-size --max-block-size --authorized-keys --private-key --required-full-encryption --require-server-port-change --prefer-seek --directory-list --max-directory-depth --help <LISTEN> <DIRECTORY>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --max-connections)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-window-size)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --request-timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-file-size)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-block-size)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --authorized-keys)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --private-key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --required-full-encryption)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --directory-list)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-directory-depth)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        tftp__sync)
            opts="-l -h --listen --request-timeout --block-size --window-size --retry-timeout --max-file-size --encryption-level --private-key --server-public-key --known-hosts --allow-server-port-change --encryption-key --start-on-create --block-duration --help <ENDPOINT> [DIRECTORY]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --listen)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -l)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --request-timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --block-size)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --window-size)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --retry-timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-file-size)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --encryption-level)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --private-key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --server-public-key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-hosts)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --encryption-key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --block-duration)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

complete -F _tftp -o nosort -o bashdefault -o default tftp
