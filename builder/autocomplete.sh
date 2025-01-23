#!/bin/bash

# complete remote directory name for receiver

# TODO currently this script relies on the endpoint directory being the last arguments

COMP_WORDBREAKS=" "

function list_remote_dirs() {
    local test_dir endpoint options
    if [[ "$1" == */ ]]; then
        test_dir="${1}dir"
    else
        test_dir="dir"
    fi

    endpoint="$2"
    # echo "t $test_dir e $endpoint o${3}" >> /tmp/a

    if [[ "$3" ]]; then
        tftp-dus --verbosity warn receive "$endpoint" "$test_dir" "${3}" --request-timeout 500 --local-path /dev/stdout 2> /dev/null
    else
        tftp-dus --verbosity warn receive "$endpoint" "$test_dir" --request-timeout 500 --local-path /dev/stdout 2> /dev/null
    fi
}

function _tftp_autocomplete() {
    local cur prev opts scope cmd
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="send sync receive server"
    # TODO handle verbosity
    scope="${COMP_WORDS[1]:-""}"
    cmd="${COMP_WORDS[0]:-""}"

    # echo "c $cur p $prev" >> /tmp/a

    if [[ "$scope" == "receive" ]] && [[ "$cur" != --* ]] && [[ "$prev" != --* ]] && [[ "$prev" != "$scope" ]] && [[ "$prev" ]]; then
        options=()
        for arg in "${COMP_WORDS[@]}"; do
            if [[ "$ignore" ]]; then
                ignore=""
                continue
            fi
            if [[ "$arg" == "$cmd" ]] || [[ "$arg" == "$scope" ]] || [[ "$arg" == "$cur" ]] || [[ "$arg" == "$prev" ]]; then
                continue
            fi
            if [[ "$arg" =~ ^--(request-timeout|local-path|verbosity)$ ]]; then
                ignore="yes"
                continue
            fi
            options+=("$arg")
        done
        opts=$(list_remote_dirs "$cur" "$prev" "${options[*]}" | tr '\n' ' ')
    elif [[ "$scope" =~ ^(receive|sync|send|server)$ ]]; then
        opts=$(tftp-dus "$scope" --help | grep -o -E '\--[a-z-]+')
    fi

    COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
    return 0

}
complete -F _tftp_autocomplete tftp
