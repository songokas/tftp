complete -c tftp -n "__fish_use_subcommand" -s v -l verbosity -r
complete -c tftp -n "__fish_use_subcommand" -s h -l help -d 'Print help'
complete -c tftp -n "__fish_use_subcommand" -s V -l version -d 'Print version'
complete -c tftp -n "__fish_use_subcommand" -f -a "send"
complete -c tftp -n "__fish_use_subcommand" -f -a "sync"
complete -c tftp -n "__fish_use_subcommand" -f -a "receive"
complete -c tftp -n "__fish_use_subcommand" -f -a "server"
complete -c tftp -n "__fish_use_subcommand" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c tftp -n "__fish_seen_subcommand_from send" -s l -l listen -r -f -a "(__fish_print_hostnames)"
complete -c tftp -n "__fish_seen_subcommand_from send" -l request-timeout -d 'Request time out in milliseconds' -r
complete -c tftp -n "__fish_seen_subcommand_from send" -l block-size -r
complete -c tftp -n "__fish_seen_subcommand_from send" -l window-size -r
complete -c tftp -n "__fish_seen_subcommand_from send" -l retry-timeout -d 'Resend packet after timeout in ms' -r
complete -c tftp -n "__fish_seen_subcommand_from send" -l max-file-size -d 'Max file size to receive' -r
complete -c tftp -n "__fish_seen_subcommand_from send" -l encryption-level -d 'Available values protocol, data, optional-data, optional-protocol, none' -r
complete -c tftp -n "__fish_seen_subcommand_from send" -l private-key -d 'Base64 encoded private key to use: value or FILE' -r
complete -c tftp -n "__fish_seen_subcommand_from send" -l server-public-key -d 'Base64 encoded remote server public key to use for encryption' -r
complete -c tftp -n "__fish_seen_subcommand_from send" -l known-hosts -d 'Path to a known hosts file where server public key will be retrieved. Format: endpoint base64(public key) per line' -r -F
complete -c tftp -n "__fish_seen_subcommand_from send" -l encryption-key -d 'Encrypt/decrypt file when sending/receiving. Key should be 32 chars long' -r
complete -c tftp -n "__fish_seen_subcommand_from send" -s r -l remote-path -r
complete -c tftp -n "__fish_seen_subcommand_from send" -l allow-server-port-change
complete -c tftp -n "__fish_seen_subcommand_from send" -l prefer-seek
complete -c tftp -n "__fish_seen_subcommand_from send" -s h -l help -d 'Print help'
complete -c tftp -n "__fish_seen_subcommand_from sync" -s l -l listen -r -f -a "(__fish_print_hostnames)"
complete -c tftp -n "__fish_seen_subcommand_from sync" -l request-timeout -d 'Request time out in milliseconds' -r
complete -c tftp -n "__fish_seen_subcommand_from sync" -l block-size -r
complete -c tftp -n "__fish_seen_subcommand_from sync" -l window-size -r
complete -c tftp -n "__fish_seen_subcommand_from sync" -l retry-timeout -d 'Resend packet after timeout in ms' -r
complete -c tftp -n "__fish_seen_subcommand_from sync" -l max-file-size -d 'Max file size to receive' -r
complete -c tftp -n "__fish_seen_subcommand_from sync" -l encryption-level -d 'Available values protocol, data, optional-data, optional-protocol, none' -r
complete -c tftp -n "__fish_seen_subcommand_from sync" -l private-key -d 'Base64 encoded private key to use: value or FILE' -r
complete -c tftp -n "__fish_seen_subcommand_from sync" -l server-public-key -d 'Base64 encoded remote server public key to use for encryption' -r
complete -c tftp -n "__fish_seen_subcommand_from sync" -l known-hosts -d 'Path to a known hosts file where server public key will be retrieved. Format: endpoint base64(public key) per line' -r -F
complete -c tftp -n "__fish_seen_subcommand_from sync" -l encryption-key -d 'Encrypt/decrypt file when sending/receiving. Key should be 32 chars long' -r
complete -c tftp -n "__fish_seen_subcommand_from sync" -l block-duration -d 'How long to block before reading the file in milliseconds (only for --start-on-create)' -r
complete -c tftp -n "__fish_seen_subcommand_from sync" -l allow-server-port-change
complete -c tftp -n "__fish_seen_subcommand_from sync" -l start-on-create -d 'Start sending the file once its created. Default is to send once file is written'
complete -c tftp -n "__fish_seen_subcommand_from sync" -s h -l help -d 'Print help'
complete -c tftp -n "__fish_seen_subcommand_from receive" -s l -l listen -r -f -a "(__fish_print_hostnames)"
complete -c tftp -n "__fish_seen_subcommand_from receive" -l request-timeout -d 'Request time out in milliseconds' -r
complete -c tftp -n "__fish_seen_subcommand_from receive" -l block-size -r
complete -c tftp -n "__fish_seen_subcommand_from receive" -l window-size -r
complete -c tftp -n "__fish_seen_subcommand_from receive" -l retry-timeout -d 'Resend packet after timeout in ms' -r
complete -c tftp -n "__fish_seen_subcommand_from receive" -l max-file-size -d 'Max file size to receive' -r
complete -c tftp -n "__fish_seen_subcommand_from receive" -l encryption-level -d 'Available values protocol, data, optional-data, optional-protocol, none' -r
complete -c tftp -n "__fish_seen_subcommand_from receive" -l private-key -d 'Base64 encoded private key to use: value or FILE' -r
complete -c tftp -n "__fish_seen_subcommand_from receive" -l server-public-key -d 'Base64 encoded remote server public key to use for encryption' -r
complete -c tftp -n "__fish_seen_subcommand_from receive" -l known-hosts -d 'Path to a known hosts file where server public key will be retrieved. Format: endpoint base64(public key) per line' -r -F
complete -c tftp -n "__fish_seen_subcommand_from receive" -l encryption-key -d 'Encrypt/decrypt file when sending/receiving. Key should be 32 chars long' -r
complete -c tftp -n "__fish_seen_subcommand_from receive" -l local-path -r -F
complete -c tftp -n "__fish_seen_subcommand_from receive" -l allow-server-port-change
complete -c tftp -n "__fish_seen_subcommand_from receive" -s h -l help -d 'Print help'
complete -c tftp -n "__fish_seen_subcommand_from server" -l max-connections -r
complete -c tftp -n "__fish_seen_subcommand_from server" -l max-window-size -r
complete -c tftp -n "__fish_seen_subcommand_from server" -l request-timeout -d 'Request time out in milliseconds' -r
complete -c tftp -n "__fish_seen_subcommand_from server" -l max-file-size -d 'Max file size to receive in bytes' -r
complete -c tftp -n "__fish_seen_subcommand_from server" -l max-block-size -r
complete -c tftp -n "__fish_seen_subcommand_from server" -l authorized-keys -d 'Path to a file with authorized public keys. Each line contains base64(public key)' -r -F
complete -c tftp -n "__fish_seen_subcommand_from server" -l private-key -d 'Base64 encoded private key to use: value or FILE' -r
complete -c tftp -n "__fish_seen_subcommand_from server" -l required-full-encryption -d 'Require that connections be fully encrypted. This is enabled if authorized keys are provided' -r -f -a "{true	'',false	''}"
complete -c tftp -n "__fish_seen_subcommand_from server" -l directory-list -d 'Retrieving specified file provides directory list' -r
complete -c tftp -n "__fish_seen_subcommand_from server" -l max-directory-depth -d 'Maximum directory depth' -r
complete -c tftp -n "__fish_seen_subcommand_from server" -s a -l allow-overwrite
complete -c tftp -n "__fish_seen_subcommand_from server" -l require-server-port-change
complete -c tftp -n "__fish_seen_subcommand_from server" -l prefer-seek
complete -c tftp -n "__fish_seen_subcommand_from server" -s h -l help -d 'Print help'
complete -c tftp -n "__fish_seen_subcommand_from help; and not __fish_seen_subcommand_from send; and not __fish_seen_subcommand_from sync; and not __fish_seen_subcommand_from receive; and not __fish_seen_subcommand_from server; and not __fish_seen_subcommand_from help" -f -a "send"
complete -c tftp -n "__fish_seen_subcommand_from help; and not __fish_seen_subcommand_from send; and not __fish_seen_subcommand_from sync; and not __fish_seen_subcommand_from receive; and not __fish_seen_subcommand_from server; and not __fish_seen_subcommand_from help" -f -a "sync"
complete -c tftp -n "__fish_seen_subcommand_from help; and not __fish_seen_subcommand_from send; and not __fish_seen_subcommand_from sync; and not __fish_seen_subcommand_from receive; and not __fish_seen_subcommand_from server; and not __fish_seen_subcommand_from help" -f -a "receive"
complete -c tftp -n "__fish_seen_subcommand_from help; and not __fish_seen_subcommand_from send; and not __fish_seen_subcommand_from sync; and not __fish_seen_subcommand_from receive; and not __fish_seen_subcommand_from server; and not __fish_seen_subcommand_from help" -f -a "server"
complete -c tftp -n "__fish_seen_subcommand_from help; and not __fish_seen_subcommand_from send; and not __fish_seen_subcommand_from sync; and not __fish_seen_subcommand_from receive; and not __fish_seen_subcommand_from server; and not __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
