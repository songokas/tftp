
use builtin;
use str;

set edit:completion:arg-completer[tftp] = {|@words|
    fn spaces {|n|
        builtin:repeat $n ' ' | str:join ''
    }
    fn cand {|text desc|
        edit:complex-candidate $text &display=$text' '(spaces (- 14 (wcswidth $text)))$desc
    }
    var command = 'tftp'
    for word $words[1..-1] {
        if (str:has-prefix $word '-') {
            break
        }
        set command = $command';'$word
    }
    var completions = [
        &'tftp'= {
            cand -v 'v'
            cand --verbosity 'verbosity'
            cand -h 'Print help'
            cand --help 'Print help'
            cand -V 'Print version'
            cand --version 'Print version'
            cand send 'send'
            cand sync 'sync'
            cand receive 'receive'
            cand server 'server'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'tftp;send'= {
            cand -l 'l'
            cand --listen 'listen'
            cand --request-timeout 'Request time out in milliseconds'
            cand --block-size 'block-size'
            cand --window-size 'window-size'
            cand --retry-timeout 'Resend packet after timeout in ms'
            cand --max-file-size 'Max file size to receive'
            cand --encryption-level 'Available values protocol, data, optional-data, optional-protocol, none'
            cand --private-key 'Base64 encoded private key to use: value or FILE'
            cand --server-public-key 'Base64 encoded remote server public key to use for encryption'
            cand --known-hosts 'Path to a known hosts file where server public key will be retrieved. Format: endpoint base64(public key) per line'
            cand --encryption-key 'Encrypt/decrypt file when sending/receiving. Key should be 32 chars long'
            cand -r 'r'
            cand --remote-path 'remote-path'
            cand --allow-server-port-change 'allow-server-port-change'
            cand --prefer-seek 'prefer-seek'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'tftp;sync'= {
            cand -l 'l'
            cand --listen 'listen'
            cand --request-timeout 'Request time out in milliseconds'
            cand --block-size 'block-size'
            cand --window-size 'window-size'
            cand --retry-timeout 'Resend packet after timeout in ms'
            cand --max-file-size 'Max file size to receive'
            cand --encryption-level 'Available values protocol, data, optional-data, optional-protocol, none'
            cand --private-key 'Base64 encoded private key to use: value or FILE'
            cand --server-public-key 'Base64 encoded remote server public key to use for encryption'
            cand --known-hosts 'Path to a known hosts file where server public key will be retrieved. Format: endpoint base64(public key) per line'
            cand --encryption-key 'Encrypt/decrypt file when sending/receiving. Key should be 32 chars long'
            cand --block-duration 'How long to block before reading the file in milliseconds (only for --start-on-create)'
            cand --allow-server-port-change 'allow-server-port-change'
            cand --start-on-create 'Start sending the file once its created. Default is to send once file is written'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'tftp;receive'= {
            cand -l 'l'
            cand --listen 'listen'
            cand --request-timeout 'Request time out in milliseconds'
            cand --block-size 'block-size'
            cand --window-size 'window-size'
            cand --retry-timeout 'Resend packet after timeout in ms'
            cand --max-file-size 'Max file size to receive'
            cand --encryption-level 'Available values protocol, data, optional-data, optional-protocol, none'
            cand --private-key 'Base64 encoded private key to use: value or FILE'
            cand --server-public-key 'Base64 encoded remote server public key to use for encryption'
            cand --known-hosts 'Path to a known hosts file where server public key will be retrieved. Format: endpoint base64(public key) per line'
            cand --encryption-key 'Encrypt/decrypt file when sending/receiving. Key should be 32 chars long'
            cand --local-path 'local-path'
            cand --allow-server-port-change 'allow-server-port-change'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'tftp;server'= {
            cand --max-connections 'max-connections'
            cand --max-window-size 'max-window-size'
            cand --request-timeout 'Request time out in milliseconds'
            cand --max-file-size 'Max file size to receive in bytes'
            cand --max-block-size 'max-block-size'
            cand --authorized-keys 'Path to a file with authorized public keys. Each line contains base64(public key)'
            cand --private-key 'Base64 encoded private key to use: value or FILE'
            cand --require-full-encryption 'Require that connections be fully encrypted. This is enabled if authorized keys are provided'
            cand --directory-list 'Retrieving specified file provides directory list'
            cand --max-directory-depth 'Maximum directory depth'
            cand -a 'a'
            cand --allow-overwrite 'allow-overwrite'
            cand --require-server-port-change 'require-server-port-change'
            cand --prefer-seek 'prefer-seek'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'tftp;help'= {
            cand send 'send'
            cand sync 'sync'
            cand receive 'receive'
            cand server 'server'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'tftp;help;send'= {
        }
        &'tftp;help;sync'= {
        }
        &'tftp;help;receive'= {
        }
        &'tftp;help;server'= {
        }
        &'tftp;help;help'= {
        }
    ]
    $completions[$command]
}
