
using namespace System.Management.Automation
using namespace System.Management.Automation.Language

Register-ArgumentCompleter -Native -CommandName 'tftp' -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commandElements = $commandAst.CommandElements
    $command = @(
        'tftp'
        for ($i = 1; $i -lt $commandElements.Count; $i++) {
            $element = $commandElements[$i]
            if ($element -isnot [StringConstantExpressionAst] -or
                $element.StringConstantType -ne [StringConstantType]::BareWord -or
                $element.Value.StartsWith('-') -or
                $element.Value -eq $wordToComplete) {
                break
        }
        $element.Value
    }) -join ';'

    $completions = @(switch ($command) {
        'tftp' {
            [CompletionResult]::new('-v', 'v', [CompletionResultType]::ParameterName, 'v')
            [CompletionResult]::new('--verbosity', 'verbosity', [CompletionResultType]::ParameterName, 'verbosity')
            [CompletionResult]::new('-h', 'h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', 'help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('-V', 'V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', 'version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('send', 'send', [CompletionResultType]::ParameterValue, 'send')
            [CompletionResult]::new('sync', 'sync', [CompletionResultType]::ParameterValue, 'sync')
            [CompletionResult]::new('receive', 'receive', [CompletionResultType]::ParameterValue, 'receive')
            [CompletionResult]::new('server', 'server', [CompletionResultType]::ParameterValue, 'server')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'tftp;send' {
            [CompletionResult]::new('-l', 'l', [CompletionResultType]::ParameterName, 'l')
            [CompletionResult]::new('--listen', 'listen', [CompletionResultType]::ParameterName, 'listen')
            [CompletionResult]::new('--request-timeout', 'request-timeout', [CompletionResultType]::ParameterName, 'Request time out in milliseconds')
            [CompletionResult]::new('--block-size', 'block-size', [CompletionResultType]::ParameterName, 'block-size')
            [CompletionResult]::new('--window-size', 'window-size', [CompletionResultType]::ParameterName, 'window-size')
            [CompletionResult]::new('--retry-timeout', 'retry-timeout', [CompletionResultType]::ParameterName, 'Resend packet after timeout in ms')
            [CompletionResult]::new('--max-file-size', 'max-file-size', [CompletionResultType]::ParameterName, 'Max file size to receive')
            [CompletionResult]::new('--encryption-level', 'encryption-level', [CompletionResultType]::ParameterName, 'Available values protocol, data, optional-data, optional-protocol, none')
            [CompletionResult]::new('--private-key', 'private-key', [CompletionResultType]::ParameterName, 'Base64 encoded private key to use: value or FILE')
            [CompletionResult]::new('--server-public-key', 'server-public-key', [CompletionResultType]::ParameterName, 'Base64 encoded remote server public key to use for encryption')
            [CompletionResult]::new('--known-hosts', 'known-hosts', [CompletionResultType]::ParameterName, 'Path to a known hosts file where server public key will be retrieved. Format: endpoint base64(public key) per line')
            [CompletionResult]::new('--encryption-key', 'encryption-key', [CompletionResultType]::ParameterName, 'Encrypt/decrypt file when sending/receiving. Key should be 32 chars long')
            [CompletionResult]::new('-r', 'r', [CompletionResultType]::ParameterName, 'r')
            [CompletionResult]::new('--remote-path', 'remote-path', [CompletionResultType]::ParameterName, 'remote-path')
            [CompletionResult]::new('--allow-server-port-change', 'allow-server-port-change', [CompletionResultType]::ParameterName, 'allow-server-port-change')
            [CompletionResult]::new('--prefer-seek', 'prefer-seek', [CompletionResultType]::ParameterName, 'prefer-seek')
            [CompletionResult]::new('-h', 'h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', 'help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'tftp;sync' {
            [CompletionResult]::new('-l', 'l', [CompletionResultType]::ParameterName, 'l')
            [CompletionResult]::new('--listen', 'listen', [CompletionResultType]::ParameterName, 'listen')
            [CompletionResult]::new('--request-timeout', 'request-timeout', [CompletionResultType]::ParameterName, 'Request time out in milliseconds')
            [CompletionResult]::new('--block-size', 'block-size', [CompletionResultType]::ParameterName, 'block-size')
            [CompletionResult]::new('--window-size', 'window-size', [CompletionResultType]::ParameterName, 'window-size')
            [CompletionResult]::new('--retry-timeout', 'retry-timeout', [CompletionResultType]::ParameterName, 'Resend packet after timeout in ms')
            [CompletionResult]::new('--max-file-size', 'max-file-size', [CompletionResultType]::ParameterName, 'Max file size to receive')
            [CompletionResult]::new('--encryption-level', 'encryption-level', [CompletionResultType]::ParameterName, 'Available values protocol, data, optional-data, optional-protocol, none')
            [CompletionResult]::new('--private-key', 'private-key', [CompletionResultType]::ParameterName, 'Base64 encoded private key to use: value or FILE')
            [CompletionResult]::new('--server-public-key', 'server-public-key', [CompletionResultType]::ParameterName, 'Base64 encoded remote server public key to use for encryption')
            [CompletionResult]::new('--known-hosts', 'known-hosts', [CompletionResultType]::ParameterName, 'Path to a known hosts file where server public key will be retrieved. Format: endpoint base64(public key) per line')
            [CompletionResult]::new('--encryption-key', 'encryption-key', [CompletionResultType]::ParameterName, 'Encrypt/decrypt file when sending/receiving. Key should be 32 chars long')
            [CompletionResult]::new('--block-duration', 'block-duration', [CompletionResultType]::ParameterName, 'How long to block before reading the file in milliseconds (only for --start-on-create)')
            [CompletionResult]::new('--allow-server-port-change', 'allow-server-port-change', [CompletionResultType]::ParameterName, 'allow-server-port-change')
            [CompletionResult]::new('--start-on-create', 'start-on-create', [CompletionResultType]::ParameterName, 'Start sending the file once its created. Default is to send once file is written')
            [CompletionResult]::new('-h', 'h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', 'help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'tftp;receive' {
            [CompletionResult]::new('-l', 'l', [CompletionResultType]::ParameterName, 'l')
            [CompletionResult]::new('--listen', 'listen', [CompletionResultType]::ParameterName, 'listen')
            [CompletionResult]::new('--request-timeout', 'request-timeout', [CompletionResultType]::ParameterName, 'Request time out in milliseconds')
            [CompletionResult]::new('--block-size', 'block-size', [CompletionResultType]::ParameterName, 'block-size')
            [CompletionResult]::new('--window-size', 'window-size', [CompletionResultType]::ParameterName, 'window-size')
            [CompletionResult]::new('--retry-timeout', 'retry-timeout', [CompletionResultType]::ParameterName, 'Resend packet after timeout in ms')
            [CompletionResult]::new('--max-file-size', 'max-file-size', [CompletionResultType]::ParameterName, 'Max file size to receive')
            [CompletionResult]::new('--encryption-level', 'encryption-level', [CompletionResultType]::ParameterName, 'Available values protocol, data, optional-data, optional-protocol, none')
            [CompletionResult]::new('--private-key', 'private-key', [CompletionResultType]::ParameterName, 'Base64 encoded private key to use: value or FILE')
            [CompletionResult]::new('--server-public-key', 'server-public-key', [CompletionResultType]::ParameterName, 'Base64 encoded remote server public key to use for encryption')
            [CompletionResult]::new('--known-hosts', 'known-hosts', [CompletionResultType]::ParameterName, 'Path to a known hosts file where server public key will be retrieved. Format: endpoint base64(public key) per line')
            [CompletionResult]::new('--encryption-key', 'encryption-key', [CompletionResultType]::ParameterName, 'Encrypt/decrypt file when sending/receiving. Key should be 32 chars long')
            [CompletionResult]::new('--local-path', 'local-path', [CompletionResultType]::ParameterName, 'local-path')
            [CompletionResult]::new('--allow-server-port-change', 'allow-server-port-change', [CompletionResultType]::ParameterName, 'allow-server-port-change')
            [CompletionResult]::new('-h', 'h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', 'help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'tftp;server' {
            [CompletionResult]::new('--max-connections', 'max-connections', [CompletionResultType]::ParameterName, 'max-connections')
            [CompletionResult]::new('--max-window-size', 'max-window-size', [CompletionResultType]::ParameterName, 'max-window-size')
            [CompletionResult]::new('--request-timeout', 'request-timeout', [CompletionResultType]::ParameterName, 'Request time out in milliseconds')
            [CompletionResult]::new('--max-file-size', 'max-file-size', [CompletionResultType]::ParameterName, 'Max file size to receive in bytes')
            [CompletionResult]::new('--max-block-size', 'max-block-size', [CompletionResultType]::ParameterName, 'max-block-size')
            [CompletionResult]::new('--authorized-keys', 'authorized-keys', [CompletionResultType]::ParameterName, 'Path to a file with authorized public keys. Each line contains base64(public key)')
            [CompletionResult]::new('--private-key', 'private-key', [CompletionResultType]::ParameterName, 'Base64 encoded private key to use: value or FILE')
            [CompletionResult]::new('--required-full-encryption', 'required-full-encryption', [CompletionResultType]::ParameterName, 'Require that connections be fully encrypted. This is enabled if authorized keys are provided')
            [CompletionResult]::new('--directory-list', 'directory-list', [CompletionResultType]::ParameterName, 'Retrieving specified file provides directory list')
            [CompletionResult]::new('--max-directory-depth', 'max-directory-depth', [CompletionResultType]::ParameterName, 'Maximum directory depth')
            [CompletionResult]::new('-a', 'a', [CompletionResultType]::ParameterName, 'a')
            [CompletionResult]::new('--allow-overwrite', 'allow-overwrite', [CompletionResultType]::ParameterName, 'allow-overwrite')
            [CompletionResult]::new('--require-server-port-change', 'require-server-port-change', [CompletionResultType]::ParameterName, 'require-server-port-change')
            [CompletionResult]::new('--prefer-seek', 'prefer-seek', [CompletionResultType]::ParameterName, 'prefer-seek')
            [CompletionResult]::new('-h', 'h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', 'help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'tftp;help' {
            [CompletionResult]::new('send', 'send', [CompletionResultType]::ParameterValue, 'send')
            [CompletionResult]::new('sync', 'sync', [CompletionResultType]::ParameterValue, 'sync')
            [CompletionResult]::new('receive', 'receive', [CompletionResultType]::ParameterValue, 'receive')
            [CompletionResult]::new('server', 'server', [CompletionResultType]::ParameterValue, 'server')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'tftp;help;send' {
            break
        }
        'tftp;help;sync' {
            break
        }
        'tftp;help;receive' {
            break
        }
        'tftp;help;server' {
            break
        }
        'tftp;help;help' {
            break
        }
    })

    $completions.Where{ $_.CompletionText -like "$wordToComplete*" } |
        Sort-Object -Property ListItemText
}
