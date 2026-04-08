rule MAL_PHP_Webshell_Advanced
{
    meta:
        description = "Detect advanced PHP webshell behavior"
        severity = "critical"

    strings:
        $eval = "eval(" nocase
        $assert = "assert(" nocase
        $exec = "exec(" nocase
        $system = "system(" nocase
        $passthru = "passthru(" nocase
        $shell_exec = "shell_exec(" nocase

        $b64 = "base64_decode" nocase
        $gz = "gzinflate" nocase
        $rot = "str_rot13" nocase

        $backtick = /`[^`]+`/
        $include = "include(" nocase
        $require = "require(" nocase
        $chr = "chr(" nocase

        $pcntl = "pcntl_exec" nocase
        $call_user_func = "call_user_func" nocase

        $concat = /"[^"]+"\s*\.\s*"[^"]+"/
        $var_func = /\$[a-zA-Z_]+\s*\(/

    condition:
        filesize < 1MB and
        (
            // decode + execute
            (1 of ($b64, $gz, $rot) and 
             1 of ($eval, $assert, $exec, $system, $passthru, $shell_exec, $pcntl, $call_user_func))

            or

            // obfuscation + execution
            (1 of ($concat, $chr, $backtick) and 
             1 of ($eval, $assert, $exec, $system, $passthru))

            or

            // dynamic execution (heuristic)
            ($var_func and filesize < 200KB)
        )
}
rule MAL_Reverse_Shell_Advanced
{
    meta:
        description = "Detect reverse shell patterns"
        author = "Sudip (improved)"
        date = "2026-04-08"
        severity = "critical"

    strings:
        $bash = "/bin/bash -i" nocase
        $nc = "nc -e" nocase
        $ncat = "ncat -e" nocase
        $perl = "perl -e" nocase
        $python = "python -c" nocase
        $php = "fsockopen" nocase
        $socket1 = /socket\(.+\)/ nocase
$       socket2 = "socket" nocase
        $connect = "connect(" nocase
        $dup = "dup2" nocase

    condition:
        (
            1 of ($bash, $nc, $ncat, $perl, $python, $php)
            or
            (1 of ($socket*) and 1 of ($connect, $dup))
            or
            (1 of ($socket*) and filesize < 200KB)
        )
}
rule MAL_Download_Execute_Advanced
{
    meta:
        description = "Detect download and execution via legit tools"
        author = "Sudip (improved)"
        date = "2026-04-08"
        severity = "critical"

    strings:
        $wget = "wget http" nocase
        $curl = "curl http" nocase
        $certutil = "certutil -urlcache" nocase
        $invoke = "Invoke-WebRequest" nocase
        $bitsadmin = "bitsadmin" nocase
        $python_dl = "urllib" nocase
        $devtcp = "/dev/tcp/" nocase
        $bash_exec = "bash -c" nocase

        $exec = "powershell" nocase
        $chmod = "chmod +x" nocase

    condition:
        (1 of ($wget, $curl, $certutil, $invoke, $bitsadmin, $python_dl, $devtcp, $php_dl)) and
        (1 of ($ps, $chmod, $bash_exec))
}
rule MAL_Command_Execution_Advanced
{
    meta:
        description = "OS command execution indicators"
        author = "Sudip (improved)"
        date = "2026-04-08"
        severity = "high"

    strings:
        $cmd = "cmd.exe" fullword nocase
        $sh = "/bin/sh" nocase
        $ps = "powershell" nocase
        $id = "id" nocase
        $uname = "uname" nocase
        $bash_exec = "bash -c" nocase
        $ls = "ls " nocase

        $whoami = "whoami" nocase
        $curl = "curl http" nocase
        $netuser = "net user" nocase

    condition:
        (1 of ($cmd, $sh, $ps, $bash_exec)) and 
        1 of ($whoami, $netuser, $id, $uname, $ls)
}
rule MAL_Encoded_Execution_Advanced
{
    meta:
        description = "Encoded payload with execution"
        author = "Sudip (improved)"
        date = "2026-04-08"
        severity = "high"

    strings:
        $b64_long = /[A-Za-z0-9+\/]{100,}={0,2}/
        $b64_short = /[A-Za-z0-9+\/]{50,}={0,2}/
        $multi_b64 = /([A-Za-z0-9+\/]{20,}={0,2}.*){3,}/

        $gz = "gzinflate" nocase
        $rot = "str_rot13" nocase
        $hex = "hex2bin" nocase

        $eval = "eval(" nocase
        $exec = "exec(" nocase
        $ps = "powershell -enc" nocase

    condition:
        ($b64_long or $b64_short or $multi_b64) and 
        1 of ($eval, $exec, $ps) and 
        1 of ($gz, $rot, $hex)
}
rule MAL_Destructive_Commands_Strong
{
    meta:
        description = "Detect destructive command patterns"
        severity = "critical"

    strings:
        $rm = "rm -rf /" nocase
        $dd = "dd if=" nocase
        $mkfs = "mkfs." nocase

    condition:
        2 of them
}
rule MAL_PDF_Exploit_Advanced
{
    meta:
        description = "Detects malicious PDF with JS, auto execution, or embedded payload"
        author = "Sudip (refined)"
        date = "2026-04-08"
        severity = "critical"

    strings:
        // JavaScript indicators
        $js1 = "/JavaScript" nocase
        $js2 = "/JS" nocase

        // Execution triggers
        $open = "/OpenAction" nocase
        $aa = "/AA" nocase
        $launch = "/Launch" nocase

        // Embedded payloads
        $embed = "/EmbeddedFile" nocase
        $filespec = "/Filespec" nocase

        // Suspicious function usage
        $eval = "eval(" nocase

        // Obfuscation / encoding
        $filter = "/FlateDecode" nocase
        $stream = "stream"
        $endstream = "endstream"

    condition:
        // Ensure it's a PDF
        uint32(0) == 0x25504446 and

        // Require COMBINATION of suspicious behaviors
        (
            // JS + execution trigger
            (1 of ($js*) and 1 of ($open, $aa, $launch)) or

            // Embedded file + execution
            (1 of ($embed, $filespec) and 1 of ($open, $launch)) or

            // Obfuscation + suspicious behavior
            ($filter and $stream and $endstream and (1 of ($js*) or $eval))
        )
}
rule Embedded_PE_File_Strong
{
    meta:
        description = "Detect embedded PE executable"
        severity = "high"

    strings:
        $mz = { 4D 5A }

    condition:
        $mz at 0 or $mz in (0..50000)
}
rule MAL_Generic_Obfuscation_Behavior
{
    meta:
        description = "Detect obfuscation and hidden execution"
        severity = "critical"

    strings:
        $chr = "chr(" nocase
        $concat = /"[^"]+"\s*\.\s*"[^"]+"/
        $var_func = /\$[a-zA-Z_]+\s*\(/
        $backtick = /`[^`]+`/
        $b64_chunks = /([A-Za-z0-9+\/]{20,}={0,2}.*){3,}/
        $pack = "pack(" nocase
        $gzun = "gzuncompress" nocase

        $eval = "eval(" nocase
        $exec = "exec(" nocase
        $system = "system(" nocase
        $assert = "assert(" nocase
        $call = "call_user_func" nocase

    condition:
        2 of ($chr, $concat, $var_func, $backtick, $b64_chunks, $pack, $gzun) and
        1 of ($eval, $exec, $system, $assert, $call)
}