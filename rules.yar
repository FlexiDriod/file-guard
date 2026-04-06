rule Suspicious_Scripting_Behavior
{
    meta:
        description = "Detect suspicious scripting functions"
        severity = "medium"
        category = "script_abuse"

    strings:
        $eval = "eval(" nocase
        $exec = "exec(" nocase
        $system = "system(" nocase
        $shell_exec = "shell_exec(" nocase
        $popen = "popen(" nocase

    condition:
        2 of them
}
rule Reverse_Shell_Patterns
{
    meta:
        description = "Detect common reverse shell patterns"
        severity = "critical"
        category = "remote_access"

    strings:
        $bash_rev = /bash\s+-i\s+>&\s+\/dev\/tcp\/\d{1,3}(\.\d{1,3}){3}\/\d+/ nocase
        $nc_rev = /nc\s+-e\s+\/bin\/(bash|sh)/ nocase
        $python_rev = /socket\.connect\(\("(\d{1,3}\.){3}\d{1,3}",\s*\d+\)\)/ nocase

    condition:
        any of them
}
rule Suspicious_Download_Execution
{
    meta:
        description = "Detect download and execute patterns"
        severity = "high"
        category = "command_execution"

    strings:
        $wget_exec = /wget\s+http.*\|\s*(bash|sh)/ nocase
        $curl_exec = /curl\s+http.*\|\s*(bash|sh)/ nocase
        $powershell_dl = /powershell.*DownloadString/ nocase

    condition:
        any of them
}
rule Encoded_Payloads
{
    meta:
        description = "Detect encoded payloads (base64, obfuscation)"
        severity = "medium"
        category = "obfuscation"

    strings:
        $b64_keyword = "base64_decode" nocase
        $long_b64 = /[A-Za-z0-9+\/]{120,}={0,2}/
        $hex_blob = /\\x[0-9a-fA-F]{2}{20,}/

    condition:
        any of them
}
rule Executable_Disguised_File
{
    meta:
        description = "Detect executable headers"
        severity = "high"
        category = "binary"

    strings:
        $mz = { 4D 5A }   // Windows EXE

    condition:
        $mz at 0
}
rule Dangerous_System_Commands
{
    meta:
        description = "Detect destructive commands"
        severity = "high"
        category = "system_attack"

    strings:
        $rm = "rm -rf /" nocase
        $dd = "dd if=" nocase
        $mkfs = "mkfs." nocase

    condition:
        any of them
}
rule PDF_Suspicious_JavaScript
{
    meta:
        description = "Detect JavaScript inside PDF"
        severity = "high"
        category = "pdf_exploit"

    strings:
        $js1 = "/JavaScript" nocase
        $js2 = "/JS" nocase
        $eval = "eval(" nocase

    condition:
        any of them
}
rule PDF_Auto_Execution
{
    meta:
        description = "Detect auto-execution in PDF"
        severity = "critical"
        category = "pdf_exploit"

    strings:
        $open = "/OpenAction" nocase
        $aa = "/AA" nocase

    condition:
        any of them
}
rule PDF_Embedded_File
{
    meta:
        description = "Detect embedded files in PDF"
        severity = "high"
        category = "pdf_exploit"

    strings:
        $embed = "/EmbeddedFile" nocase
        $filespec = "/Filespec" nocase

    condition:
        any of them
}
rule PDF_Launch_Action
{
    meta:
        description = "Detect launch command in PDF"
        severity = "critical"
        category = "pdf_exploit"

    strings:
        $launch = "/Launch" nocase

    condition:
        $launch
}
rule PDF_Obfuscation_Stream
{
    meta:
        description = "Detect suspicious encoded streams"
        severity = "medium"
        category = "pdf_exploit"

    strings:
        $stream = "stream"
        $endstream = "endstream"
        $filter = "/FlateDecode"

    condition:
        $stream and $endstream and $filter
}
rule Suspicious_Image_Content
{
    meta:
        description = "Detect suspicious content inside image files"
        severity = "medium"
        category = "image_exploit"

    strings:
        $exe = "MZ"
        $script = "<script"
        $php = "<?php"
        $bash = "/bin/bash"

    condition:
        any of them
}
rule Suspicious_Video_Content
{
    meta:
        description = "Detect suspicious patterns inside video files"
        severity = "medium"
        category = "video_exploit"

    strings:
        $exe = "MZ"
        $cmd = "cmd.exe"
        $ps = "powershell"

    condition:
        any of them
}
rule Embedded_Executable_Inside_File
{
    meta:
        description = "Detect embedded executable in any file"
        severity = "high"
        category = "file_injection"

    strings:
        $mz = { 4D 5A }

    condition:
        $mz at 0 or $mz in (0..5000)
}
rule Possible_Steganography
{
    meta:
        description = "Detect unusually large embedded data"
        severity = "low"
        category = "steganography"

    strings:
        $long_data = /[A-Za-z0-9+\/]{200,}/

    condition:
        $long_data
}