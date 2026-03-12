// Destructive commands -- block shell commands that destroy filesystems,
// corrupt disks or execute arbitrary remote code.

@id("vectimus-base-001")
@description("Block recursive deletion of root, home or current directory")
@incident("Home directory deletion via rm -rf reported in Claude Code sessions, 2025")
@controls("SOC2-CC6.1, EU-AI-15")
@suggested_alternative("Delete specific files or directories by name instead of using broad recursive deletion.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    // Unix/macOS
    context.command like "*rm -rf /*" ||
    context.command like "*rm -rf ~*" ||
    context.command like "*rm -rf .*" ||
    // Windows cmd
    context.command like "*rd /s /q*" ||
    context.command like "*rmdir /s /q*" ||
    context.command like "*del /f /s /q*" ||
    // Windows PowerShell
    context.command like "*Remove-Item*-Recurse*-Force*"
};

@id("vectimus-base-002")
@description("Block disk destruction via mkfs or dd zeroing")
@incident("Accidental mkfs on production volume, various incident reports 2023-2025")
@controls("SOC2-CC6.1, EU-AI-15")
@suggested_alternative("Use file-level operations instead of raw disk commands.  Request human approval for disk formatting.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    // Unix/macOS
    context.command like "*mkfs*" ||
    context.command like "*dd if=/dev/zero*" ||
    // Windows
    context.command like "*format*/fs:*" ||
    context.command like "*diskpart*clean*"
};

@id("vectimus-base-003")
@description("Block fork bomb execution")
@incident("Fork bomb denial-of-service used to crash developer workstations, various reports")
@controls("SOC2-CC6.1, EU-AI-15")
@suggested_alternative("This command is a fork bomb and has no safe alternative.  It should never be executed.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*:(){ :|:*"
};

@id("vectimus-base-004")
@description("Block recursive chmod 777 on root filesystem")
@incident("chmod 777 / rendered Linux servers unbootable, multiple sysadmin post-mortems")
@controls("SOC2-CC6.1, EU-AI-15")
@suggested_alternative("Set permissions on specific files with appropriate modes (e.g. chmod 644 for files, 755 for directories).")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    // Unix/macOS
    context.command like "*chmod -R 777 /*" ||
    // Windows -- grant full control to Everyone recursively
    context.command like "*icacls*Everyone:F*/T*" ||
    context.command like "*icacls*Everyone:(OI)(CI)F*" ||
    context.command like "*cacls*Everyone:F*"
};

@id("vectimus-base-005")
@description("Block disk overwrite via redirect to block device")
@incident("Redirect to /dev/sda destroyed partition tables, data recovery incident reports")
@controls("SOC2-CC6.1, EU-AI-15")
@suggested_alternative("Use file-level operations instead of writing directly to block devices.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    // Unix/macOS
    context.command like "*> /dev/sda*" ||
    // Windows -- raw disk writes
    context.command like "*> \\\\.\\PhysicalDrive*" ||
    context.command like "*diskpart*" ||
    context.command like "*Clear-Disk*"
};

@id("vectimus-base-006")
@description("Block remote code execution via curl/wget piped to shell")
@incident("Supply-chain attacks via curl|sh pattern, Clinejection February 2026")
@controls("SOC2-CC6.6, SOC2-CC6.8, NIST-AI-MG-3.2, EU-AI-15")
@suggested_alternative("Download the script to a file first, review its contents, then execute it after inspection.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*curl*| sh" ||
    context.command like "*curl*| sh *" ||
    context.command like "*curl*| sh;*" ||
    context.command like "*curl*|sh" ||
    context.command like "*curl*|sh *" ||
    context.command like "*curl*|sh;*" ||
    context.command like "*curl*| /bin/sh*" ||
    context.command like "*curl*|/bin/sh*" ||
    context.command like "*curl*| bash*" ||
    context.command like "*curl*|bash*" ||
    context.command like "*wget*| sh" ||
    context.command like "*wget*| sh *" ||
    context.command like "*wget*| sh;*" ||
    context.command like "*wget*|sh" ||
    context.command like "*wget*|sh *" ||
    context.command like "*wget*|sh;*" ||
    context.command like "*wget*| /bin/sh*" ||
    context.command like "*wget*|/bin/sh*" ||
    context.command like "*wget*| bash*" ||
    context.command like "*wget*|bash*" ||
    // Windows PowerShell -- download and execute patterns
    context.command like "*Invoke-WebRequest*|*Invoke-Expression*" ||
    context.command like "*Invoke-WebRequest*| iex*" ||
    context.command like "*iwr*|*iex*" ||
    context.command like "*IEX*(New-Object*Net.WebClient)*DownloadString*" ||
    context.command like "*Invoke-Expression*(New-Object*Net.WebClient)*" ||
    // Windows cmd -- certutil download-execute
    context.command like "*certutil*-urlcache*" ||
    context.command like "*bitsadmin*/transfer*"
};

@id("vectimus-base-021")
@description("Block agents from running vectimus CLI commands to prevent governance bypass")
@incident("Agent attempted to disable its own governance rules after receiving deny response, 2026")
@controls("SOC2-CC6.1, EU-AI-14")
@suggested_alternative("Vectimus configuration must be changed by a human administrator.  Do not attempt to modify governance settings.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "vectimus *" ||
    context.command like "*vectimus rule*" ||
    context.command like "*vectimus pack*" ||
    context.command like "*vectimus init*" ||
    context.command like "*python -m vectimus*" ||
    context.command like "*python3 -m vectimus*"
};
