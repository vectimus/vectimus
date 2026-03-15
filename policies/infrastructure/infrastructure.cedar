// Infrastructure safety -- block destructive cloud, container and IaC
// operations and prevent privilege escalation to elevated roles.

@id("vectimus-infra-001")
@description("Block terraform destroy without explicit approval")
@incident("Terraform destroy on production infrastructure, 2025")
@controls("SOC2-CC6.1, EU-AI-14, NIST-CSF-PR.AA-05, ISO27001-A.8.2")
@suggested_alternative("Use terraform plan to preview changes, then request human approval for destructive operations.")
forbid (
    principal,
    action == Vectimus::Action::"infrastructure",
    resource
) when {
    context.command like "*terraform destroy*"
};

@id("vectimus-infra-002")
@description("Block terraform apply with auto-approve flag")
@incident("Unreviewed terraform apply auto-approved production changes, 2025")
@controls("SOC2-CC6.1, EU-AI-14, NIST-CSF-PR.AA-05, ISO27001-A.8.2")
@suggested_alternative("Use terraform plan first, then terraform apply without -auto-approve so changes can be reviewed.")
forbid (
    principal,
    action == Vectimus::Action::"infrastructure",
    resource
) when {
    context.command like "*terraform apply*-auto-approve*"
};

@id("vectimus-infra-003")
@description("Block kubectl delete namespace to prevent accidental cluster damage")
@incident("kubectl delete namespace wiped production services, Kubernetes incident postmortem 2024")
@controls("SOC2-CC6.1, EU-AI-14, NIST-CSF-PR.AA-05, ISO27001-A.8.2")
@suggested_alternative("Delete individual resources within the namespace instead, or request human approval for namespace deletion.")
forbid (
    principal,
    action == Vectimus::Action::"infrastructure",
    resource
) when {
    context.command like "*kubectl delete namespace*"
};

@id("vectimus-infra-004")
@description("Block forced deletion of S3 buckets")
@incident("Accidental S3 bucket deletion caused data loss, AWS incident reports 2023-2025")
@controls("SOC2-CC6.1, EU-AI-14, NIST-CSF-PR.AA-05, ISO27001-A.8.2")
@suggested_alternative("Empty the bucket contents first with aws s3 rm, then delete the bucket without --force after human review.")
forbid (
    principal,
    action == Vectimus::Action::"infrastructure",
    resource
) when {
    context.command like "*aws s3 rb*--force*"
};

@id("vectimus-infra-005")
@description("Block docker rm -f on running containers")
@incident("Force-removed production containers caused service outage, Docker incident reports")
@controls("SOC2-CC6.1, NIST-CSF-PR.AA-05, ISO27001-A.8.2")
@suggested_alternative("Use docker stop to gracefully stop the container first, then docker rm to remove it.")
forbid (
    principal,
    action == Vectimus::Action::"infrastructure",
    resource
) when {
    context.command like "*docker rm -f*"
};

@id("vectimus-infra-006")
@description("Block cloud CLI privilege escalation commands")
@incident("15 Ways to Break Your Copilot, BHUSA 2024 - agent privilege escalation")
@controls("OWASP-ASI03, SOC2-CC6.1, EU-AI-15, NIST-CSF-PR.AA-05, ISO27001-A.8.2")
@suggested_alternative("Use the cloud credentials already configured for the current session.  Request human approval for role assumption or re-authentication.")
forbid (
    principal,
    action == Vectimus::Action::"infrastructure",
    resource
) when {
    context.command like "*aws sts assume-role*" ||
    context.command like "*gcloud auth login*" ||
    context.command like "*gcloud auth activate-service-account*" ||
    context.command like "*az login*"
};

@id("vectimus-infra-007")
@description("Block file operations targeting other users' home directories")
@incident("Docker MCP prompt injection allowed cross-user file access, 2025")
@controls("OWASP-ASI03, SOC2-CC6.1, NIST-CSF-PR.AA-05, ISO27001-A.8.3")
@suggested_alternative("Operate within your own project directory.  Access to other users' files requires explicit human authorisation.")
forbid (
    principal,
    action == Vectimus::Action::"file_read",
    resource
) when {
    // Unix/macOS
    context.file_path like "/home/*/../*" ||
    context.file_path like "/Users/*/../*" ||
    context.file_path like "/root/*" ||
    // Windows
    context.file_path like "*\\Users\\*\\..\\*" ||
    context.file_path like "C:\\Users\\*\\..\\*"
};

@id("vectimus-infra-008")
@description("Block sudo and su execution by agents to prevent privilege escalation")
@incident("CVE-2025-31491: agent privilege escalation via sudo")
@controls("OWASP-ASI03, SOC2-CC6.1, EU-AI-14, NIST-CSF-PR.AA-05, ISO27001-A.8.2")
@suggested_alternative("Run commands with current user permissions.  If elevated privileges are needed, request human approval to run the command manually.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    // Unix/macOS
    context.command like "sudo *" ||
    context.command like "*| sudo *" ||
    context.command like "su *" ||
    context.command like "su -c*" ||
    // Windows cmd
    context.command like "*runas /user:*" ||
    context.command like "*runas /noprofile*" ||
    // Windows PowerShell
    context.command like "*Start-Process*-Verb RunAs*" ||
    context.command like "*Start-Process*-Verb runas*"
};
