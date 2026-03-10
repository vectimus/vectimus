// Infrastructure safety -- block dangerous infrastructure commands that
// can destroy cloud resources or delete Kubernetes namespaces.

@id("vectimus-base-007")
@description("Block terraform destroy without explicit approval")
@incident("Terraform destroy on production infrastructure, 2025")
@controls("SOC2-CC6.1, EU-AI-14")
@suggested_alternative("Use terraform plan to preview changes, then request human approval for destructive operations.")
forbid (
    principal,
    action == Vectimus::Action::"infrastructure",
    resource
) when {
    context.command like "*terraform destroy*"
};

@id("vectimus-base-008")
@description("Block terraform apply with auto-approve flag")
@incident("Unreviewed terraform apply auto-approved production changes, 2025")
@controls("SOC2-CC6.1, EU-AI-14")
@suggested_alternative("Use terraform plan first, then terraform apply without -auto-approve so changes can be reviewed.")
forbid (
    principal,
    action == Vectimus::Action::"infrastructure",
    resource
) when {
    context.command like "*terraform apply*-auto-approve*"
};

@id("vectimus-base-009")
@description("Block kubectl delete namespace to prevent accidental cluster damage")
@incident("kubectl delete namespace wiped production services, Kubernetes incident postmortem 2024")
@controls("SOC2-CC6.1, EU-AI-14")
@suggested_alternative("Delete individual resources within the namespace instead, or request human approval for namespace deletion.")
forbid (
    principal,
    action == Vectimus::Action::"infrastructure",
    resource
) when {
    context.command like "*kubectl delete namespace*"
};

@id("vectimus-base-010")
@description("Block forced deletion of S3 buckets")
@incident("Accidental S3 bucket deletion caused data loss, AWS incident reports 2023-2025")
@controls("SOC2-CC6.1, EU-AI-14")
@suggested_alternative("Empty the bucket contents first with aws s3 rm, then delete the bucket without --force after human review.")
forbid (
    principal,
    action == Vectimus::Action::"infrastructure",
    resource
) when {
    context.command like "*aws s3 rb*--force*"
};

@id("vectimus-base-011-infra")
@description("Block docker rm -f on running containers")
@incident("Force-removed production containers caused service outage, Docker incident reports")
@controls("SOC2-CC6.1")
@suggested_alternative("Use docker stop to gracefully stop the container first, then docker rm to remove it.")
forbid (
    principal,
    action == Vectimus::Action::"infrastructure",
    resource
) when {
    context.command like "*docker rm -f*"
};
