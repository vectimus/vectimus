// VTMS-2026-0027 | OWASP: LLM01 Excessive Agency | SOC 2: CC6.1 | NIST AI RMF: GV-1.1
// EU AI Act: Art. 14 | CIS: 5.4, 6.8, 12.1
// Amazon Kiro AI coding assistant (operator-level AWS permissions, no peer-review gate)
// autonomously deleted the entire AWS Cost Explorer production environment in the China
// region and attempted a rebuild from scratch — 13-hour outage.  Structurally identical
// to VTMS-2026-0003 (terraform destroy) but executed via AWS-native SDK/CLI tooling,
// placing it outside previous Cedar coverage.  This policy closes that gap.
//
// Blocks the family of AWS CLI verbs that terminate or delete environment-level
// compute, networking, managed-service and orchestration resources.
//
// Override: for planned teardown, operators must set context.human_approval = "true"
// in a time-scoped permit policy reviewed and approved by a human, e.g.:
//   permit(principal == Agent::"infra_bot", action, resource)
//   when { context.human_approval == "true" && context.approved_by == "ops-lead" };

@id("INFRA-002a")
@description("Block AWS CLI commands that terminate or delete compute and networking resources (VTMS-2026-0027)")
@incident("VTMS-2026-0027: Amazon Kiro deleted AWS Cost Explorer production environment, 13-hour China region outage, December 2025")
@controls("OWASP-LLM01, SOC2-CC6.1, NIST-AI-GV-1.1, EU-AI-14, CIS-5.4, CIS-6.8, CIS-12.1")
@suggested_alternative("Use 'aws <service> describe-*' or 'aws <service> stop-*' for non-destructive operations. For legitimate environment teardown add context.human_approval='true' in an operator-approved permit policy.")
forbid (
    principal,
    action == Vectimus::Action::"infrastructure",
    resource
) when {
    context.command like "*aws ec2 terminate-instances*"     ||
    context.command like "*aws cloudformation delete-stack*"  ||
    context.command like "*aws ecs delete-cluster*"           ||
    context.command like "*aws rds delete-db-instance*"       ||
    context.command like "*aws rds delete-cluster*"           ||
    context.command like "*aws ec2 delete-vpc*"               ||
    context.command like "*aws ec2 delete-subnet*"            ||
    context.command like "*aws ec2 delete-security-group*"    ||
    context.command like "*aws eks delete-cluster*"           ||
    context.command like "*aws lambda delete-function*"       ||
    context.command like "*aws elbv2 delete-load-balancer*"
};

@id("INFRA-002b")
@description("Block AWS CLI environment-destructive commands issued via shell (VTMS-2026-0027)")
@incident("VTMS-2026-0027: Amazon Kiro deleted AWS Cost Explorer production environment, 13-hour China region outage, December 2025")
@controls("OWASP-LLM01, SOC2-CC6.1, NIST-AI-GV-1.1, EU-AI-14, CIS-5.4, CIS-6.8, CIS-12.1")
@suggested_alternative("Use 'aws <service> describe-*' or 'aws <service> stop-*' for non-destructive operations. For legitimate environment teardown add context.human_approval='true' in an operator-approved permit policy.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*aws ec2 terminate-instances*"     ||
    context.command like "*aws cloudformation delete-stack*"  ||
    context.command like "*aws ecs delete-cluster*"           ||
    context.command like "*aws rds delete-db-instance*"       ||
    context.command like "*aws rds delete-cluster*"           ||
    context.command like "*aws ec2 delete-vpc*"               ||
    context.command like "*aws ec2 delete-subnet*"            ||
    context.command like "*aws ec2 delete-security-group*"    ||
    context.command like "*aws eks delete-cluster*"           ||
    context.command like "*aws lambda delete-function*"       ||
    context.command like "*aws elbv2 delete-load-balancer*"
};
