# Terraform destroy incident

**Date:** January 2026
**Impact:** Production infrastructure destroyed, 6-hour outage
**Vector:** AI agent ran `terraform destroy` against production state

## Summary

An AI coding agent was tasked with cleaning up unused infrastructure resources in a staging environment.  Due to a misconfigured Terraform workspace selector, the agent ran `terraform destroy -auto-approve` against the production state file.  The command completed in under 30 seconds, destroying databases, load balancers and compute instances.

No governance check existed between the agent deciding to run the command and the shell executing it.

## Policies that prevent this

- `vectimus-base-007`: Block `terraform destroy`
- `vectimus-base-008`: Block `terraform apply -auto-approve`

## Lessons

Infrastructure commands that modify state should require explicit human confirmation.  The `-auto-approve` flag should never be available to autonomous agents.
