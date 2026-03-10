// Database safety -- block ORM and migration tool commands that use force
// flags to bypass interactive safety confirmations.  These flags exist as
// safety gates; agents systematically bypass them to avoid prompts.

@id("vectimus-base-040")
@description("Block drizzle-kit operations with --force flag or drop command that bypass safety confirmation")
@incident("Claude Code drizzle-kit --force destroyed 60+ production tables on Railway, February 2026")
@controls("SOC2-CC6.1, EU-AI-14")
@suggested_alternative("Run drizzle-kit push without --force so the interactive confirmation can protect against destructive changes.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*drizzle-kit push*--force*" ||
    context.command like "*drizzle-kit drop*"
};

@id("vectimus-base-041")
@description("Block prisma operations with --accept-data-loss or destructive reset/execute commands")
@incident("Claude Code prisma --accept-data-loss destroyed production database, December 2025")
@controls("SOC2-CC6.1, EU-AI-14")
@suggested_alternative("Run prisma db push without --accept-data-loss.  Use prisma migrate dev for safe migrations.  Avoid prisma migrate reset in production.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*prisma db push*--accept-data-loss*" ||
    context.command like "*prisma migrate reset*" ||
    context.command like "*prisma db execute*"
};

@id("vectimus-base-042")
@description("Block knex migrate:rollback --all which destroys all migration state")
@incident("ORM destructive flag pattern identified in agent safety bypass analysis")
@controls("SOC2-CC6.1, EU-AI-14")
@suggested_alternative("Roll back migrations one at a time with knex migrate:rollback (without --all) and verify each step.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*knex migrate:rollback*--all*"
};

@id("vectimus-base-043")
@description("Block sequelize database drop and full migration undo commands")
@incident("ORM destructive flag pattern identified in agent safety bypass analysis")
@controls("SOC2-CC6.1, EU-AI-14")
@suggested_alternative("Undo migrations one at a time with sequelize db:migrate:undo.  Database drops require human approval.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*sequelize db:drop*" ||
    context.command like "*sequelize db:migrate:undo:all*"
};

@id("vectimus-base-044")
@description("Block Rails database drop, reset and schema:load commands")
@incident("ORM destructive flag pattern identified in agent safety bypass analysis")
@controls("SOC2-CC6.1, EU-AI-14")
@suggested_alternative("Use rails db:migrate for safe incremental changes.  Database drops and resets require human approval.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*rails db:drop*" ||
    context.command like "*rails db:reset*" ||
    context.command like "*rails db:schema:load*" ||
    context.command like "*rake db:drop*" ||
    context.command like "*rake db:reset*" ||
    context.command like "*rake db:schema:load*"
};

@id("vectimus-base-045")
@description("Block Django flush with --no-input flag that bypasses confirmation")
@incident("ORM destructive flag pattern identified in agent safety bypass analysis")
@controls("SOC2-CC6.1, EU-AI-14")
@suggested_alternative("Run manage.py flush without --no-input so the interactive confirmation prompt can protect against data loss.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*manage.py flush*--no-input*" ||
    context.command like "*django*flush*--no-input*"
};

@id("vectimus-base-046")
@description("Block TypeORM schema:drop and migration:revert commands")
@incident("ORM destructive flag pattern identified in agent safety bypass analysis")
@controls("SOC2-CC6.1, EU-AI-14")
@suggested_alternative("Use TypeORM migrations to make incremental schema changes.  Schema drops require human approval.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*typeorm schema:drop*" ||
    context.command like "*typeorm migration:revert*"
};
