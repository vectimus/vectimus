"""Click CLI group entry point.

All sub-commands are registered here.  The ``vectimus`` console script
defined in pyproject.toml points at the ``cli`` group.
"""

from __future__ import annotations

import click

from vectimus.cli.init_cmd import init_cmd
from vectimus.cli.pack_cmd import pack_cmd
from vectimus.cli.remove_cmd import remove_cmd
from vectimus.cli.rule_cmd import rule_cmd
from vectimus.cli.server_cmd import server_cmd
from vectimus.cli.status_cmd import status_cmd
from vectimus.cli.test_cmd import test_cmd
from vectimus.core.config import VectimusConfig


@click.group()
@click.version_option(package_name="vectimus")
def cli() -> None:
    """Vectimus -- deterministic governance for AI coding tools."""


@click.command("observe")
@click.argument("action", type=click.Choice(["on", "off", "status"]))
def observe_cmd(action: str) -> None:
    """Enable or disable observe mode.

    Observe mode logs all policy decisions to the audit trail but never
    blocks actions.  Use this to trial Vectimus before enforcing.

    \b
      vectimus observe on      Enable observe mode
      vectimus observe off     Disable observe mode (enforce policies)
      vectimus observe status  Show current mode
    """
    config = VectimusConfig()

    if action == "status":
        mode = "observe (log only)" if config.is_observe_mode() else "enforce (default)"
        click.echo(f"Mode: {mode}")
        return

    enabled = action == "on"
    config.set_observe_mode(enabled)

    if enabled:
        click.echo("Observe mode enabled.  Decisions will be logged but all actions allowed.")
        click.echo("Review the audit log to see what would have been blocked:")
        click.echo(f"  {config.get_log_dir()}")
    else:
        click.echo("Observe mode disabled.  Policies are now enforced.")


@click.group("mcp")
def mcp_cmd() -> None:
    """Manage the MCP server allowlist.

    By default Vectimus blocks all MCP tool calls (rule vectimus-base-030).
    Use these commands to approve specific MCP servers.
    """


@mcp_cmd.command("allow")
@click.argument("server")
def mcp_allow(server: str) -> None:
    """Add an MCP server to the approved list.

    \b
      vectimus mcp allow github
      vectimus mcp allow slack
    """
    config = VectimusConfig()
    if server in config.mcp_allowed_servers():
        click.echo(f"Server '{server}' is already on the approved list.")
        return
    config.mcp_allow_server(server)
    click.echo(f"Approved MCP server: {server}")
    click.echo(f"  Agents can now call tools on the '{server}' MCP server.")


@mcp_cmd.command("deny")
@click.argument("server")
def mcp_deny(server: str) -> None:
    """Remove an MCP server from the approved list.

    \b
      vectimus mcp deny evil-server
    """
    config = VectimusConfig()
    if server not in config.mcp_allowed_servers():
        click.echo(f"Server '{server}' is not on the approved list.")
        return
    config.mcp_deny_server(server)
    click.echo(f"Removed MCP server: {server}")
    click.echo(f"  Agents can no longer call tools on the '{server}' MCP server.")


@mcp_cmd.command("list")
def mcp_list() -> None:
    """Show the current MCP server allowlist."""
    config = VectimusConfig()
    servers = config.mcp_allowed_servers()
    if not servers:
        click.echo("No MCP servers approved.  All MCP tool calls are blocked.")
        click.echo("  Use 'vectimus mcp allow <server>' to approve a server.")
        return
    click.echo("Approved MCP servers:")
    for s in sorted(servers):
        click.echo(f"  [+] {s}")


cli.add_command(init_cmd, name="init")
cli.add_command(remove_cmd, name="remove")
cli.add_command(test_cmd, name="test")
cli.add_command(status_cmd, name="status")
cli.add_command(pack_cmd, name="pack")
cli.add_command(rule_cmd, name="rule")
cli.add_command(server_cmd, name="server")
cli.add_command(observe_cmd, name="observe")
cli.add_command(mcp_cmd, name="mcp")
