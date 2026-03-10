"""Tests for the event enrichment module."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from vectimus.core.enrichment import (
    _get_branch,
    _get_hostname,
    _get_identity,
    _get_repository,
    enrich,
)
from vectimus.core.models import (
    ActionInfo,
    ActionType,
    ContextInfo,
    IdentityInfo,
    SourceInfo,
    VectimusEvent,
)


@pytest.fixture(autouse=True)
def _clear_caches():
    """Clear all lru_caches between tests."""
    _get_hostname.cache_clear()
    _get_identity.cache_clear()
    _get_repository.cache_clear()
    _get_branch.cache_clear()
    yield
    _get_hostname.cache_clear()
    _get_identity.cache_clear()
    _get_repository.cache_clear()
    _get_branch.cache_clear()


def _bare_event(
    *,
    principal: str = "unknown",
    version: str | None = None,
    hostname: str | None = None,
    repository: str | None = None,
    branch: str | None = None,
    cwd: str | None = "/home/user/project",
) -> VectimusEvent:
    return VectimusEvent(
        source=SourceInfo(tool="claude-code", version=version),
        identity=IdentityInfo(principal=principal),
        action=ActionInfo(
            action_type=ActionType.SHELL_COMMAND,
            raw_tool_name="Bash",
        ),
        context=ContextInfo(
            cwd=cwd,
            hostname=hostname,
            repository=repository,
            branch=branch,
        ),
    )


# ---------------------------------------------------------------------------
# Version enrichment
# ---------------------------------------------------------------------------


class TestVersionEnrichment:
    def test_sets_version_when_none(self) -> None:
        event = _bare_event()
        enriched = enrich(event)
        assert enriched.source.version is not None
        import vectimus

        assert enriched.source.version == vectimus.__version__

    def test_does_not_overwrite_existing_version(self) -> None:
        event = _bare_event(version="custom-1.0")
        enriched = enrich(event)
        assert enriched.source.version == "custom-1.0"


# ---------------------------------------------------------------------------
# Hostname enrichment
# ---------------------------------------------------------------------------


class TestHostnameEnrichment:
    @patch("vectimus.core.enrichment.socket.gethostname", return_value="myhost")
    def test_sets_hostname(self, mock_gh: MagicMock) -> None:
        event = _bare_event()
        enriched = enrich(event)
        assert enriched.context.hostname == "myhost"

    @patch("vectimus.core.enrichment.socket.gethostname", side_effect=OSError)
    def test_handles_socket_failure(self, mock_gh: MagicMock) -> None:
        event = _bare_event()
        enriched = enrich(event)
        assert enriched.context.hostname is None

    @patch("vectimus.core.enrichment.socket.gethostname", return_value="myhost")
    def test_does_not_overwrite_existing_hostname(self, mock_gh: MagicMock) -> None:
        event = _bare_event(hostname="preset-host")
        enriched = enrich(event)
        assert enriched.context.hostname == "preset-host"


# ---------------------------------------------------------------------------
# Identity enrichment
# ---------------------------------------------------------------------------


class TestIdentityEnrichment:
    @patch("vectimus.core.enrichment.subprocess.run")
    def test_resolves_git_email(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(stdout="dev@example.com\n", returncode=0)
        event = _bare_event()
        enriched = enrich(event)
        assert enriched.identity.principal == "dev@example.com"

    @patch("vectimus.core.enrichment.subprocess.run")
    def test_falls_back_to_git_name(self, mock_run: MagicMock) -> None:
        def side_effect(cmd, **kwargs):
            if "user.email" in cmd:
                return MagicMock(stdout="", returncode=1)
            return MagicMock(stdout="Dev User\n", returncode=0)

        mock_run.side_effect = side_effect
        event = _bare_event()
        enriched = enrich(event)
        assert enriched.identity.principal == "Dev User"

    @patch("vectimus.core.enrichment.getpass.getuser", return_value="osuser")
    @patch(
        "vectimus.core.enrichment.subprocess.run",
        side_effect=FileNotFoundError,
    )
    def test_falls_back_to_os_user(self, mock_run: MagicMock, mock_gp: MagicMock) -> None:
        event = _bare_event()
        enriched = enrich(event)
        assert enriched.identity.principal == "osuser"

    @patch("vectimus.core.enrichment.getpass.getuser", side_effect=OSError)
    @patch(
        "vectimus.core.enrichment.subprocess.run",
        side_effect=FileNotFoundError,
    )
    def test_stays_unknown_when_all_fail(self, mock_run: MagicMock, mock_gp: MagicMock) -> None:
        event = _bare_event()
        enriched = enrich(event)
        assert enriched.identity.principal == "unknown"

    @patch("vectimus.core.enrichment.subprocess.run")
    def test_does_not_overwrite_known_principal(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(stdout="other@example.com\n", returncode=0)
        event = _bare_event(principal="already@set.com")
        enriched = enrich(event)
        assert enriched.identity.principal == "already@set.com"


# ---------------------------------------------------------------------------
# Git context enrichment
# ---------------------------------------------------------------------------


class TestGitContextEnrichment:
    @patch("vectimus.core.enrichment.subprocess.run")
    def test_sets_repository_and_branch(self, mock_run: MagicMock) -> None:
        def side_effect(cmd, **kwargs):
            if "--show-toplevel" in cmd:
                return MagicMock(stdout="/home/user/project\n", returncode=0)
            if "--abbrev-ref" in cmd:
                return MagicMock(stdout="main\n", returncode=0)
            # identity calls
            if "user.email" in cmd:
                return MagicMock(stdout="dev@example.com\n", returncode=0)
            return MagicMock(stdout="", returncode=1)

        mock_run.side_effect = side_effect
        event = _bare_event()
        enriched = enrich(event)
        assert enriched.context.repository == "/home/user/project"
        assert enriched.context.branch == "main"

    @patch("vectimus.core.enrichment.subprocess.run", side_effect=FileNotFoundError)
    def test_handles_no_git(self, mock_run: MagicMock) -> None:
        event = _bare_event()
        enriched = enrich(event)
        assert enriched.context.repository is None
        assert enriched.context.branch is None

    @patch("vectimus.core.enrichment.subprocess.run")
    def test_handles_not_a_repo(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(stdout="", returncode=128)
        event = _bare_event()
        enriched = enrich(event)
        assert enriched.context.repository is None
        assert enriched.context.branch is None

    @patch(
        "vectimus.core.enrichment.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="git", timeout=5),
    )
    def test_handles_timeout(self, mock_run: MagicMock) -> None:
        event = _bare_event()
        enriched = enrich(event)
        assert enriched.context.repository is None
        assert enriched.context.branch is None

    @patch("vectimus.core.enrichment.subprocess.run")
    def test_does_not_overwrite_existing_repo(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(stdout="other\n", returncode=0)
        event = _bare_event(repository="/preset/repo")
        enriched = enrich(event)
        assert enriched.context.repository == "/preset/repo"

    def test_none_cwd_skips_git_context(self) -> None:
        event = _bare_event(cwd=None)
        enriched = enrich(event)
        assert enriched.context.repository is None
        assert enriched.context.branch is None


# ---------------------------------------------------------------------------
# Cache effectiveness
# ---------------------------------------------------------------------------


class TestCacheEffectiveness:
    @patch("vectimus.core.enrichment.socket.gethostname", return_value="cached-host")
    def test_hostname_cached(self, mock_gh: MagicMock) -> None:
        e1 = _bare_event()
        e2 = _bare_event()
        enrich(e1)
        enrich(e2)
        assert mock_gh.call_count == 1

    @patch("vectimus.core.enrichment.subprocess.run")
    def test_identity_cached(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(stdout="dev@example.com\n", returncode=0)
        e1 = _bare_event()
        e2 = _bare_event()
        enrich(e1)
        _get_hostname.cache_clear()  # avoid hostname cache interference
        enrich(e2)
        # subprocess.run should be called once for identity (email hit),
        # plus git context calls — but identity itself is only resolved once
        identity_calls = [
            c for c in mock_run.call_args_list if any("user.email" in str(a) for a in c.args)
        ]
        assert len(identity_calls) == 1
