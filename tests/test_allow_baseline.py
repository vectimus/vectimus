"""False-positive regression tests: safe commands that must never be blocked.

This file catches overly broad regex patterns in Cedar policies.  Every
command here is something a developer or agent would routinely use and must
not trigger a deny.
"""

from __future__ import annotations

import pytest

from vectimus.core.evaluator import PolicyEngine
from vectimus.core.loader import PolicyLoader
from vectimus.core.models import ActionType


@pytest.fixture()
def engine():
    return PolicyEngine(loader=PolicyLoader())


# ---------------------------------------------------------------------------
# Safe shell commands
# ---------------------------------------------------------------------------


class TestSafeShellCommands:
    """Common developer commands that must pass through."""

    @pytest.mark.parametrize(
        "command",
        [
            # File listing and navigation
            "ls -la",
            "ls -la src/",
            "pwd",
            "whoami",
            "which python",
            "find . -name '*.py'",
            "wc -l src/main.py",
            # File operations
            "cat README.md",
            "head -n 20 src/main.py",
            "tail -f logs/app.log",
            "cp src/old.py src/new.py",
            "mv temp.txt archive/temp.txt",
            "mkdir -p src/components",
            "touch new_file.py",
            "rm temp_file.txt",
            "rm -r __pycache__",
            # Text processing
            "grep -r 'TODO' src/",
            "sed -i 's/old/new/g' file.txt",
            "awk '{print $1}' data.csv",
            "sort data.txt",
            "uniq -c output.txt",
            "diff file1.txt file2.txt",
            # Editors and viewing
            "echo 'Hello world'",
            "printf '%s\\n' 'test'",
            # Process management
            "ps aux",
            "top -l 1",
            "kill 12345",
            # Network (non-pipe)
            "curl https://api.example.com/data",
            "curl -o output.json https://api.example.com/users",
            "curl https://example.com | sha256sum",
            "curl https://example.com | shasum",
            "curl https://example.com | jq '.data'",
            "wget https://example.com/file.tar.gz",
            "wget -O archive.tar.gz https://example.com/release",
            "ping -c 3 example.com",
            "ssh user@server",
            "scp file.txt user@server:/path",
            "rsync -avz src/ user@server:/dst/",
            "rsync -e ssh file.txt server:/path",
            "rsync -c file.txt server:/path",
            # Compression
            "tar czf archive.tar.gz src/",
            "tar xzf archive.tar.gz",
            "zip -r archive.zip src/",
            "unzip archive.zip",
            "gzip file.txt",
            # System info
            "uname -a",
            "date",
            "uptime",
            "df -h",
            "du -sh .",
            "free -m",
            "env",
            "printenv PATH",
            "stat file.txt",
        ],
    )
    def test_shell_allowed(self, engine, make_event, command):
        event = make_event(command=command)
        assert engine.evaluate(event).decision == "allow", (
            f"False positive: '{command}' was blocked"
        )


# ---------------------------------------------------------------------------
# Safe development tool commands
# ---------------------------------------------------------------------------


class TestSafeDevelopmentCommands:
    """Build, test and lint commands that must pass through."""

    @pytest.mark.parametrize(
        "command",
        [
            # Python
            "python main.py",
            "python -m pytest",
            "python -c 'print(1+1)'",
            "python3 script.py",
            "pip install flask",
            "pip install -r requirements.txt",
            "pip freeze",
            "pip list",
            "uv sync",
            "uv run pytest",
            "uv add requests",
            "ruff check src/",
            "ruff format src/",
            "mypy src/",
            "black src/",
            "isort src/",
            "pytest",
            "pytest tests/ -v",
            "pytest -k test_login",
            # Node.js
            "node app.js",
            "npm install",
            "npm install express",
            "npm install --save-dev jest",
            "npm run build",
            "npm run dev",
            "npm test",
            "npm run lint",
            "npm ci",
            "npx jest",
            "npx tsc",
            "yarn install",
            "yarn build",
            "yarn test",
            "pnpm install",
            "pnpm build",
            "pnpm dev",
            # Rust
            "cargo build",
            "cargo test",
            "cargo run",
            "cargo clippy",
            "cargo fmt",
            # Go
            "go build ./...",
            "go test ./...",
            "go run main.go",
            "go mod tidy",
            # Java
            "mvn clean install",
            "mvn test",
            "gradle build",
            "gradle test",
            # General
            "make",
            "make test",
            "make build",
            "make clean",
            "cmake .",
            "cmake --build .",
        ],
    )
    def test_dev_tools_allowed(self, engine, make_event, command):
        event = make_event(command=command)
        assert engine.evaluate(event).decision == "allow", (
            f"False positive: '{command}' was blocked"
        )


# ---------------------------------------------------------------------------
# Safe git commands
# ---------------------------------------------------------------------------


class TestSafeGitCommands:
    """Routine git operations that must pass through."""

    @pytest.mark.parametrize(
        "command",
        [
            "git status",
            "git log",
            "git log --oneline",
            "git log --oneline -10",
            "git diff",
            "git diff --staged",
            "git diff HEAD~1",
            "git add .",
            "git add src/main.py",
            "git commit -m 'Fix bug'",
            "git push origin main",
            "git push origin feature-branch",
            "git push --force-with-lease origin feature-branch",
            "git push -f origin feature-branch",
            "git pull",
            "git pull origin main",
            "git fetch",
            "git fetch --all",
            "git checkout feature",
            "git checkout -b new-branch",
            "git switch main",
            "git switch -c new-branch",
            "git branch",
            "git branch -a",
            "git merge feature",
            "git rebase main",
            "git cherry-pick abc123",
            "git stash",
            "git stash pop",
            "git stash list",
            "git tag v1.0.0",
            "git remote -v",
            "git clean -n",
            "git clean --dry-run",
            "git reset --soft HEAD~1",
            "git reset HEAD file.txt",
            "git blame src/main.py",
            "git show HEAD",
        ],
    )
    def test_git_allowed(self, engine, make_event, command):
        event = make_event(
            action_type=ActionType.GIT_OPERATION,
            command=command,
        )
        assert engine.evaluate(event).decision == "allow", (
            f"False positive: '{command}' was blocked"
        )


# ---------------------------------------------------------------------------
# Safe infrastructure commands
# ---------------------------------------------------------------------------


class TestSafeInfraCommands:
    """Routine infrastructure commands that must pass through."""

    @pytest.mark.parametrize(
        "command",
        [
            "terraform init",
            "terraform plan",
            "terraform apply",
            "terraform validate",
            "terraform fmt",
            "terraform output",
            "terraform state list",
            "kubectl get pods",
            "kubectl get services",
            "kubectl apply -f deployment.yaml",
            "kubectl describe pod my-pod",
            "kubectl logs my-pod",
            "kubectl port-forward my-pod 8080:80",
            "kubectl rollout status deployment/app",
            "kubectl scale deployment/app --replicas=3",
            "aws s3 ls",
            "aws s3 cp file.txt s3://bucket/",
            "aws s3 sync ./dist s3://bucket/",
            "aws ec2 describe-instances",
            "aws iam list-users",
            "docker build .",
            "docker build -t myapp .",
            "docker run hello-world",
            "docker run -d -p 8080:80 nginx",
            "docker ps",
            "docker images",
            "docker stop container",
            "docker logs container",
            "docker-compose up -d",
            "docker-compose down",
        ],
    )
    def test_infra_allowed(self, engine, make_event, command):
        event = make_event(
            action_type=ActionType.INFRASTRUCTURE,
            command=command,
        )
        assert engine.evaluate(event).decision == "allow", (
            f"False positive: '{command}' was blocked"
        )


# ---------------------------------------------------------------------------
# Safe file operations
# ---------------------------------------------------------------------------


class TestSafeFileOperations:
    """File reads and writes to non-sensitive paths must pass through."""

    @pytest.mark.parametrize(
        "file_path",
        [
            "src/main.py",
            "src/components/Button.tsx",
            "tests/test_login.py",
            "README.md",
            "CHANGELOG.md",
            "package.json",
            "tsconfig.json",
            "pyproject.toml",
            "Cargo.toml",
            "go.mod",
            "Makefile",
            "Dockerfile",
            "docker-compose.yml",
            ".gitignore",
            ".eslintrc.json",
            "config.yaml",
            "config/settings.json",
            "docs/guide.md",
        ],
    )
    def test_file_read_allowed(self, engine, make_event, file_path):
        event = make_event(
            action_type=ActionType.FILE_READ,
            tool_name="Read",
            file_path=file_path,
        )
        assert engine.evaluate(event).decision == "allow", (
            f"False positive: reading '{file_path}' was blocked"
        )

    @pytest.mark.parametrize(
        "file_path",
        [
            "src/main.py",
            "src/components/Button.tsx",
            "tests/test_login.py",
            "README.md",
            "package.json",
            "pyproject.toml",
            ".gitignore",
            ".eslintrc.json",
            "config.yaml",
            "docs/guide.md",
            "scripts/build.sh",
        ],
    )
    def test_file_write_allowed(self, engine, make_event, file_path):
        event = make_event(
            action_type=ActionType.FILE_WRITE,
            tool_name="Write",
            file_path=file_path,
        )
        assert engine.evaluate(event).decision == "allow", (
            f"False positive: writing '{file_path}' was blocked"
        )


# ---------------------------------------------------------------------------
# Edge cases: commands that look dangerous but are not
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Commands that share tokens with blocked patterns but must be allowed."""

    @pytest.mark.parametrize(
        "command,reason",
        [
            # "at" in command should not match "at" (crontab-like) patterns
            ("cat README.md", "cat contains 'at'"),
            ("date", "date command"),
            ("stat file.txt", "stat contains 'at'"),
            # "rm" in harmless contexts
            ("rm temp.txt", "single file delete"),
            ("rm -r temp_dir", "directory without -f"),
            # curl without pipe
            ("curl https://api.example.com", "curl without pipe"),
            ("curl -o file.tar.gz https://example.com/archive.tar.gz", "curl to file"),
            ("curl https://example.com | jq '.'", "curl to jq, not shell"),
            ("curl https://example.com | sha256sum", "curl to checksum"),
            # terraform without destroy
            ("terraform plan -destroy", "plan mode, not actual destroy"),
            # git without force
            ("git push origin main", "normal push, not forced"),
            # NOTE: --force-with-lease on main is blocked because Cedar pattern
            # *git push*--force*main* matches --force-with-lease.  Known limitation.
            ("git push --force-with-lease origin feature-branch", "safe force push to feature"),
            # rsync flags that look like nc flags
            ("rsync -e ssh file server:/path", "rsync -e is not nc -e"),
            ("rsync -c file server:/path", "rsync -c is not nc -c"),
            # Docker without -f
            ("docker rm container", "remove without force"),
            ("docker stop container", "stop, not force remove"),
        ],
    )
    def test_edge_case_allowed(self, engine, make_event, command, reason):
        event = make_event(command=command)
        assert engine.evaluate(event).decision == "allow", (
            f"False positive ({reason}): '{command}' was blocked"
        )
