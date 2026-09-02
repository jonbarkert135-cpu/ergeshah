"""Git plumbing: worktree isolation, commits, merges, push.

Each task is built in its own ``git worktree`` on its own branch, so parallel agents cannot
step on each other's files, and a failed task can be thrown away with one command. Merges into
the integration branch happen only after gates pass; a conflict is reported back as a normal
task failure instead of leaving a half-merged tree behind.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from .util import LOG, slug, trim


class GitError(RuntimeError):
    pass


@dataclass
class GitResult:
    ok: bool
    stdout: str
    stderr: str

    @property
    def output(self) -> str:
        return (self.stdout + ("\n" + self.stderr if self.stderr else "")).strip()


def git(args: list[str], cwd: Path, timeout: int = 300, check: bool = False) -> GitResult:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitError("git is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git {' '.join(args)} timed out after {timeout}s") from exc
    result = GitResult(proc.returncode == 0, (proc.stdout or "").strip(), (proc.stderr or "").strip())
    if check and not result.ok:
        raise GitError(f"git {' '.join(args)} failed: {trim(result.output, 500)}")
    return result


def is_repo(path: Path) -> bool:
    return git(["rev-parse", "--is-inside-work-tree"], path).ok


def ensure_repo(path: Path, initial_branch: str = "main") -> None:
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    if is_repo(path):
        return
    git(["init", "-b", initial_branch], path, check=True)
    LOG.info("initialised a new git repository in %s", path)


def current_branch(path: Path) -> str:
    return git(["rev-parse", "--abbrev-ref", "HEAD"], path).stdout.strip()


def head_sha(path: Path) -> str:
    return git(["rev-parse", "HEAD"], path).stdout.strip()


def has_commits(path: Path) -> bool:
    return git(["rev-parse", "--verify", "HEAD"], path).ok


def is_dirty(path: Path) -> bool:
    return bool(git(["status", "--porcelain"], path).stdout.strip())


def changed_files(path: Path) -> list[str]:
    out = git(["status", "--porcelain"], path).stdout
    files = []
    for line in out.splitlines():
        entry = line[3:].strip().strip('"')
        if " -> " in entry:  # renames
            entry = entry.split(" -> ", 1)[1]
        if entry:
            files.append(entry)
    return files


def commit_all(path: Path, message: str, author: str = "Hive Agent <hive@localhost>") -> str:
    git(["add", "-A"], path, check=True)
    if not git(["diff", "--cached", "--quiet"], path).ok:
        git(["commit", "-m", message, f"--author={author}"], path, check=True)
        return head_sha(path)
    return ""


def branch_name(prefix: str, task_id: str) -> str:
    return f"{prefix}/{slug(task_id, 50)}"


def add_worktree(repo: Path, rel_dir: str, branch: str, base: str = "HEAD") -> Path:
    """Create (or reuse) a worktree at ``repo/rel_dir`` on a fresh ``branch``."""
    target = Path(repo) / rel_dir
    if target.exists():
        remove_worktree(repo, rel_dir, delete_branch=branch)
    git(["branch", "-D", branch], repo)  # ignore failure
    args = ["worktree", "add", rel_dir, "-b", branch]
    if has_commits(repo):
        args.append(base)
    git(args, repo, check=True)
    return target


def remove_worktree(repo: Path, rel_dir: str, delete_branch: str = "") -> None:
    git(["worktree", "remove", "--force", rel_dir], repo)
    path = Path(repo) / rel_dir
    if path.exists():
        import shutil

        shutil.rmtree(path, ignore_errors=True)
    git(["worktree", "prune"], repo)
    if delete_branch:
        git(["branch", "-D", delete_branch], repo)


def merge_branch(repo: Path, branch: str, message: str) -> tuple[bool, str]:
    """Merge ``branch`` into the current branch. Aborts cleanly on conflict."""
    result = git(["merge", "--no-ff", "-m", message, branch], repo)
    if result.ok:
        return True, result.output
    conflict = git(["diff", "--name-only", "--diff-filter=U"], repo).stdout
    git(["merge", "--abort"], repo)
    return False, f"merge conflict in: {conflict or 'unknown files'}\n{trim(result.output, 1000)}"


def diff_stat(repo: Path, base: str, head: str = "HEAD") -> str:
    return git(["diff", "--stat", f"{base}..{head}"], repo).stdout


def diff_text(repo: Path, base: str, head: str = "HEAD", limit: int = 40_000) -> str:
    out = git(["diff", "--unified=3", f"{base}..{head}"], repo).stdout
    return trim(out, limit)


def push(repo: Path, remote: str, branch: str) -> tuple[bool, str]:
    if not git(["remote", "get-url", remote], repo).ok:
        return False, f"remote '{remote}' is not configured"
    result = git(["push", remote, f"HEAD:{branch}"], repo, timeout=600)
    return result.ok, result.output
