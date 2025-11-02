"""Utilities for ensuring generated files are owned by the invoking user."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Optional, Sequence, Tuple, Union

try:
    import pwd
except ImportError:  # pragma: no cover - pwd is POSIX specific
    pwd = None  # type: ignore[assignment]


_PATH_LIKE = Union[str, os.PathLike[str]]
_REPO_ROOT = Path(__file__).resolve().parents[1]


def _parse_int(value: Optional[str]) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):  # pragma: no cover - defensive guard
        return None


def _infer_gid(uid: int) -> Optional[int]:
    if pwd is None:
        return None

    try:
        return pwd.getpwuid(uid).pw_gid
    except KeyError:  # pragma: no cover - defensive guard
        return None


def _determine_owner() -> Optional[Tuple[int, int]]:
    """Return the desired UID/GID for generated artefacts."""

    if os.name != "posix":
        return None

    uid = os.getuid()
    gid = os.getgid()
    if uid != 0:
        return uid, gid

    candidates: Sequence[Tuple[str, str]] = (
        ("RECON_UID", "RECON_GID"),
        ("SUDO_UID", "SUDO_GID"),
        ("PKEXEC_UID", "PKEXEC_GID"),
        ("DOAS_UID", "DOAS_GID"),
    )

    for uid_var, gid_var in candidates:
        candidate_uid = _parse_int(os.environ.get(uid_var))
        if not candidate_uid or candidate_uid == 0:
            continue

        candidate_gid = _parse_int(os.environ.get(gid_var))
        if not candidate_gid or candidate_gid == 0:
            inferred_gid = _infer_gid(candidate_uid)
            if inferred_gid:
                candidate_gid = inferred_gid
        if candidate_gid and candidate_gid != 0:
            return candidate_uid, candidate_gid

    try:
        stat_info = _REPO_ROOT.stat()
    except OSError:  # pragma: no cover - defensive guard
        stat_info = None

    if stat_info and stat_info.st_uid != 0:
        gid_value = stat_info.st_gid
        if gid_value == 0:
            inferred_gid = _infer_gid(stat_info.st_uid)
            if inferred_gid:
                gid_value = inferred_gid
        if gid_value != 0:
            return stat_info.st_uid, gid_value

    raise RuntimeError(
        "Unable to determine a non-root owner for generated files. Set RECON_UID/RECON_GID "
        "(or run the program without sudo) so artefacts are owned by a regular user."
    )


_DESIRED_OWNER = _determine_owner()


def desired_owner() -> Optional[Tuple[int, int]]:
    """Expose the resolved non-root owner so callers can inspect it."""

    return _DESIRED_OWNER


def _iter_targets(path: Path, *, include_parents: bool) -> Iterable[Path]:
    resolved: Path
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path

    yield path
    if not include_parents:
        return

    repo_root = _REPO_ROOT.resolve()
    try:
        resolved.relative_to(repo_root)
        inside_repo = True
    except ValueError:
        inside_repo = False

    if inside_repo:
        for parent in resolved.parents:
            yield parent
            if parent == repo_root:
                break


def ensure_path_owner(path: _PATH_LIKE, *, parents: bool = False) -> None:
    """Force ``path`` (and optionally its parents) to use the resolved owner."""

    if _DESIRED_OWNER is None:
        return

    candidate = Path(path)
    uid, gid = _DESIRED_OWNER
    for target in _iter_targets(candidate, include_parents=parents):
        try:
            stat_info = target.stat()
        except FileNotFoundError:
            continue

        if stat_info.st_uid == uid and stat_info.st_gid == gid:
            continue

        os.chown(target, uid, gid)


def ensure_tree_owner(path: _PATH_LIKE) -> None:
    """Recursively ensure that ``path`` and its contents use the resolved owner."""

    if _DESIRED_OWNER is None:
        return

    root = Path(path)
    if not root.exists():
        return

    ensure_path_owner(root, parents=True)
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        ensure_path_owner(current)
        for dirname in dirnames:
            ensure_path_owner(current / dirname)
        for filename in filenames:
            ensure_path_owner(current / filename)


__all__ = ["desired_owner", "ensure_path_owner", "ensure_tree_owner"]
