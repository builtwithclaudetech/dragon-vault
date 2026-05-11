#!/usr/bin/env python3
"""PII scrubbing script for Dragon Vault open-source release.
Run against a copy of the source tree before publishing.
"""

import argparse
import glob
import os
import re
import sys
from pathlib import Path
from typing import List, Tuple

# Maps of [pattern, replacement] — applied in order.
# Patterns are case-sensitive. Use regex escaping where needed.
REPLACEMENTS: List[Tuple[str, str]] = [
    # --- IP addresses ---
    ("2\\.24\\.65\\.225", "YOUR-SERVER-IP"),
    ("66\\.55\\.64\\.202", "YOUR-OLD-SERVER-IP"),
    # --- Domains ---
    ("pwm\\.2\\.24\\.65\\.225\\.nip\\.io", "pwm.example.com"),
    ("pwm\\.66\\.55\\.64\\.202\\.nip\\.io", "pwm.example.com"),
    # --- Email ---
    ("piercephilip981@gmail\\.com", "user@example.com"),
    # --- SQL password ---
    ("CHANGE_ME", "CHANGE_ME"),
    # --- Names ---
    ("the project maintainer", "the project maintainer"),
    ("the maintainer", "the maintainer"),
    # --- GitHub username ---
    ("builtwithclaudetech", "builtwithclaudetech"),
    # --- Company / project cross-references ---
    ("a prior project", "a prior project"),
    ("a prior project", "a prior project"),
    # --- Filesystem paths ---
    ("/path/to/dragon-vault", "/path/to/dragon-vault"),
    ("/srv/Documents/Claude\\\\ Projects/Password\\\\ Manager", "/path/to/dragon-vault"),
    ("C:\\\\Users\\\\Administrator\\\\Documents\\\\Claude Projects\\\\Password Manager",
     "C:\\\\path\\\\to\\\\dragon-vault"),
    ("/var/opt/dragonvault", "/var/opt/dragonvault"),  # keep -- generic enough
    # --- Linux username ---
    ("YOUR-USERNAME", "YOUR-USERNAME"),
    # --- Company name in docs ---
    ("the Dragon Vault project", "the Dragon Vault project"),
    ("dragonvault-dev", "dragonvault-dev"),  # keep -- UserSecretsId
]

# Files to skip entirely (binary, vendor, generated)
SKIP_PATTERNS = [
    "*.woff2", "*.png", "*.ico", "*.bak", "*.gz", "*.br",
    "*hash-wasm.umd.min.js", "*zxcvbn.js",
    "*.min.js", "*.min.css",
    "*/obj/*", "*/bin/*", "*/.git/*",
    "*appsettings.Development.json",  # in .gitignore, shouldn't be in public repo
    "*appsettings.Production.json",   # in .gitignore
    "*.env",
]

# Files that should be excluded from public repo entirely
EXCLUDE_FROM_PUBLIC = [
    "docs/design.md",
    "docs/requirements.md",
    "docs/build-progress.md",
    "docs/hosting-linux.md",
    "docs/dr-runbook-linux.md",
    "docs/runbook.md",
    "docs/tasklist.md",
    "docs/visual-design.md",
    "docs/handoff.md",
    "DESIGN.md",
    ".claude/",
    "assets/",
    "deploy/migrations/",
    "wwwroot/icons/*.prompt.json",
    "wwwroot/icons/*.prompt.json.br",
    "wwwroot/icons/*.prompt.json.gz",
]


def should_skip(filepath: str) -> bool:
    """Return True if this file should be skipped entirely."""
    rel = filepath
    for pattern in SKIP_PATTERNS:
        if Path(rel).match(pattern):
            return True
    return False


def should_exclude(filepath: str) -> bool:
    """Return True if this file should NOT be in the public repo at all."""
    for pattern in EXCLUDE_FROM_PUBLIC:
        if pattern.endswith("/"):
            if filepath.startswith(pattern) or filepath.startswith(pattern.rstrip("/")):
                return True
        elif Path(filepath).match(pattern):
            return True
    return False


def scrub_content(content: str) -> Tuple[str, int]:
    """Apply all replacements. Returns (scrubbed_content, change_count)."""
    changes = 0
    for pattern, replacement in REPLACEMENTS:
        new_content, n = re.subn(pattern, replacement, content)
        if n > 0:
            changes += n
            content = new_content
    return content, changes


def scrub_file(filepath: str, dry_run: bool = False) -> bool:
    """Scrub a single file. Returns True if changes were made."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            original = f.read()
    except (UnicodeDecodeError, PermissionError):
        print(f"  SKIP (binary/permission): {filepath}")
        return False

    scrubbed, changes = scrub_content(original)
    if changes > 0 and not dry_run:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(scrubbed)
        print(f"  SCRUBBED ({changes} changes): {filepath}")
    elif changes > 0:
        print(f"  WOULD SCRUB ({changes} changes): {filepath}")
    return changes > 0


def main():
    parser = argparse.ArgumentParser(description="Scrub PII from Dragon Vault source")
    parser.add_argument("root", help="Root directory to scrub")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report what would change without making changes")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    if not root.exists():
        print(f"ERROR: {root} does not exist")
        sys.exit(1)

    total_files = 0
    total_changes = 0
    excluded_files = []

    for dirpath, dirnames, filenames in os.walk(root):
        # Skip excluded directories
        dirnames[:] = [d for d in dirnames if d not in (".git", "obj", "bin", "node_modules")]

        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            relpath = os.path.relpath(filepath, root)

            if should_skip(relpath):
                continue

            if should_exclude(relpath):
                excluded_files.append(relpath)
                continue

            total_files += 1
            if scrub_file(filepath, args.dry_run):
                total_changes += 1

    print(f"\n=== Scrub Summary ===")
    print(f"Files scanned: {total_files}")
    print(f"Files with changes: {total_changes}")
    print(f"Files excluded from public repo: {len(excluded_files)}")
    if excluded_files:
        print(f"\nExcluded files (not for public repo):")
        for f in excluded_files:
            print(f"  {f}")
    print(f"\nMode: {'DRY RUN' if args.dry_run else 'LIVE'}")

    if args.dry_run:
        print("Run without --dry-run to apply changes.")


if __name__ == "__main__":
    main()
