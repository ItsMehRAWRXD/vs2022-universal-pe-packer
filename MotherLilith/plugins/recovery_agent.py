#!/usr/bin/env python3
import os
import sys
import subprocess
import argparse
import hashlib
from pathlib import Path

# Utility: Calculate file checksum
def file_checksum(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

# Detect missing or corrupted files (by comparing to git)
def detect_issues(repo_path, known_checksums=None):
    os.chdir(repo_path)
    # Get list of tracked files
    result = subprocess.run(["git", "ls-files"], capture_output=True, text=True)
    tracked_files = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    issues = []
    for f in tracked_files:
        p = Path(repo_path) / f
        if not p.exists():
            issues.append({'file': f, 'issue': 'missing'})
        elif known_checksums:
            cs = file_checksum(p)
            if f in known_checksums and cs != known_checksums[f]:
                issues.append({'file': f, 'issue': 'corrupted'})
    return issues

# Recover file from git (latest, commit, or branch)
def recover_file(repo_path, file, commit=None):
    os.chdir(repo_path)
    if commit:
        subprocess.run(["git", "checkout", commit, "--", file])
    else:
        subprocess.run(["git", "checkout", "--", file])

# Attempt recovery from forks (placeholder)
def recover_from_forks(repo_url, file):
    print(f"[TODO] Attempting recovery from forks for {file} in {repo_url}")
    # This would use GitHub API to find forks and try to recover the file
    return False

def main():
    parser = argparse.ArgumentParser(description="Mother Lilith GitHub Recovery Agent")
    parser.add_argument("repo", help="Path to the local git repo")
    parser.add_argument("--commit", help="Recover from specific commit or branch")
    parser.add_argument("--fallback-forks", action="store_true", help="Attempt recovery from forks if main repo fails")
    args = parser.parse_args()

    issues = detect_issues(args.repo)
    if not issues:
        print("No missing or corrupted files detected.")
        return
    print(f"Detected issues: {issues}")
    for issue in issues:
        file = issue['file']
        print(f"Recovering {file}...")
        try:
            recover_file(args.repo, file, commit=args.commit)
            print(f"Recovered {file} from main repo.")
        except Exception as e:
            print(f"Failed to recover {file} from main repo: {e}")
            if args.fallback_forks:
                # Placeholder: repo_url would be needed
                recovered = recover_from_forks("<repo_url>", file)
                if recovered:
                    print(f"Recovered {file} from a fork.")
                else:
                    print(f"Failed to recover {file} from forks.")
    print("[Recovery complete]")

if __name__ == "__main__":
    main()