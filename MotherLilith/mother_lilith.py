import os
import sys
import subprocess
import argparse
from pathlib import Path

REPOS_DIR = Path(__file__).parent / "repos"
REPOS_DIR.mkdir(exist_ok=True)

REPO_LIST_FILE = Path(__file__).parent / "repos.txt"

def save_repo(url):
    with open(REPO_LIST_FILE, 'a') as f:
        f.write(url + '\n')

def load_repos():
    if not REPO_LIST_FILE.exists():
        return []
    with open(REPO_LIST_FILE, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def add_repo(url):
    repo_name = url.rstrip('/').split('/')[-1].replace('.git', '')
    dest = REPOS_DIR / repo_name
    if dest.exists():
        print(f"Repo {repo_name} already exists.")
        return
    print(f"Cloning {url} into {dest}...")
    subprocess.run(["git", "clone", url, str(dest)])
    save_repo(url)
    print(f"Added {repo_name}.")

def list_repos():
    repos = load_repos()
    if not repos:
        print("No repos added yet.")
        return
    print("Managed repos:")
    for url in repos:
        print(f"- {url}")

def remove_repo(url):
    repos = load_repos()
    if url not in repos:
        print("Repo not found in list.")
        return
    repo_name = url.rstrip('/').split('/')[-1].replace('.git', '')
    dest = REPOS_DIR / repo_name
    if dest.exists():
        subprocess.run(["rm", "-rf", str(dest)])
    with open(REPO_LIST_FILE, 'w') as f:
        for r in repos:
            if r != url:
                f.write(r + '\n')
    print(f"Removed {repo_name}.")

def main():
    parser = argparse.ArgumentParser(description="Mother Lilith - Sploit Bank Co-Pilot")
    subparsers = parser.add_subparsers(dest="command")

    add_parser = subparsers.add_parser("add", help="Add a GitHub repo by URL")
    add_parser.add_argument("url", help="GitHub repo URL")

    list_parser = subparsers.add_parser("list", help="List managed repos")

    remove_parser = subparsers.add_parser("remove", help="Remove a repo by URL")
    remove_parser.add_argument("url", help="GitHub repo URL")

    args = parser.parse_args()

    if args.command == "add":
        add_repo(args.url)
    elif args.command == "list":
        list_repos()
    elif args.command == "remove":
        remove_repo(args.url)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()