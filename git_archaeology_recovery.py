#!/usr/bin/env python3
"""
Git Archaeology Recovery Tool
=============================
Comprehensive script for recovering lost code from git history across multiple repositories.
Perfect for finding deleted files, lost branches, and recovering valuable source code.

Features:
- Multi-repository scanning
- Deleted file recovery
- Branch archaeology
- Commit history analysis
- MASM/Assembly code detection
- Advanced pattern matching
- Recovery reporting

Author: AI Assistant
Version: 1.0.0
"""

import os
import subprocess
import json
import re
import tempfile
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import argparse
import logging

class GitArchaeologyRecovery:
    def __init__(self, output_dir: str = "./recovered_code"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.recovery_log = []
        self.found_items = []
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.output_dir / 'recovery.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def run_git_command(self, command: List[str], repo_path: str) -> Tuple[bool, str]:
        """Execute git command in specified repository"""
        try:
            result = subprocess.run(
                ['git'] + command,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0, result.stdout if result.returncode == 0 else result.stderr
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)
    
    def clone_repository(self, repo_url: str, local_name: str) -> Optional[str]:
        """Clone repository for analysis"""
        temp_dir = tempfile.mkdtemp(prefix=f"recovery_{local_name}_")
        
        self.logger.info(f"Cloning {repo_url} to {temp_dir}")
        
        success, output = self.run_git_command(['clone', repo_url, temp_dir], '.')
        if success:
            return temp_dir
        else:
            self.logger.error(f"Failed to clone {repo_url}: {output}")
            shutil.rmtree(temp_dir, ignore_errors=True)
            return None
    
    def get_all_commits(self, repo_path: str) -> List[str]:
        """Get all commit hashes from repository"""
        success, output = self.run_git_command(['log', '--all', '--format=%H'], repo_path)
        if success:
            return [line.strip() for line in output.split('\n') if line.strip()]
        return []
    
    def get_all_branches(self, repo_path: str) -> List[str]:
        """Get all branches including remote branches"""
        success, output = self.run_git_command(['branch', '-a'], repo_path)
        if success:
            branches = []
            for line in output.split('\n'):
                line = line.strip()
                if line and not line.startswith('*'):
                    # Clean branch name
                    branch = line.replace('remotes/origin/', '').replace('remotes/', '')
                    if branch not in branches and branch != 'HEAD':
                        branches.append(branch)
            return branches
        return []
    
    def search_deleted_files(self, repo_path: str) -> List[Dict[str, Any]]:
        """Find deleted files in git history"""
        self.logger.info("Searching for deleted files...")
        deleted_files = []
        
        # Find all deleted files
        success, output = self.run_git_command(['log', '--diff-filter=D', '--summary', '--all'], repo_path)
        if success:
            lines = output.split('\n')
            for line in lines:
                if 'delete mode' in line:
                    # Extract filename
                    parts = line.split()
                    if len(parts) >= 3:
                        filename = parts[-1]
                        deleted_files.append({
                            'filename': filename,
                            'type': 'deleted_file',
                            'path': filename
                        })
        
        return deleted_files
    
    def search_for_patterns(self, repo_path: str, patterns: List[str]) -> List[Dict[str, Any]]:
        """Search for specific patterns in git history"""
        found_items = []
        
        for pattern in patterns:
            self.logger.info(f"Searching for pattern: {pattern}")
            
            # Search in current files
            success, output = self.run_git_command(['grep', '-r', '-i', pattern], repo_path)
            if success:
                for line in output.split('\n'):
                    if line.strip():
                        found_items.append({
                            'type': 'current_match',
                            'pattern': pattern,
                            'line': line.strip(),
                            'context': 'current_files'
                        })
            
            # Search in git history
            success, output = self.run_git_command(['log', '-S', pattern, '--all', '--oneline'], repo_path)
            if success:
                for line in output.split('\n'):
                    if line.strip():
                        found_items.append({
                            'type': 'history_match',
                            'pattern': pattern,
                            'commit': line.strip(),
                            'context': 'git_history'
                        })
        
        return found_items
    
    def recover_file_from_commit(self, repo_path: str, commit_hash: str, file_path: str) -> Optional[str]:
        """Recover specific file from specific commit"""
        try:
            success, content = self.run_git_command(['show', f'{commit_hash}:{file_path}'], repo_path)
            if success:
                return content
        except:
            pass
        return None
    
    def analyze_large_deletions(self, repo_path: str) -> List[Dict[str, Any]]:
        """Find commits with large deletions (potential code loss)"""
        self.logger.info("Analyzing commits with large deletions...")
        large_deletions = []
        
        success, output = self.run_git_command(['log', '--stat', '--all', '--format=%H|%s|%ad'], repo_path)
        if success:
            current_commit = None
            current_subject = None
            current_date = None
            deletions = 0
            
            for line in output.split('\n'):
                if '|' in line and 'deletions' not in line and 'insertions' not in line:
                    # New commit line
                    parts = line.split('|')
                    if len(parts) >= 3:
                        current_commit = parts[0]
                        current_subject = parts[1]
                        current_date = parts[2]
                        deletions = 0
                elif 'deletion' in line:
                    # Count deletions
                    match = re.search(r'(\d+) deletion', line)
                    if match:
                        deletions += int(match.group(1))
                elif line.strip() == '' and current_commit and deletions > 50:
                    # End of commit stats, check if significant deletions
                    large_deletions.append({
                        'commit': current_commit,
                        'subject': current_subject,
                        'date': current_date,
                        'deletions': deletions,
                        'type': 'large_deletion'
                    })
        
        return large_deletions
    
    def search_for_masm_code(self, repo_path: str) -> List[Dict[str, Any]]:
        """Specifically search for MASM/Assembly code patterns"""
        masm_patterns = [
            'UniqueStub71',
            'MASM',
            '.asm',
            'Microsoft Macro Assembler',
            'mutex.*system',
            'company.*profile.*spoofing',
            'exploit.*method',
            'anti.*analysis',
            'polymorphic.*code',
            'stub.*generator',
            'BenignPacker',
            '40.*mutex',
            '18.*exploit',
            'UAC.*bypass',
            'privilege.*escalation',
            'process.*injection',
            'debugger.*detection',
            'VM.*detection',
            'sandbox.*detection',
            'certificate.*chain',
            'Visual Studio 2022',
            'UNIQUE_STUB_71',
            'IStubGenerator',
            'namespace BenignPacker',
            'CompanyProfile.*Microsoft',
            'CompanyProfile.*Adobe',
            'CompanyProfile.*Google',
            'CompanyProfile.*NVIDIA',
            'CompanyProfile.*Intel'
        ]
        
        return self.search_for_patterns(repo_path, masm_patterns)
    
    def comprehensive_repository_scan(self, repo_url: str, repo_name: str) -> Dict[str, Any]:
        """Perform comprehensive scan of a single repository"""
        self.logger.info(f"🔍 Starting comprehensive scan of {repo_name}")
        
        # Clone repository
        repo_path = self.clone_repository(repo_url, repo_name)
        if not repo_path:
            return {'error': 'Failed to clone repository'}
        
        try:
            scan_results = {
                'repository': repo_name,
                'url': repo_url,
                'scan_timestamp': datetime.now().isoformat(),
                'commits': [],
                'branches': [],
                'deleted_files': [],
                'masm_matches': [],
                'large_deletions': [],
                'recovered_files': []
            }
            
            # Get all commits and branches
            scan_results['commits'] = self.get_all_commits(repo_path)
            scan_results['branches'] = self.get_all_branches(repo_path)
            
            self.logger.info(f"Found {len(scan_results['commits'])} commits and {len(scan_results['branches'])} branches")
            
            # Search for deleted files
            scan_results['deleted_files'] = self.search_deleted_files(repo_path)
            
            # Search for MASM code
            scan_results['masm_matches'] = self.search_for_masm_code(repo_path)
            
            # Analyze large deletions
            scan_results['large_deletions'] = self.analyze_large_deletions(repo_path)
            
            # Try to recover interesting files
            interesting_files = [
                'UniqueStub71Plugin.h',
                'UniqueStub71Plugin.cpp',
                'masm_2035.asm',
                'stub_generator.h',
                'benign_packer.h',
                'company_profiles.h',
                'mutex_systems.h',
                'exploit_methods.h'
            ]
            
            for commit in scan_results['commits'][:20]:  # Check recent commits
                for file_path in interesting_files:
                    content = self.recover_file_from_commit(repo_path, commit, file_path)
                    if content and len(content) > 100:  # Found substantial content
                        recovery_path = self.output_dir / f"{repo_name}_{commit[:8]}_{Path(file_path).name}"
                        with open(recovery_path, 'w', encoding='utf-8') as f:
                            f.write(content)
                        
                        scan_results['recovered_files'].append({
                            'file': file_path,
                            'commit': commit,
                            'size': len(content),
                            'recovered_to': str(recovery_path)
                        })
                        
                        self.logger.info(f"✅ Recovered {file_path} from commit {commit[:8]}")
            
            return scan_results
            
        finally:
            # Cleanup
            shutil.rmtree(repo_path, ignore_errors=True)
    
    def scan_multiple_repositories(self, repositories: List[Dict[str, str]]) -> Dict[str, Any]:
        """Scan multiple repositories for lost code"""
        self.logger.info(f"🚀 Starting multi-repository scan of {len(repositories)} repositories")
        
        all_results = {
            'scan_summary': {
                'total_repositories': len(repositories),
                'start_time': datetime.now().isoformat(),
                'repositories_scanned': 0,
                'total_recovered_files': 0,
                'total_masm_matches': 0
            },
            'repository_results': {}
        }
        
        for repo in repositories:
            repo_name = repo['name']
            repo_url = repo['url']
            
            try:
                results = self.comprehensive_repository_scan(repo_url, repo_name)
                all_results['repository_results'][repo_name] = results
                all_results['scan_summary']['repositories_scanned'] += 1
                
                if 'recovered_files' in results:
                    all_results['scan_summary']['total_recovered_files'] += len(results['recovered_files'])
                if 'masm_matches' in results:
                    all_results['scan_summary']['total_masm_matches'] += len(results['masm_matches'])
                    
            except Exception as e:
                self.logger.error(f"❌ Error scanning {repo_name}: {str(e)}")
                all_results['repository_results'][repo_name] = {'error': str(e)}
        
        all_results['scan_summary']['end_time'] = datetime.now().isoformat()
        
        # Save comprehensive results
        results_file = self.output_dir / 'comprehensive_scan_results.json'
        with open(results_file, 'w') as f:
            json.dump(all_results, f, indent=2)
        
        self.logger.info(f"📊 Scan complete! Results saved to {results_file}")
        return all_results
    
    def generate_recovery_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate human-readable recovery report"""
        report = []
        report.append("🎯 GIT ARCHAEOLOGY RECOVERY REPORT")
        report.append("=" * 50)
        report.append(f"Scan Date: {scan_results['scan_summary']['start_time']}")
        report.append(f"Repositories Scanned: {scan_results['scan_summary']['repositories_scanned']}")
        report.append(f"Total Recovered Files: {scan_results['scan_summary']['total_recovered_files']}")
        report.append(f"Total MASM Matches: {scan_results['scan_summary']['total_masm_matches']}")
        report.append("")
        
        for repo_name, results in scan_results['repository_results'].items():
            if 'error' in results:
                report.append(f"❌ {repo_name}: {results['error']}")
                continue
                
            report.append(f"📁 {repo_name.upper()}")
            report.append("-" * 30)
            report.append(f"   Commits: {len(results.get('commits', []))}")
            report.append(f"   Branches: {len(results.get('branches', []))}")
            report.append(f"   Deleted Files: {len(results.get('deleted_files', []))}")
            report.append(f"   MASM Matches: {len(results.get('masm_matches', []))}")
            report.append(f"   Recovered Files: {len(results.get('recovered_files', []))}")
            
            # Show recovered files
            for recovered in results.get('recovered_files', []):
                report.append(f"      ✅ {recovered['file']} ({recovered['size']} bytes) from {recovered['commit'][:8]}")
            
            # Show MASM matches
            for match in results.get('masm_matches', [])[:5]:  # Show first 5
                if match['type'] == 'history_match':
                    report.append(f"      🔍 MASM: {match['pattern']} in {match['commit']}")
            
            report.append("")
        
        report_text = "\n".join(report)
        
        # Save report
        report_file = self.output_dir / 'recovery_report.txt'
        with open(report_file, 'w') as f:
            f.write(report_text)
        
        return report_text

def main():
    parser = argparse.ArgumentParser(description='Git Archaeology Recovery Tool')
    parser.add_argument('--repos-file', help='JSON file containing repositories to scan')
    parser.add_argument('--single-repo', help='Single repository URL to scan')
    parser.add_argument('--output-dir', default='./recovered_code', help='Output directory for recovered files')
    parser.add_argument('--search-pattern', action='append', help='Additional search patterns')
    
    args = parser.parse_args()
    
    recovery_tool = GitArchaeologyRecovery(args.output_dir)
    
    repositories = []
    
    if args.repos_file:
        with open(args.repos_file, 'r') as f:
            repos_data = json.load(f)
            for name, info in repos_data.items():
                repositories.append({
                    'name': name,
                    'url': info['url']
                })
    elif args.single_repo:
        repositories.append({
            'name': 'single_repo',
            'url': args.single_repo
        })
    else:
        # Default repositories for MASM 2035 recovery
        repositories = [
            {'name': 'burp', 'url': 'https://github.com/ItsMehRAWRXD/Burp'},
            {'name': 'vs2022-packer', 'url': 'https://github.com/ItsMehRAWRXD/vs2022-universal-pe-packer'},
            {'name': 'hm-pe-packer', 'url': 'https://github.com/TheAenema/hm-pe-packer'},
            {'name': 'evader', 'url': 'https://github.com/KooroshRZ/Evader'},
            {'name': 'pe-packer', 'url': 'https://github.com/NullArray/PE-Packer'}
        ]
    
    # Run comprehensive scan
    results = recovery_tool.scan_multiple_repositories(repositories)
    
    # Generate report
    report = recovery_tool.generate_recovery_report(results)
    print(report)
    
    print(f"\n🎉 Recovery complete! Check {args.output_dir} for recovered files.")

if __name__ == "__main__":
    main()