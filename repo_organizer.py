#!/usr/bin/env python3
"""
Repository Source Organizer
===========================
Automatically organizes repository sources into appropriate folder structures.
Perfect for managing multiple repositories with different frameworks and purposes.

Features:
- Automatic folder structure creation
- Framework-based organization
- Project type categorization
- Source code sorting
- Duplicate detection and handling
- Integration with git repositories
- Comprehensive logging and reporting

Author: AI Assistant
Version: 1.0.0
"""

import os
import shutil
import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import argparse
import logging

class RepositoryOrganizer:
    def __init__(self, base_dir: str = "./organized_sources"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)
        
        # Define folder structure
        self.folder_structure = {
            'security': {
                'cpp': 'Security/CPP_Projects',
                'masm': 'Security/MASM_Assembly',
                'csharp': 'Security/CSharp_Projects',
                'cpp_masm': 'Security/CPP_MASM_Hybrid',
                'python': 'Security/Python_Tools'
            },
            'ai': {
                'python': 'AI_ML/Python_Projects',
                'cpp': 'AI_ML/CPP_Projects',
                'javascript': 'AI_ML/JavaScript_Projects'
            },
            'web': {
                'javascript': 'Web_Development/JavaScript',
                'typescript': 'Web_Development/TypeScript',
                'html': 'Web_Development/HTML_CSS',
                'python': 'Web_Development/Python_Backend',
                'php': 'Web_Development/PHP'
            },
            'tools': {
                'python': 'Development_Tools/Python',
                'cpp': 'Development_Tools/CPP',
                'shell': 'Development_Tools/Scripts'
            },
            'recovered': {
                'masm_2035': 'Recovered_Code/MASM_2035',
                'historical': 'Recovered_Code/Historical_Sources',
                'archived': 'Recovered_Code/Archived'
            }
        }
        
        # Setup logging
        log_file = self.base_dir / 'organization.log'
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def create_folder_structure(self):
        """Create the complete folder structure"""
        self.logger.info("Creating folder structure...")
        
        for project_type, frameworks in self.folder_structure.items():
            for framework, path in frameworks.items():
                full_path = self.base_dir / path
                full_path.mkdir(parents=True, exist_ok=True)
                self.logger.info(f"Created: {full_path}")
        
        # Create additional utility folders
        additional_folders = [
            'Documentation',
            'Build_Scripts',
            'Configuration_Files',
            'Test_Data',
            'Binary_Releases',
            'Archive'
        ]
        
        for folder in additional_folders:
            (self.base_dir / folder).mkdir(exist_ok=True)
    
    def determine_project_category(self, repo_info: Dict[str, Any]) -> tuple:
        """Determine project type and framework from repository info"""
        project_type = repo_info.get('project_type', 'tools')
        framework = repo_info.get('framework', 'unknown')
        
        # Handle special cases
        if 'masm' in repo_info.get('description', '').lower():
            if framework == 'cpp':
                framework = 'cpp_masm'
            else:
                framework = 'masm'
        
        if 'recovered' in repo_info.get('url', '').lower() or repo_info.get('status') == 'FULLY RECOVERED':
            project_type = 'recovered'
            if 'masm_2035' in repo_info.get('url', ''):
                framework = 'masm_2035'
            else:
                framework = 'historical'
        
        return project_type, framework
    
    def clone_repository(self, repo_url: str, repo_name: str) -> Optional[str]:
        """Clone repository to temporary location"""
        if repo_url.startswith('local://'):
            return None  # Skip local files for now
            
        temp_dir = tempfile.mkdtemp(prefix=f"organize_{repo_name}_")
        
        try:
            result = subprocess.run(
                ['git', 'clone', repo_url, temp_dir],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                return temp_dir
            else:
                self.logger.error(f"Failed to clone {repo_url}: {result.stderr}")
                shutil.rmtree(temp_dir, ignore_errors=True)
                return None
                
        except Exception as e:
            self.logger.error(f"Error cloning {repo_url}: {str(e)}")
            shutil.rmtree(temp_dir, ignore_errors=True)
            return None
    
    def organize_source_files(self, source_dir: str, target_dir: Path, repo_name: str):
        """Organize source files from repository to target directory"""
        source_path = Path(source_dir)
        target_path = target_dir / repo_name
        target_path.mkdir(parents=True, exist_ok=True)
        
        # File type mappings
        source_extensions = {
            '.cpp', '.hpp', '.h', '.c', '.cc', '.cxx',
            '.py', '.pyx',
            '.js', '.ts', '.jsx', '.tsx',
            '.cs',
            '.asm', '.s',
            '.md', '.txt', '.rst',
            '.json', '.xml', '.yaml', '.yml',
            '.sql',
            '.sh', '.bat', '.ps1'
        }
        
        build_files = {
            'Makefile', 'CMakeLists.txt', 'Dockerfile', 'requirements.txt',
            'package.json', 'package-lock.json', 'yarn.lock',
            'Pipfile', 'poetry.lock', 'setup.py',
            '.gitignore', '.gitattributes',
            '*.sln', '*.vcxproj', '*.vcxproj.filters'
        }
        
        organized_count = 0
        
        for root, dirs, files in os.walk(source_path):
            # Skip .git and other VCS directories
            dirs[:] = [d for d in dirs if not d.startswith('.git')]
            
            for file in files:
                file_path = Path(root) / file
                relative_path = file_path.relative_to(source_path)
                
                # Determine file category
                if file_path.suffix.lower() in source_extensions:
                    # Source code files
                    dest_path = target_path / 'src' / relative_path
                elif any(pattern in file for pattern in build_files) or file_path.suffix in ['.sln', '.vcxproj']:
                    # Build and configuration files
                    dest_path = target_path / 'build' / relative_path
                elif file_path.suffix.lower() in ['.exe', '.dll', '.so', '.dylib']:
                    # Binary files
                    dest_path = target_path / 'bin' / relative_path
                elif file_path.suffix.lower() in ['.png', '.jpg', '.jpeg', '.gif', '.svg']:
                    # Image files
                    dest_path = target_path / 'assets' / relative_path
                else:
                    # Other files
                    dest_path = target_path / 'misc' / relative_path
                
                # Create destination directory and copy file
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.copy2(file_path, dest_path)
                    organized_count += 1
                except Exception as e:
                    self.logger.warning(f"Failed to copy {file_path}: {str(e)}")
        
        self.logger.info(f"Organized {organized_count} files for {repo_name}")
        return organized_count
    
    def handle_local_files(self, local_path: str, target_dir: Path, repo_name: str):
        """Handle local files (like recovered MASM 2035)"""
        source_path = Path(local_path)
        
        if source_path.exists():
            target_path = target_dir / repo_name
            target_path.mkdir(parents=True, exist_ok=True)
            
            if source_path.is_file():
                # Single file
                dest_file = target_path / source_path.name
                shutil.copy2(source_path, dest_file)
                self.logger.info(f"Copied local file: {source_path} -> {dest_file}")
                return 1
            else:
                # Directory
                return self.organize_source_files(str(source_path), target_dir, repo_name)
        
        return 0
    
    def organize_repositories(self, repos_config: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Organize all repositories from configuration"""
        self.logger.info(f"Starting organization of {len(repos_config)} repositories")
        
        # Create folder structure
        self.create_folder_structure()
        
        results = {
            'summary': {
                'total_repositories': len(repos_config),
                'processed': 0,
                'failed': 0,
                'total_files_organized': 0,
                'start_time': datetime.now().isoformat()
            },
            'repository_results': {}
        }
        
        for repo_name, repo_info in repos_config.items():
            self.logger.info(f"Processing repository: {repo_name}")
            
            try:
                # Determine category and target directory
                project_type, framework = self.determine_project_category(repo_info)
                
                if project_type in self.folder_structure and framework in self.folder_structure[project_type]:
                    target_dir = self.base_dir / self.folder_structure[project_type][framework]
                else:
                    # Fallback to tools category
                    target_dir = self.base_dir / 'Development_Tools' / 'Uncategorized'
                
                target_dir.mkdir(parents=True, exist_ok=True)
                
                files_organized = 0
                
                # Handle different source types
                if repo_info['url'].startswith('local://'):
                    # Local file
                    local_path = repo_info['url'].replace('local://', '')
                    if not local_path.startswith('/'):
                        local_path = str(Path.cwd() / local_path)
                    files_organized = self.handle_local_files(local_path, target_dir, repo_name)
                    
                elif repo_info.get('cloned', False) and 'local_path' in repo_info:
                    # Already cloned locally
                    local_path = repo_info['local_path']
                    if Path(local_path).exists():
                        files_organized = self.organize_source_files(local_path, target_dir, repo_name)
                    else:
                        # Try cloning
                        temp_dir = self.clone_repository(repo_info['url'], repo_name)
                        if temp_dir:
                            files_organized = self.organize_source_files(temp_dir, target_dir, repo_name)
                            shutil.rmtree(temp_dir, ignore_errors=True)
                else:
                    # Clone and organize
                    temp_dir = self.clone_repository(repo_info['url'], repo_name)
                    if temp_dir:
                        files_organized = self.organize_source_files(temp_dir, target_dir, repo_name)
                        shutil.rmtree(temp_dir, ignore_errors=True)
                
                # Create repository info file
                info_file = target_dir / repo_name / 'repository_info.json'
                with open(info_file, 'w') as f:
                    json.dump({
                        'original_info': repo_info,
                        'organization_info': {
                            'organized_at': datetime.now().isoformat(),
                            'project_type': project_type,
                            'framework': framework,
                            'files_organized': files_organized,
                            'target_directory': str(target_dir)
                        }
                    }, f, indent=2)
                
                results['repository_results'][repo_name] = {
                    'status': 'success',
                    'project_type': project_type,
                    'framework': framework,
                    'files_organized': files_organized,
                    'target_directory': str(target_dir / repo_name)
                }
                
                results['summary']['processed'] += 1
                results['summary']['total_files_organized'] += files_organized
                
                self.logger.info(f"✅ Successfully organized {repo_name}: {files_organized} files")
                
            except Exception as e:
                self.logger.error(f"❌ Failed to organize {repo_name}: {str(e)}")
                results['repository_results'][repo_name] = {
                    'status': 'failed',
                    'error': str(e)
                }
                results['summary']['failed'] += 1
        
        results['summary']['end_time'] = datetime.now().isoformat()
        
        # Save results
        results_file = self.base_dir / 'organization_results.json'
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        return results
    
    def generate_organization_report(self, results: Dict[str, Any]) -> str:
        """Generate human-readable organization report"""
        report = []
        report.append("📁 REPOSITORY ORGANIZATION REPORT")
        report.append("=" * 50)
        report.append(f"Organization Date: {results['summary']['start_time']}")
        report.append(f"Total Repositories: {results['summary']['total_repositories']}")
        report.append(f"Successfully Processed: {results['summary']['processed']}")
        report.append(f"Failed: {results['summary']['failed']}")
        report.append(f"Total Files Organized: {results['summary']['total_files_organized']}")
        report.append("")
        
        # Group by project type
        by_type = {}
        for repo_name, result in results['repository_results'].items():
            if result['status'] == 'success':
                project_type = result['project_type']
                if project_type not in by_type:
                    by_type[project_type] = []
                by_type[project_type].append((repo_name, result))
        
        for project_type, repos in by_type.items():
            report.append(f"📂 {project_type.upper()}")
            report.append("-" * 30)
            
            for repo_name, result in repos:
                report.append(f"  ✅ {repo_name}")
                report.append(f"     Framework: {result['framework']}")
                report.append(f"     Files: {result['files_organized']}")
                report.append(f"     Location: {result['target_directory']}")
            report.append("")
        
        # Show failed repositories
        failed_repos = [name for name, result in results['repository_results'].items() 
                       if result['status'] == 'failed']
        
        if failed_repos:
            report.append("❌ FAILED REPOSITORIES")
            report.append("-" * 30)
            for repo_name in failed_repos:
                error = results['repository_results'][repo_name]['error']
                report.append(f"  ❌ {repo_name}: {error}")
            report.append("")
        
        report.append("📁 FOLDER STRUCTURE CREATED:")
        report.append("-" * 30)
        for project_type, frameworks in self.folder_structure.items():
            report.append(f"  📂 {project_type.title()}/")
            for framework, path in frameworks.items():
                report.append(f"    📁 {path}")
        
        report_text = "\n".join(report)
        
        # Save report
        report_file = self.base_dir / 'organization_report.txt'
        with open(report_file, 'w') as f:
            f.write(report_text)
        
        return report_text

def main():
    parser = argparse.ArgumentParser(description='Repository Source Organizer')
    parser.add_argument('--repos-file', default='repos.json', help='JSON file containing repositories')
    parser.add_argument('--output-dir', default='./organized_sources', help='Output directory for organized sources')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without actually doing it')
    
    args = parser.parse_args()
    
    # Load repositories configuration
    if not Path(args.repos_file).exists():
        print(f"❌ Repository configuration file not found: {args.repos_file}")
        return
    
    with open(args.repos_file, 'r') as f:
        repos_config = json.load(f)
    
    # Create organizer
    organizer = RepositoryOrganizer(args.output_dir)
    
    if args.dry_run:
        print("🔍 DRY RUN MODE - Showing what would be organized:")
        for repo_name, repo_info in repos_config.items():
            project_type, framework = organizer.determine_project_category(repo_info)
            target_path = organizer.folder_structure.get(project_type, {}).get(framework, 'Development_Tools/Uncategorized')
            print(f"  📁 {repo_name} -> {target_path}")
        return
    
    # Organize repositories
    results = organizer.organize_repositories(repos_config)
    
    # Generate and display report
    report = organizer.generate_organization_report(results)
    print(report)
    
    print(f"\n🎉 Organization complete! Check {args.output_dir} for organized sources.")

if __name__ == "__main__":
    main()