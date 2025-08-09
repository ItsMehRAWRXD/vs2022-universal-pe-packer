# Repository Management Guide for VS2022 Menu Encryptor

## Overview

The VS2022 Menu Encryptor now includes comprehensive repository management features that allow you to integrate and work with any number of repositories. This is perfect for managing multiple projects, libraries, and tools in one centralized location.

## Features

### 1. Unlimited Repository Support
- Initially configured for 4 repositories
- Dynamically expandable to support any number of repositories
- Each repository can be individually configured

### 2. Repository Configuration Options

#### Option 16: Configure Repositories
- **Configure existing slots**: Set up your repository details
- **Add more slots**: Expand beyond the initial 4 repositories
- **Import from file**: Bulk import repositories from a list
- **Clone from remote**: Add repositories by URL

### 3. Repository Operations

#### Option 17: Sync All Repositories
- Automatically clones repositories that don't exist locally
- Pulls latest changes for existing repositories
- Works with Git repositories from any source (GitHub, GitLab, Bitbucket, etc.)

#### Option 18: Pack Files from All Repositories
- Search for specific file patterns across all repositories
- Pack matching files with your choice of encryption:
  - AES Encryption
  - ChaCha20 Encryption
  - Triple Encryption (Maximum Security)
- Batch process files from multiple repositories at once

#### Option 19: Repository Status
- View all configured repositories
- Check clone status
- See file counts
- Monitor active/inactive repositories

## Quick Start

### Method 1: Manual Configuration
1. Run the program and select option 16
2. Choose "Configure existing 4 repository slots"
3. For each repository, enter:
   - Name: A friendly name for the repository
   - URL: The Git URL or local path
   - Branch: The branch to track (default: main)
   - Local path: Where to clone it (auto-generated if left empty)
   - Description: A brief description

### Method 2: Import from File
1. Create a repository list file (see `sample_repos.txt`)
2. Run the program and select option 16
3. Choose "Import repositories from file"
4. Enter the path to your repository list

### Method 3: Clone Multiple Repositories
1. Run the program and select option 16
2. Choose "Clone repositories from GitHub/GitLab/Bitbucket"
3. Enter repository URLs one per line
4. Press Enter on an empty line to finish

## Repository List File Format

```
# Comments start with #
name,url,branch,description
example-repo,https://github.com/user/repo.git,main,Example repository
local-project,/path/to/local/repo,develop,Local development project
```

## Use Cases

### 1. Security Tool Collection
Import multiple security tools and pack their executables with encryption for distribution or analysis.

### 2. Library Management
Keep all your encryption libraries, compression tools, and dependencies in sync.

### 3. Project Distribution
Pack all executables from multiple projects with consistent encryption settings.

### 4. Development Workflow
- Sync all your development tools and libraries
- Pack debug/release builds from multiple projects
- Maintain consistent encryption across all outputs

## Example Workflow

1. Import repositories from `sample_repos.txt`:
   ```
   Select option 16 → 3 → Enter: sample_repos.txt
   ```

2. Sync all repositories:
   ```
   Select option 17
   ```

3. Pack all executables with Triple encryption:
   ```
   Select option 18 → 3 → Enter pattern: *.exe
   ```

4. Check status:
   ```
   Select option 19
   ```

## Tips

- The tool supports local paths as well as remote Git URLs
- You can mix different repository sources (GitHub, GitLab, local paths)
- Use wildcard patterns to pack specific file types (*.exe, *.dll, *.so)
- The tool preserves the original files and creates packed versions
- Repository data is stored in memory; consider saving your repository list for reuse

## Advanced Features

- **Batch Operations**: Process hundreds of files across dozens of repositories
- **Pattern Matching**: Use wildcards to select specific file types
- **Mixed Sources**: Combine local and remote repositories
- **Flexible Structure**: No limit on the number of repositories you can manage

This repository management system turns the VS2022 Menu Encryptor into a powerful multi-repository encryption and packing hub!