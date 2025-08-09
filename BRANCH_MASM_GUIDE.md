# Enhanced Branch and MASM Support Guide

## Overview

The VS2022 Menu Encryptor now includes comprehensive support for:
- **ALL branches** in every repository
- **Full MASM projects** with special handling
- **Complete archival** of all handmade work
- **Automatic detection** of renamed/forked content

## Quick Start for ItsMehRAWRXD Repositories

### Option 20: Quick Add Your Repositories

This single option will:
1. Add all 4 of your main repositories:
   - Star
   - Burp
   - RawrXD
   - vs2022-universal-pe-packer

2. Automatically discover ALL branches in each repository
3. Detect and flag MASM projects
4. Set up for complete archival of all your handmade work

```
Select option: 20
Also scan your GitHub profile? y
```

## Branch-Aware Features

### Option 21: Pack Files from ALL Branches

This powerful feature will:
- Switch to EVERY branch in EVERY repository
- Pack files from each branch with unique naming
- Preserve branch-specific variations
- Handle renamed/forked content

Example workflow:
```
Select option: 21
[Automatically processes all branches]
```

### Option 22: Archive Complete Repositories

Creates comprehensive archives including:
- Every single branch
- All MASM projects
- All variations and renames
- Complete preservation of your handmade work

### Option 23: Scan for MASM Projects

Specifically searches for MASM projects across all branches:
- Detects .asm, .ASM, .inc, .INC files
- Finds MASM references in project files
- Counts total MASM files across all branches
- Offers to pack all MASM projects immediately

## MASM Project Handling

The tool now has special support for MASM projects:

1. **Auto-detection**: Scans for MASM files and project configurations
2. **Branch awareness**: Checks every branch for MASM content
3. **Special packaging**: Groups MASM files together
4. **Project preservation**: Maintains project structure

### Supported MASM Files:
- `.asm` / `.ASM` - Assembly source files
- `.inc` / `.INC` - Include files
- `.s` / `.S` - Assembly files
- Project files with MASM references (ml64.exe, ml.exe)

## Complete Workflow Example

1. **Add your repositories**:
   ```
   Option 20 → Quick add all ItsMehRAWRXD repos
   ```

2. **Scan for MASM projects**:
   ```
   Option 23 → Scan all branches for MASM content
   ```

3. **Pack everything from all branches**:
   ```
   Option 21 → Pack files from ALL branches
   ```

4. **Create complete archives**:
   ```
   Option 22 → Archive everything for backup
   ```

## File Naming Convention

When packing from multiple branches, files are named:
```
{RepositoryName}_{BranchName}_{OriginalFileName}
```

For MASM projects:
```
{RepositoryName}_{BranchName}_MASM_project.cpp
```

## Advanced Features

### Branch Discovery
- Automatically finds all remote branches
- No manual branch switching needed
- Processes branches sequentially

### Duplicate Detection
- Handles renamed projects across branches
- Preserves all variations
- No content is lost

### Comprehensive Archival
- Creates encrypted mega-archives
- Includes complete repository history
- Perfect for backup and preservation

## Tips

1. **Initial Setup**: Use option 20 first to quickly add all your repos
2. **Regular Backups**: Use option 22 periodically for complete backups
3. **MASM Focus**: Use option 23 if you specifically need MASM projects
4. **Branch Updates**: The tool automatically discovers new branches

## Security

- All files are encrypted with your choice of:
  - AES (Fast)
  - ChaCha20 (Modern)
  - Triple (Maximum security for sensitive content)
- MASM projects default to Triple encryption
- Branch names are preserved in encrypted filenames

This enhanced system ensures that EVERY piece of your handmade work across ALL branches is captured, encrypted, and preserved!