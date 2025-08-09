#!/usr/bin/env python3
"""
MASM 2035 Weaponized Framework - Download Script
Downloads all files from the mRAWR repository
"""

import os
import sys
import requests
import json

def download_masm_2035():
    """Download MASM 2035 weaponized files from GitHub"""
    
    print("🚀 MASM 2035 Weaponized Framework - Downloader")
    print("=" * 50)
    
    # GitHub repository details
    repo_owner = "ItsMehRAWRXD"
    repo_name = "mRAWR"
    branch = "main"
    
    # Files to download
    files_to_download = [
        "MASM_2035_WEAPONIZED_COMPLETE.asm",
        "build_mingw_masm_2035.bat", 
        "README.md"
    ]
    
    base_url = f"https://raw.githubusercontent.com/{repo_owner}/{repo_name}/{branch}/"
    
    print(f"📥 Downloading from: https://github.com/{repo_owner}/{repo_name}")
    print()
    
    for filename in files_to_download:
        try:
            print(f"⬇️  Downloading {filename}...")
            
            # Download file
            url = base_url + filename
            response = requests.get(url)
            response.raise_for_status()
            
            # Save file
            with open(filename, 'wb') as f:
                f.write(response.content)
            
            file_size = len(response.content)
            print(f"✅ {filename} ({file_size:,} bytes)")
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Failed to download {filename}: {e}")
        except Exception as e:
            print(f"❌ Error saving {filename}: {e}")
    
    print()
    print("🎯 Download completed!")
    print()
    print("📁 Downloaded files:")
    for filename in files_to_download:
        if os.path.exists(filename):
            size = os.path.getsize(filename)
            print(f"   ✓ {filename} ({size:,} bytes)")
    
    print()
    print("🔧 Next steps:")
    print("   1. Install NASM: https://www.nasm.us/")
    print("   2. Run: build_mingw_masm_2035.bat")
    print("   3. Get: masm_2035_weaponized.exe")
    print()
    print("🚨 Security Notice:")
    print("   This contains real working exploits for authorized testing only!")

if __name__ == "__main__":
    try:
        download_masm_2035()
    except KeyboardInterrupt:
        print("\n❌ Download cancelled by user")
    except Exception as e:
        print(f"❌ Download failed: {e}")