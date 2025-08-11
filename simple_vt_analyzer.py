#!/usr/bin/env python3
"""
Simple VirusTotal URL Analyzer
Extracts file hashes and basic information from VirusTotal URLs without external dependencies.
"""

import re
import json
import urllib.request
import urllib.parse
from typing import List, Dict

def extract_file_hash(url: str) -> str:
    """Extract file hash from VirusTotal URL."""
    # Pattern for VT URLs
    pattern = r'/file/([a-f0-9]{64})'
    match = re.search(pattern, url)
    if match:
        return match.group(1)
    return None

def analyze_urls(urls: List[str]):
    """Analyze the provided VirusTotal URLs."""
    print("🔍 VirusTotal URL Analysis")
    print("=" * 60)
    
    results = []
    
    for i, url in enumerate(urls, 1):
        print(f"\n[{i}/{len(urls)}] Analyzing: {url}")
        
        file_hash = extract_file_hash(url)
        if not file_hash:
            print("❌ Could not extract file hash")
            continue
            
        print(f"📁 File Hash: {file_hash}")
        
        # Determine URL type
        if "/behavior" in url:
            url_type = "behavior"
            print(f"🔍 URL Type: Behavior Analysis")
        elif "/details" in url:
            url_type = "details"
            print(f"📊 URL Type: File Details")
        elif "/detection" in url:
            url_type = "detection"
            print(f"🛡️ URL Type: Detection Results")
        else:
            url_type = "general"
            print(f"🔗 URL Type: General Information")
        
        # Extract additional info from URL
        if "nocache=1" in url:
            print(f"🔄 Cache: Disabled (nocache=1)")
        
        results.append({
            "url": url,
            "file_hash": file_hash,
            "url_type": url_type,
            "cache_disabled": "nocache=1" in url
        })
    
    return results

def generate_summary(results: List[Dict]):
    """Generate a summary of the analysis."""
    print(f"\n{'='*60}")
    print("📋 ANALYSIS SUMMARY")
    print(f"{'='*60}")
    
    total_files = len(results)
    behavior_count = len([r for r in results if r['url_type'] == 'behavior'])
    details_count = len([r for r in results if r['url_type'] == 'details'])
    detection_count = len([r for r in results if r['url_type'] == 'detection'])
    general_count = len([r for r in results if r['url_type'] == 'general'])
    nocache_count = len([r for r in results if r['cache_disabled']])
    
    print(f"📁 Total Files: {total_files}")
    print(f"🔍 Behavior Analysis URLs: {behavior_count}")
    print(f"📊 File Details URLs: {details_count}")
    print(f"🛡️ Detection Results URLs: {detection_count}")
    print(f"🔗 General URLs: {general_count}")
    print(f"🔄 Cache Disabled: {nocache_count}")
    
    print(f"\n📝 File Hashes:")
    for i, result in enumerate(results, 1):
        print(f"  {i}. {result['file_hash']} ({result['url_type']})")
    
    return {
        "total_files": total_files,
        "behavior_count": behavior_count,
        "details_count": details_count,
        "detection_count": detection_count,
        "general_count": general_count,
        "nocache_count": nocache_count,
        "file_hashes": [r['file_hash'] for r in results]
    }

def main():
    # Your provided URLs
    urls = [
        "https://www.virustotal.com/gui/file/ff9af2daf73e8b2ca8d0648f1f8650367b717dd76f7458777d151ce5cbd8eaae/behavior",
        "https://www.virustotal.com/gui/file/a929d11f2653be0f5ea0abbf29a3d73ea4d9700a5cfce27de7c7c8aeb84e7cf9/details",
        "https://www.virustotal.com/gui/file/46653119500aea47ec149afe0bcb9c76cad82b36fbfa1ed571bf1bbf452a9031/details",
        "https://www.virustotal.com/gui/file/dcfc2f15c0e010bc8ae1c3fb6709a7458defbc636a5afc8a73990b8a2d82cd22?nocache=1",
        "https://www.virustotal.com/gui/file/3e671895062924ac704ff8df342a1fe2c27e3a4397d31bd982639e7daaceb746?nocache=1",
        "https://www.virustotal.com/gui/file/dcbdc717d1b37ee9552b81f53a7b68ee62f2147fddd83c21e4efe5ff34fad896/detection"
    ]
    
    results = analyze_urls(urls)
    summary = generate_summary(results)
    
    # Save results
    with open("vt_analysis_results.json", "w") as f:
        json.dump({
            "results": results,
            "summary": summary
        }, f, indent=2)
    
    print(f"\n💾 Results saved to: vt_analysis_results.json")
    
    print(f"\n🔑 For detailed analysis with detection rates and behavior data,")
    print(f"   you'll need a VirusTotal API key and the full analyzer script.")
    print(f"   Install dependencies: pip install requests")
    print(f"   Run: python vt_analyzer.py " + " ".join(urls) + " --api-key YOUR_API_KEY")

if __name__ == "__main__":
    main()