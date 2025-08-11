#!/usr/bin/env python3
"""
Simple VirusTotal URL Analyzer
Extracts file hashes and basic information from VirusTotal URLs.
"""

import re
import requests
import json
from typing import List, Dict

def extract_file_hash(url: str) -> str:
    """Extract file hash from VirusTotal URL."""
    # Pattern for VT URLs
    pattern = r'/file/([a-f0-9]{64})'
    match = re.search(pattern, url)
    if match:
        return match.group(1)
    return None

def get_basic_file_info(file_hash: str) -> Dict:
    """Get basic file information using VirusTotal's public API."""
    url = f"https://www.virustotal.com/vtapi/v2/file/report"
    params = {"apikey": "YOUR_API_KEY", "resource": file_hash}
    
    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

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
        
        # For now, just show the hash and URL type
        url_type = "behavior" if "/behavior" in url else "details" if "/details" in url else "detection" if "/detection" in url else "general"
        print(f"🔗 URL Type: {url_type}")
        
        results.append({
            "url": url,
            "file_hash": file_hash,
            "url_type": url_type
        })
    
    return results

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
    
    # Save results
    with open("vt_analysis_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n{'='*60}")
    print("📋 SUMMARY")
    print(f"{'='*60}")
    print(f"📁 Total Files: {len(results)}")
    print(f"🔍 Behavior URLs: {len([r for r in results if r['url_type'] == 'behavior'])}")
    print(f"📊 Details URLs: {len([r for r in results if r['url_type'] == 'details'])}")
    print(f"🛡️ Detection URLs: {len([r for r in results if r['url_type'] == 'detection'])}")
    print(f"\n💾 Results saved to: vt_analysis_results.json")
    
    print(f"\n🔑 To get detailed analysis, you'll need a VirusTotal API key.")
    print(f"   Run: python vt_analyzer.py " + " ".join(urls) + " --api-key YOUR_API_KEY")

if __name__ == "__main__":
    main()