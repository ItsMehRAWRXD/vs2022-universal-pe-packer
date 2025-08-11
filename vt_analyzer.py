#!/usr/bin/env python3
"""
VirusTotal URL Analyzer
Analyzes VirusTotal URLs to extract file information, detection rates, and behavioral data.
"""

import re
import requests
import json
import time
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Optional
import argparse
import sys

class VirusTotalAnalyzer:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {}
        if api_key:
            self.headers["x-apikey"] = api_key
    
    def extract_file_id_from_url(self, url: str) -> Optional[str]:
        """Extract file ID from VirusTotal URL."""
        # Pattern for VT URLs
        patterns = [
            r'/file/([a-f0-9]{64})',
            r'/gui/file/([a-f0-9]{64})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return match.group(1)
        return None
    
    def get_file_info(self, file_id: str) -> Optional[Dict]:
        """Get file information from VirusTotal API."""
        if not self.api_key:
            print("Warning: No API key provided. Some features may be limited.")
            return None
            
        url = f"{self.base_url}/files/{file_id}"
        try:
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Error: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"Error fetching file info: {e}")
            return None
    
    def get_file_behavior(self, file_id: str) -> Optional[Dict]:
        """Get file behavior analysis from VirusTotal API."""
        if not self.api_key:
            return None
            
        url = f"{self.base_url}/files/{file_id}/behaviours"
        try:
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Error: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"Error fetching behavior info: {e}")
            return None
    
    def analyze_url(self, url: str) -> Dict:
        """Analyze a single VirusTotal URL."""
        print(f"\n{'='*60}")
        print(f"Analyzing: {url}")
        print(f"{'='*60}")
        
        file_id = self.extract_file_id_from_url(url)
        if not file_id:
            print("❌ Could not extract file ID from URL")
            return {}
        
        print(f"📁 File ID: {file_id}")
        
        # Get file information
        file_info = self.get_file_info(file_id)
        if file_info:
            data = file_info.get('data', {})
            attributes = data.get('attributes', {})
            
            print(f"📊 File Name: {attributes.get('meaningful_name', 'N/A')}")
            print(f"📏 File Size: {attributes.get('size', 'N/A')} bytes")
            print(f"🔍 File Type: {attributes.get('type_description', 'N/A')}")
            print(f"📅 First Seen: {attributes.get('first_submission_date', 'N/A')}")
            print(f"📅 Last Seen: {attributes.get('last_analysis_date', 'N/A')}")
            
            # Detection stats
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            print(f"✅ Clean: {last_analysis_stats.get('undetected', 0)}")
            print(f"❌ Detected: {last_analysis_stats.get('malicious', 0)}")
            print(f"⚠️ Suspicious: {last_analysis_stats.get('suspicious', 0)}")
            print(f"🔄 Total Scanners: {sum(last_analysis_stats.values())}")
            
            # Detection ratio
            total = sum(last_analysis_stats.values())
            detected = last_analysis_stats.get('malicious', 0)
            if total > 0:
                detection_rate = (detected / total) * 100
                print(f"🎯 Detection Rate: {detection_rate:.2f}%")
                
                if detected == 0:
                    print("🟢 STATUS: FUD (Fully Undetected)")
                elif detected <= 5:
                    print("🟡 STATUS: Low Detection")
                else:
                    print("🔴 STATUS: Detected")
            
            # Get behavior analysis
            behavior = self.get_file_behavior(file_id)
            if behavior:
                print(f"\n🔍 BEHAVIOR ANALYSIS:")
                behavior_data = behavior.get('data', [])
                if behavior_data:
                    for item in behavior_data[:5]:  # Show first 5 behaviors
                        attrs = item.get('attributes', {})
                        print(f"  • {attrs.get('rule_title', 'Unknown behavior')}")
                else:
                    print("  No behavior data available")
        
        return {
            'file_id': file_id,
            'url': url,
            'file_info': file_info
        }
    
    def analyze_multiple_urls(self, urls: List[str]) -> List[Dict]:
        """Analyze multiple VirusTotal URLs."""
        results = []
        
        print(f"🔍 Analyzing {len(urls)} VirusTotal URLs...")
        
        for i, url in enumerate(urls, 1):
            print(f"\n[{i}/{len(urls)}] Processing...")
            result = self.analyze_url(url)
            results.append(result)
            
            # Rate limiting
            if i < len(urls):
                time.sleep(1)
        
        return results
    
    def generate_summary(self, results: List[Dict]) -> None:
        """Generate a summary of all analyzed files."""
        print(f"\n{'='*60}")
        print("📋 SUMMARY REPORT")
        print(f"{'='*60}")
        
        total_files = len(results)
        fud_count = 0
        detected_count = 0
        
        for result in results:
            file_info = result.get('file_info', {})
            if file_info:
                data = file_info.get('data', {})
                attributes = data.get('attributes', {})
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                detected = last_analysis_stats.get('malicious', 0)
                
                if detected == 0:
                    fud_count += 1
                else:
                    detected_count += 1
        
        print(f"📁 Total Files Analyzed: {total_files}")
        print(f"🟢 FUD Files: {fud_count}")
        print(f"🔴 Detected Files: {detected_count}")
        print(f"📊 FUD Rate: {(fud_count/total_files)*100:.1f}%" if total_files > 0 else "N/A")

def main():
    parser = argparse.ArgumentParser(description="Analyze VirusTotal URLs")
    parser.add_argument("urls", nargs="+", help="VirusTotal URLs to analyze")
    parser.add_argument("--api-key", help="VirusTotal API key (optional)")
    parser.add_argument("--output", help="Output file for results (JSON)")
    
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = VirusTotalAnalyzer(api_key=args.api_key)
    
    # Analyze URLs
    results = analyzer.analyze_multiple_urls(args.urls)
    
    # Generate summary
    analyzer.generate_summary(results)
    
    # Save results if output file specified
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n💾 Results saved to: {args.output}")

if __name__ == "__main__":
    # Example usage without command line arguments
    if len(sys.argv) == 1:
        print("🔍 VirusTotal URL Analyzer")
        print("Usage: python vt_analyzer.py <url1> <url2> ... [--api-key YOUR_API_KEY]")
        print("\nExample URLs from your input:")
        
        example_urls = [
            "https://www.virustotal.com/gui/file/ff9af2daf73e8b2ca8d0648f1f8650367b717dd76f7458777d151ce5cbd8eaae/behavior",
            "https://www.virustotal.com/gui/file/a929d11f2653be0f5ea0abbf29a3d73ea4d9700a5cfce27de7c7c8aeb84e7cf9/details",
            "https://www.virustotal.com/gui/file/46653119500aea47ec149afe0bcb9c76cad82b36fbfa1ed571bf1bbf452a9031/details",
            "https://www.virustotal.com/gui/file/dcfc2f15c0e010bc8ae1c3fb6709a7458defbc636a5afc8a73990b8a2d82cd22?nocache=1",
            "https://www.virustotal.com/gui/file/3e671895062924ac704ff8df342a1fe2c27e3a4397d31bd982639e7daaceb746?nocache=1",
            "https://www.virustotal.com/gui/file/dcbdc717d1b37ee9552b81f53a7b68ee62f2147fddd83c21e4efe5ff34fad896/detection"
        ]
        
        print("\nWould you like me to analyze these example URLs? (Note: API key required for full analysis)")
        print("Run: python vt_analyzer.py " + " ".join(example_urls))
    else:
        main()