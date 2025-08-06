#!/usr/bin/env python3
"""
Simple FUD Tracking System (No external dependencies)
"""

import json
import os
from datetime import datetime

class SimpleFUDTracker:
    def __init__(self):
        self.results_file = 'fud_tracking_results.json'
        self.results = self.load_results()
    
    def load_results(self):
        """Load existing results from file"""
        if os.path.exists(self.results_file):
            try:
                with open(self.results_file, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []
    
    def save_results(self):
        """Save results to file"""
        with open(self.results_file, 'w') as f:
            json.dump(self.results, f, indent=2)
    
    def add_result(self, vt_link, company, cert, arch, is_fud, detection_count=0, notes=""):
        """Add a new test result"""
        # Extract hash from VT link if possible
        file_hash = "unknown"
        if '/file/' in vt_link:
            file_hash = vt_link.split('/file/')[-1].split('?')[0].split('/')[0]
        elif '/file-analysis/' in vt_link:
            # Handle analysis links
            file_hash = f"analysis_{vt_link.split('/')[-1]}"
        
        result = {
            'timestamp': datetime.now().isoformat(),
            'company': company,
            'certificate': cert,
            'architecture': arch,
            'is_fud': is_fud,
            'detection_count': detection_count,
            'vt_link': vt_link,
            'hash': file_hash,
            'notes': notes
        }
        
        self.results.append(result)
        self.save_results()
        
        status = "✅ FUD" if is_fud else f"❌ DETECTED ({detection_count}/72)"
        print(f"{status}: {company} + {cert} + {arch}")
        print(f"🔗 {vt_link}")
        if notes:
            print(f"📝 Notes: {notes}")
        print()
    
    def generate_report(self):
        """Generate comprehensive report"""
        print("🎯 FUD TRACKING REPORT")
        print("=" * 60)
        
        fud_results = [r for r in self.results if r['is_fud']]
        detected_results = [r for r in self.results if not r['is_fud']]
        
        print(f"\n📊 SUMMARY:")
        print(f"✅ FUD Combinations: {len(fud_results)}")
        print(f"❌ Detected Combinations: {len(detected_results)}")
        print(f"📊 Total Tested: {len(self.results)}")
        
        if fud_results:
            print(f"\n🏆 VERIFIED FUD COMBINATIONS:")
            print("-" * 40)
            for i, result in enumerate(fud_results, 1):
                print(f"{i}. ✅ {result['company']} + {result['certificate']} + {result['architecture']}")
                print(f"   📅 {result['timestamp']}")
                print(f"   🔗 {result['vt_link']}")
                if result.get('notes'):
                    print(f"   📝 {result['notes']}")
                print()
        
        if detected_results:
            print(f"\n❌ DETECTED COMBINATIONS:")
            print("-" * 30)
            for i, result in enumerate(detected_results, 1):
                print(f"{i}. ❌ {result['company']} + {result['certificate']} + {result['architecture']}")
                print(f"   🚨 Detections: {result['detection_count']}/72")
                print(f"   📅 {result['timestamp']}")
                print(f"   🔗 {result['vt_link']}")
                if result.get('notes'):
                    print(f"   📝 {result['notes']}")
                print()
        
        # Generate pattern analysis
        self.analyze_patterns()
        
        # Save text report
        self.save_text_reports()
    
    def analyze_patterns(self):
        """Analyze FUD patterns"""
        print("🔍 PATTERN ANALYSIS:")
        print("-" * 20)
        
        # Company analysis
        company_stats = {}
        for result in self.results:
            company = result['company']
            if company not in company_stats:
                company_stats[company] = {'fud': 0, 'total': 0}
            company_stats[company]['total'] += 1
            if result['is_fud']:
                company_stats[company]['fud'] += 1
        
        print("\n📈 Company FUD Success Rates:")
        for company, stats in company_stats.items():
            rate = (stats['fud'] / stats['total']) * 100 if stats['total'] > 0 else 0
            print(f"  🏢 {company}: {stats['fud']}/{stats['total']} ({rate:.1f}%)")
        
        # Certificate analysis
        cert_stats = {}
        for result in self.results:
            cert = result['certificate']
            if cert not in cert_stats:
                cert_stats[cert] = {'fud': 0, 'total': 0}
            cert_stats[cert]['total'] += 1
            if result['is_fud']:
                cert_stats[cert]['fud'] += 1
        
        print("\n🔐 Certificate FUD Success Rates:")
        for cert, stats in cert_stats.items():
            rate = (stats['fud'] / stats['total']) * 100 if stats['total'] > 0 else 0
            print(f"  📜 {cert}: {stats['fud']}/{stats['total']} ({rate:.1f}%)")
        
        # Architecture analysis
        arch_stats = {}
        for result in self.results:
            arch = result['architecture']
            if arch not in arch_stats:
                arch_stats[arch] = {'fud': 0, 'total': 0}
            arch_stats[arch]['total'] += 1
            if result['is_fud']:
                arch_stats[arch]['fud'] += 1
        
        print("\n🏗️ Architecture FUD Success Rates:")
        for arch, stats in arch_stats.items():
            rate = (stats['fud'] / stats['total']) * 100 if stats['total'] > 0 else 0
            print(f"  ⚙️ {arch}: {stats['fud']}/{stats['total']} ({rate:.1f}%)")
    
    def save_text_reports(self):
        """Save text reports"""
        # FUD combinations
        with open('verified_fud_combinations.txt', 'w') as f:
            f.write("VERIFIED FUD COMBINATIONS\n")
            f.write("=" * 50 + "\n\n")
            
            fud_results = [r for r in self.results if r['is_fud']]
            for result in fud_results:
                f.write(f"✅ {result['company']} + {result['certificate']} + {result['architecture']}\n")
                f.write(f"   Date: {result['timestamp']}\n")
                f.write(f"   Hash: {result['hash']}\n")
                f.write(f"   Link: {result['vt_link']}\n")
                if result.get('notes'):
                    f.write(f"   Notes: {result['notes']}\n")
                f.write("\n")
        
        # Blocked combinations
        with open('blocked_combinations.txt', 'w') as f:
            f.write("BLOCKED COMBINATIONS\n")
            f.write("=" * 50 + "\n\n")
            
            detected_results = [r for r in self.results if not r['is_fud']]
            for result in detected_results:
                f.write(f"❌ {result['company']} + {result['certificate']} + {result['architecture']}\n")
                f.write(f"   Detections: {result['detection_count']}/72\n")
                f.write(f"   Date: {result['timestamp']}\n")
                f.write(f"   Hash: {result['hash']}\n")
                f.write(f"   Link: {result['vt_link']}\n")
                if result.get('notes'):
                    f.write(f"   Notes: {result['notes']}\n")
                f.write("\n")
        
        print("💾 Reports saved:")
        print("   📄 verified_fud_combinations.txt")
        print("   📄 blocked_combinations.txt")
        print("   📄 fud_tracking_results.json")

def main():
    tracker = SimpleFUDTracker()
    
    print("🎯 SIMPLE FUD TRACKING SYSTEM")
    print("=" * 50)
    print("1. Add test result")
    print("2. Generate report")
    print("3. Add your latest result (Adobe + AnyCPU + Realtek)")
    print("4. View all results")
    
    try:
        choice = input("\nSelect option (1-4): ").strip()
    except KeyboardInterrupt:
        print("\nExiting...")
        return
    
    if choice == "1":
        print("\n📋 ADD TEST RESULT")
        print("-" * 20)
        try:
            vt_link = input("VirusTotal link: ").strip()
            company = input("Company name: ").strip()
            cert = input("Certificate authority: ").strip()
            arch = input("Architecture (x86/x64/AnyCPU): ").strip()
            is_fud_input = input("Is FUD? (y/n): ").strip().lower()
            is_fud = is_fud_input in ['y', 'yes', '1', 'true']
            
            detection_count = 0
            if not is_fud:
                detection_count = int(input("Number of detections: ").strip() or "0")
            
            notes = input("Notes (optional): ").strip()
            
            tracker.add_result(vt_link, company, cert, arch, is_fud, detection_count, notes)
            print("✅ Result added successfully!")
            
        except (ValueError, KeyboardInterrupt):
            print("❌ Invalid input or cancelled")
    
    elif choice == "2":
        tracker.generate_report()
    
    elif choice == "3":
        print("\n📋 ADDING YOUR LATEST RESULT")
        print("-" * 30)
        vt_link = "https://www.virustotal.com/gui/file-analysis/NzcxZGI0ZjI0ZDZmOGVmYmIwNjJkZDk5Yjc3M2VjODg6MTc1NDQ1MzI5Nw=="
        company = "Adobe Systems Incorporated"
        cert = "Realtek Root Certificate"
        arch = "AnyCPU"
        is_fud = True
        notes = "Manual test - 0/72 detections confirmed"
        
        tracker.add_result(vt_link, company, cert, arch, is_fud, 0, notes)
        print("✅ Latest result added successfully!")
        
        # Auto-generate report
        tracker.generate_report()
    
    elif choice == "4":
        print("\n📋 ALL RESULTS")
        print("-" * 15)
        if not tracker.results:
            print("No results found.")
        else:
            for i, result in enumerate(tracker.results, 1):
                status = "✅ FUD" if result['is_fud'] else f"❌ DETECTED ({result['detection_count']}/72)"
                print(f"{i}. {status}: {result['company']} + {result['certificate']} + {result['architecture']}")
                print(f"   📅 {result['timestamp']}")
                print(f"   🔗 {result['vt_link']}")
                if result.get('notes'):
                    print(f"   📝 {result['notes']}")
                print()
    
    else:
        print("Invalid option")

if __name__ == "__main__":
    # Add the latest FUD result from user
    tracker = SimpleFUDTracker()
    
    # Adding new FUD result - Adobe + Thawte + AnyCPU + XOR + PE Exec
    tracker.add_result(
        'https://www.virustotal.com/gui/file/df2c92b20e2aa7df9b49704b53fe433118839b69ce92b12990947d7c5ed17c3c?nocache=1',
        'Adobe Systems Incorporated',
        'Thawte Timestamping CA',
        'AnyCPU',
        True,
        0,
        'Manual test #67 - Adobe + Thawte + AnyCPU + XOR + PE Exec delivery - FUD SUCCESS! Polymorphic generation working perfectly.'
    )
    
    main()