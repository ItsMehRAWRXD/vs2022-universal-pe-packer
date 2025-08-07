#!/usr/bin/env python3
"""
Populate FUD Database with Historical Results
"""

from simple_fud_tracker import SimpleFUDTracker

def populate_historical_data():
    tracker = SimpleFUDTracker()
    
    print("🔄 POPULATING FUD DATABASE WITH HISTORICAL RESULTS")
    print("=" * 60)
    
    # Historical FUD combinations confirmed in our conversation
    historical_fud_results = [
        {
            'vt_link': 'https://www.virustotal.com/gui/file/e09ddc17b05f716e258c4debe587e00647265070ea195e66ed42da06f52c10a2',
            'company': 'Adobe Systems Incorporated',
            'cert': 'GoDaddy Root Certificate Authority',
            'arch': 'x64',
            'notes': 'Confirmed FUD from manual testing'
        },
        {
            'vt_link': 'https://www.virustotal.com/gui/file/78ddef4bd8f51b70327dd23e0591d838579d1f245f737d3c9e471731b49cf2b1',
            'company': 'Adobe Systems Incorporated', 
            'cert': 'DigiCert Assured ID Root CA',
            'arch': 'x64',
            'notes': 'Confirmed FUD from manual testing'
        },
        {
            'vt_link': 'https://www.virustotal.com/gui/file/c99bcf0fe8f16575c5a3c0e46081d49aa7c5a7d26ac36e924808a4d7195ffed0',
            'company': 'Adobe Systems Incorporated',
            'cert': 'GlobalSign Root CA', 
            'arch': 'x64',
            'notes': 'Confirmed FUD from manual testing'
        },
        {
            'vt_link': 'https://www.virustotal.com/gui/file/3589ae323a149bd0c8b8024bfa934fe0f88654df3aaaa730a079ba13f6e9d142',
            'company': 'Adobe Systems Incorporated',
            'cert': 'Lenovo Certificate Authority',
            'arch': 'x64', 
            'notes': 'Confirmed FUD from manual testing'
        },
        {
            'vt_link': 'https://www.virustotal.com/gui/file-analysis/01eedf7e7fd0eb26c615f9fb5cece035d5a455a1855208bbd6dc50ea28eae4cd',
            'company': 'Adobe Systems Incorporated',
            'cert': 'Baltimore CyberTrust Root',
            'arch': 'x64',
            'notes': 'Confirmed FUD from manual testing'
        },
        {
            'vt_link': 'https://www.virustotal.com/gui/file/6f78360e4ce2b999c3d4178c9ee67f5ec38e42e903403d7bd7071e2a9dc4422a',
            'company': 'Adobe Systems Incorporated',
            'cert': 'Realtek Root Certificate',
            'arch': 'AnyCPU',
            'notes': 'Confirmed FUD from manual testing'
        },
        {
            'vt_link': 'https://www.virustotal.com/gui/file/9da5e9238963cef41f77caef081c63d671dc01eae4872ac3b141859c04e3e38a',
            'company': 'Adobe Systems Incorporated',
            'cert': 'Apple Root CA',
            'arch': 'x64',
            'notes': 'FUD but inconsistent - detected in other tests'
        },
        {
            'vt_link': 'https://websec.nl/scanner/result/aef3cc12-5ebb-4aa8-ad89-0a3592efb7d7',
            'company': 'Google LLC',
            'cert': 'Comodo RSA CA',
            'arch': 'x64',
            'notes': 'Confirmed FUD - alternative scanner'
        }
    ]
    
    # Historical detected combinations (known failures)
    historical_detected_results = [
        {
            'vt_link': 'https://www.virustotal.com/gui/file/6c6c4fe52bed6125448af25ac786c89c2d23882e500201fde87c379e5fb08ffa',
            'company': 'Adobe Systems Incorporated',
            'cert': 'Apple Root CA',
            'arch': 'AnyCPU',
            'detections': 1,
            'notes': 'Inconsistent - sometimes FUD, sometimes detected'
        },
        {
            'vt_link': 'https://www.virustotal.com/gui/file-analysis/MDNiMGFiOWE1YTcyMjM3MTA1MTg2MTBhMzJiYzdhYjI6MTc1NDQ1MTU4Ng==',
            'company': 'Adobe Systems Incorporated',
            'cert': 'HP Enterprise Root CA',
            'arch': 'x64',
            'detections': 2,
            'notes': 'Consistently detected - avoid this combination'
        },
        {
            'vt_link': 'https://www.virustotal.com/gui/file-analysis/Y2UxZDQyZWMwNjNjOTZiYTBmMDdmN2Y4ZjhiYmFmNWQ6MTc1NDQ1MjQzMg==',
            'company': 'Adobe Systems Incorporated',
            'cert': 'Qualcomm Root Authority',
            'arch': 'x64',
            'detections': 1,
            'notes': 'Inconsistent - 2/3 FUD rate, unreliable'
        },
        {
            'vt_link': 'https://www.virustotal.com/gui/file-analysis/ZGVkNWUxYmY5MTliNjRkZmZmNTgzYjE0Yjc1MjE0ZTY6MTc1NDQ1MjQ3Mg==',
            'company': 'Adobe Systems Incorporated',
            'cert': 'Microsoft Root Certificate Authority',
            'arch': 'AnyCPU',
            'detections': 3,
            'notes': 'Microsoft combinations consistently detected'
        }
    ]
    
    print(f"Adding {len(historical_fud_results)} FUD combinations...")
    for result in historical_fud_results:
        tracker.add_result(
            result['vt_link'],
            result['company'],
            result['cert'], 
            result['arch'],
            True,  # is_fud
            0,     # detection_count
            result['notes']
        )
    
    print(f"Adding {len(historical_detected_results)} detected combinations...")
    for result in historical_detected_results:
        tracker.add_result(
            result['vt_link'],
            result['company'],
            result['cert'],
            result['arch'], 
            False,  # is_fud
            result['detections'],
            result['notes']
        )
    
    print("\n✅ Historical data populated successfully!")
    print("Generating comprehensive report...")
    
    # Generate full report
    tracker.generate_report()

if __name__ == "__main__":
    populate_historical_data()