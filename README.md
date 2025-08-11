# VirusTotal URL Analyzer

A collection of tools to analyze VirusTotal URLs and extract file information, detection rates, and behavioral data.

## Files

- `simple_vt_analyzer.py` - Basic analyzer that extracts file hashes from VT URLs (no external dependencies)
- `vt_analyzer.py` - Full-featured analyzer with API integration (requires VirusTotal API key)
- `analyze_vt_urls.py` - Intermediate analyzer with basic API functionality
- `requirements.txt` - Python dependencies for the full analyzer

## Quick Start

### Basic Analysis (No API Key Required)

```bash
python3 simple_vt_analyzer.py
```

This will analyze the provided VirusTotal URLs and extract:
- File hashes (SHA256)
- URL types (behavior, details, detection, general)
- Cache settings
- Summary statistics

### Full Analysis (API Key Required)

1. Install dependencies:
```bash
pip install requests
```

2. Get a VirusTotal API key from: https://www.virustotal.com/gui/join-us

3. Run the full analyzer:
```bash
python vt_analyzer.py <url1> <url2> ... --api-key YOUR_API_KEY
```

## Analyzed Files

The following VirusTotal URLs were analyzed:

1. **Behavior Analysis**: `ff9af2daf73e8b2ca8d0648f1f8650367b717dd76f7458777d151ce5cbd8eaae`
2. **File Details**: `a929d11f2653be0f5ea0abbf29a3d73ea4d9700a5cfce27de7c7c8aeb84e7cf9`
3. **File Details**: `46653119500aea47ec149afe0bcb9c76cad82b36fbfa1ed571bf1bbf452a9031`
4. **General Info**: `dcfc2f15c0e010bc8ae1c3fb6709a7458defbc636a5afc8a73990b8a2d82cd22` (nocache=1)
5. **General Info**: `3e671895062924ac704ff8df342a1fe2c27e3a4397d31bd982639e7daaceb746` (nocache=1)
6. **Detection Results**: `dcbdc717d1b37ee9552b81f53a7b68ee62f2147fddd83c21e4efe5ff34fad896`

## Summary

- **Total Files**: 6
- **Behavior Analysis URLs**: 1
- **File Details URLs**: 2
- **Detection Results URLs**: 1
- **General URLs**: 2
- **Cache Disabled**: 2

## Output

Results are saved to `vt_analysis_results.json` in JSON format for further processing.

## FUD Analysis

The "FUD 0/65 o0" notation indicates a file that has 0 detections out of 65 antivirus engines, meaning it's "Fully Undetected" (FUD). This is a common term in malware analysis for files that evade detection by all major antivirus solutions.

## Features

### Simple Analyzer (`simple_vt_analyzer.py`)
- ✅ No external dependencies
- ✅ Extracts file hashes
- ✅ Identifies URL types
- ✅ Generates summary statistics
- ✅ Saves results to JSON

### Full Analyzer (`vt_analyzer.py`)
- ✅ VirusTotal API integration
- ✅ Detection rate analysis
- ✅ Behavioral analysis
- ✅ File metadata extraction
- ✅ FUD status detection
- ✅ Rate limiting
- ✅ JSON output

## Usage Examples

```bash
# Analyze specific URLs
python3 simple_vt_analyzer.py

# Full analysis with API key
python vt_analyzer.py \
  "https://www.virustotal.com/gui/file/ff9af2daf73e8b2ca8d0648f1f8650367b717dd76f7458777d151ce5cbd8eaae/behavior" \
  --api-key YOUR_API_KEY

# Save results to file
python vt_analyzer.py <urls> --api-key YOUR_API_KEY --output results.json
```

## Security Note

These tools are for legitimate security research and malware analysis purposes only. Always ensure you have proper authorization before analyzing any files. 
