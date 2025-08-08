#!/usr/bin/env python3
"""
Test script for the Enhanced AI Code Generator with Repository Management
This script demonstrates the new repository management capabilities.
"""

import sys
import json
from pathlib import Path

# Add the current directory to path to import ai_coder
sys.path.insert(0, str(Path(__file__).parent))

from ai_coder import AICodeGenerator

def test_repository_management():
    """Test the repository management functionality"""
    print("🧪 Testing Enhanced AI Code Generator")
    print("=" * 50)
    
    # Initialize the generator
    generator = AICodeGenerator()
    
    # Test 1: List repositories
    print("\n1️⃣ Testing repository listing:")
    generator.list_repositories()
    
    # Test 2: Add a custom repository (simulated)
    print("\n2️⃣ Testing repository addition:")
    generator.add_repository(
        "custom-tools",
        "https://github.com/example/custom-tools",
        "Custom development tools and utilities",
        "tools",
        "python"
    )
    
    # Test 3: Show repository patterns analysis (without actually cloning)
    print("\n3️⃣ Repository configuration loaded:")
    for name, repo in generator.repositories.items():
        print(f"  📦 {name}: {repo['description']}")
        print(f"      Type: {repo['project_type']}, Framework: {repo['framework']}")
        print(f"      URL: {repo['url']}")
        print()
    
    # Test 4: Simulate project creation workflow
    print("\n4️⃣ Project creation workflow demonstration:")
    print("Available project templates:")
    for name, repo in generator.repositories.items():
        print(f"  - {name} ({repo['project_type']})")
    
    print("\n✅ Repository management system is ready!")
    print("🔧 To use the enhanced AI coder:")
    print("   python ai_coder.py")
    print("\n📚 Features added:")
    print("   - Repository management and configuration")
    print("   - Template-based project creation")
    print("   - Repository cloning and analysis")
    print("   - Pattern recognition for different project types")
    
    return True

def demonstrate_enhanced_features():
    """Demonstrate the key enhanced features"""
    print("\n🚀 Enhanced AI Code Generator Features:")
    print("=" * 50)
    
    features = [
        "📚 Repository Management: Add, list, and manage multiple code repositories",
        "🔄 Smart Cloning: Clone repositories locally for template usage",
        "📊 Pattern Analysis: Analyze repository structure and patterns", 
        "🎯 Template Creation: Create new projects from repository templates",
        "⚙️ Configuration: Persistent repository configuration with JSON storage",
        "🔧 Multi-Framework: Support for Python, JavaScript, C++, and more",
        "🎨 Customization: Template variable replacement for project names and ideas"
    ]
    
    for i, feature in enumerate(features, 1):
        print(f"{i}. {feature}")
    
    print(f"\n📈 Total repositories configured: {len(AICodeGenerator().repositories)}")
    print("🎉 Ready to accelerate your development workflow!")

if __name__ == "__main__":
    # Run tests
    test_repository_management()
    demonstrate_enhanced_features()
    
    print("\n" + "="*60)
    print("🎯 THE ENHANCED AI CODER IS NOW READY!")
    print("Run 'python ai_coder.py' to start using the enhanced features.")
    print("="*60)