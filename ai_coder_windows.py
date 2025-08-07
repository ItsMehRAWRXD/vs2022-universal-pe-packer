#!/usr/bin/env python3
"""
AI Code Generator for Windows 11 - Local AI Coding Assistant
This tool can create files, generate code, and help you build projects from your ideas.
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any

class AICodeGenerator:
    def __init__(self):
        # Use Windows-friendly paths
        self.project_dir = Path.cwd()
        
    def create_file(self, filepath: str, content: str):
        """Create a file with the given content"""
        full_path = self.project_dir / filepath
        full_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"✅ Created: {filepath}")
        return full_path
    
    def create_project_structure(self, project_name: str, structure: Dict[str, Any]):
        """Create a complete project structure"""
        project_path = self.project_dir / project_name
        project_path.mkdir(exist_ok=True)
        
        def create_structure_recursive(base_path: Path, structure: Dict[str, Any]):
            for name, content in structure.items():
                item_path = base_path / name
                
                if isinstance(content, dict):
                    # It's a directory
                    item_path.mkdir(exist_ok=True)
                    create_structure_recursive(item_path, content)
                else:
                    # It's a file
                    with open(item_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    print(f"✅ Created: {item_path.relative_to(self.project_dir)}")
        
        create_structure_recursive(project_path, structure)
        return project_path
    
    def generate_code(self, prompt: str, language: str = "python") -> str:
        """Generate code using local templates and patterns"""
        
        # Local code generation patterns
        templates = {
            "python": {
                "web_app": """from flask import Flask, render_template, request, jsonify
import os

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/data', methods=['GET', 'POST'])
def api_data():
    if request.method == 'POST':
        data = request.json
        # Process data here
        return jsonify({"status": "success", "data": data})
    return jsonify({"message": "API endpoint"})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
""",
                "cli_tool": """#!/usr/bin/env python3
import argparse
import sys
import os

def main():
    parser = argparse.ArgumentParser(description='CLI Tool')
    parser.add_argument('--input', '-i', help='Input file or data')
    parser.add_argument('--output', '-o', help='Output file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        print(f"Processing: {args.input}")
    
    # Your main logic here
    print("CLI tool executed successfully!")

if __name__ == '__main__':
    main()
""",
                "data_analysis": """import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Load data
def load_data(filepath):
    return pd.read_csv(filepath)

# Analyze data
def analyze_data(df):
    print("Data shape:", df.shape)
    print("\\nData types:")
    print(df.dtypes)
    print("\\nMissing values:")
    print(df.isnull().sum())
    print("\\nSummary statistics:")
    print(df.describe())

# Visualize data
def visualize_data(df):
    plt.figure(figsize=(12, 8))
    
    # Create subplots
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
    
    # Plot 1: Histogram
    axes[0, 0].hist(df.select_dtypes(include=[np.number]).iloc[:, 0], bins=20)
    axes[0, 0].set_title('Distribution')
    
    # Plot 2: Correlation heatmap
    numeric_cols = df.select_dtypes(include=[np.number])
    if len(numeric_cols.columns) > 1:
        sns.heatmap(numeric_cols.corr(), ax=axes[0, 1], annot=True)
        axes[0, 1].set_title('Correlation Matrix')
    
    plt.tight_layout()
    plt.show()

if __name__ == '__main__':
    # Example usage
    # df = load_data('your_data.csv')
    # analyze_data(df)
    # visualize_data(df)
    print("Data analysis script ready!")
""",
                "api_server": """from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import uvicorn

app = FastAPI(title="API Server", version="1.0.0")

class Item(BaseModel):
    id: Optional[int] = None
    name: str
    description: Optional[str] = None
    price: float

# In-memory storage
items = []
next_id = 1

@app.get("/")
def read_root():
    return {"message": "Welcome to the API Server"}

@app.get("/items", response_model=List[Item])
def get_items():
    return items

@app.post("/items", response_model=Item)
def create_item(item: Item):
    global next_id
    item.id = next_id
    next_id += 1
    items.append(item)
    return item

@app.get("/items/{item_id}", response_model=Item)
def get_item(item_id: int):
    for item in items:
        if item.id == item_id:
            return item
    raise HTTPException(status_code=404, detail="Item not found")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
"""
            },
            "javascript": {
                "web_app": """const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/data', (req, res) => {
    res.json({ message: 'API endpoint working!' });
});

app.post('/api/data', (req, res) => {
    const data = req.body;
    // Process data here
    res.json({ status: 'success', data });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
""",
                "react_app": """import React, { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/data')
      .then(response => response.json())
      .then(data => {
        setData(data);
        setLoading(false);
      })
      .catch(error => {
        console.error('Error:', error);
        setLoading(false);
      });
  }, []);

  if (loading) return <div>Loading...</div>;

  return (
    <div className="App">
      <header className="App-header">
        <h1>React App</h1>
        <p>Data: {JSON.stringify(data)}</p>
      </header>
    </div>
  );
}

export default App;
"""
            },
            "html": {
                "basic": """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Website</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            text-align: center;
        }
        .content {
            line-height: 1.6;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to My Website</h1>
        <div class="content">
            <p>This is a basic HTML template. You can customize it to fit your needs.</p>
            <p>Features:</p>
            <ul>
                <li>Responsive design</li>
                <li>Clean and modern styling</li>
                <li>Easy to customize</li>
            </ul>
        </div>
    </div>
</body>
</html>"""
            },
            "batch": {
                "basic": """@echo off
REM Windows Batch Script
echo Hello from Windows!
echo Current directory: %CD%
echo Current date: %DATE%
echo Current time: %TIME%

REM Your commands here
echo Script completed successfully!
pause
""",
                "installer": """@echo off
REM Windows Installer Script
echo Installing application...

REM Create directories
if not exist "C:\\Program Files\\MyApp" mkdir "C:\\Program Files\\MyApp"
if not exist "%APPDATA%\\MyApp" mkdir "%APPDATA%\\MyApp"

REM Copy files
copy "*.exe" "C:\\Program Files\\MyApp\\"
copy "*.dll" "C:\\Program Files\\MyApp\\"

echo Installation completed!
pause
"""
            }
        }
        
        # Simple pattern matching for code generation
        prompt_lower = prompt.lower()
        
        if "web" in prompt_lower or "flask" in prompt_lower:
            return templates[language]["web_app"]
        elif "cli" in prompt_lower or "command" in prompt_lower:
            return templates[language]["cli_tool"]
        elif "data" in prompt_lower or "analysis" in prompt_lower:
            return templates[language]["data_analysis"]
        elif "api" in prompt_lower or "server" in prompt_lower:
            return templates[language]["api_server"]
        elif "react" in prompt_lower:
            return templates["javascript"]["react_app"]
        elif "html" in prompt_lower or "website" in prompt_lower:
            return templates["html"]["basic"]
        elif "batch" in prompt_lower or "windows" in prompt_lower:
            return templates["batch"]["basic"]
        else:
            # Default template
            return templates[language]["web_app"]
    
    def create_project_from_idea(self, idea: str):
        """Create a complete project from an idea"""
        print(f"🚀 Creating project for: {idea}")
        
        # Generate project name
        project_name = idea.lower().replace(" ", "_").replace("-", "_")
        project_name = "".join(c for c in project_name if c.isalnum() or c == "_")
        
        # Determine project type and language
        idea_lower = idea.lower()
        
        if "web" in idea_lower or "website" in idea_lower:
            return self.create_web_project(project_name, idea)
        elif "api" in idea_lower or "server" in idea_lower:
            return self.create_api_project(project_name, idea)
        elif "data" in idea_lower or "analysis" in idea_lower:
            return self.create_data_project(project_name, idea)
        elif "cli" in idea_lower or "tool" in idea_lower:
            return self.create_cli_project(project_name, idea)
        elif "windows" in idea_lower or "batch" in idea_lower:
            return self.create_windows_project(project_name, idea)
        else:
            return self.create_generic_project(project_name, idea)
    
    def create_web_project(self, project_name: str, idea: str):
        """Create a web project"""
        structure = {
            "app.py": self.generate_code(f"Create a Flask web app for {idea}", "python"),
            "requirements.txt": "flask==2.3.3\njinja2==3.1.2\n",
            "templates": {
                "index.html": """<!DOCTYPE html>
<html>
<head>
    <title>{{ title }}</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
    <div class="container">
        <h1>{{ title }}</h1>
        <p>{{ description }}</p>
        <div class="content">
            <!-- Your content here -->
        </div>
    </div>
</body>
</html>""",
                "base.html": """<!DOCTYPE html>
<html>
<head>
    <title>{% block title %}{% endblock %}</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
    <nav>
        <a href="{{ url_for('home') }}">Home</a>
    </nav>
    <main>
        {% block content %}{% endblock %}
    </main>
</body>
</html>"""
            },
            "static": {
                "style.css": """body {
    font-family: Arial, sans-serif;
    margin: 0;
    padding: 20px;
    background-color: #f5f5f5;
}
.container {
    max-width: 800px;
    margin: 0 auto;
    background: white;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}
nav {
    background: #333;
    padding: 10px;
    margin-bottom: 20px;
}
nav a {
    color: white;
    text-decoration: none;
    padding: 10px;
}
nav a:hover {
    background: #555;
}""",
                "script.js": """// Your JavaScript code here
console.log('Web app loaded!');

function handleFormSubmit(event) {
    event.preventDefault();
    // Handle form submission
    console.log('Form submitted');
}"""
            },
            "README.md": f"""# {project_name.replace('_', ' ').title()}

A web application for {idea}.

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python app.py
```

3. Open http://localhost:5000 in your browser

## Features

- Web interface
- RESTful API endpoints
- Responsive design

## Project Structure

- `app.py` - Main Flask application
- `templates/` - HTML templates
- `static/` - CSS, JavaScript, and other static files
- `requirements.txt` - Python dependencies
"""
        }
        
        return self.create_project_structure(project_name, structure)
    
    def create_windows_project(self, project_name: str, idea: str):
        """Create a Windows-specific project"""
        structure = {
            f"{project_name}.bat": self.generate_code(f"Create a Windows batch script for {idea}", "batch"),
            "install.bat": """@echo off
echo Installing {project_name}...
echo.
echo This will install the application to your system.
echo.
pause

REM Create program directory
if not exist "C:\\Program Files\\{project_name}" mkdir "C:\\Program Files\\{project_name}"

REM Copy files
copy "*.bat" "C:\\Program Files\\{project_name}\\"
copy "*.exe" "C:\\Program Files\\{project_name}\\"

echo.
echo Installation completed!
echo You can now run the application from the Start menu.
pause
""".format(project_name=project_name),
            "uninstall.bat": """@echo off
echo Uninstalling {project_name}...
echo.
pause

REM Remove program directory
if exist "C:\\Program Files\\{project_name}" rmdir /s /q "C:\\Program Files\\{project_name}"

echo.
echo Uninstallation completed!
pause
""".format(project_name=project_name),
            "README.md": f"""# {project_name.replace('_', ' ').title()}

A Windows application for {idea}.

## Installation

1. Run the installer:
```cmd
install.bat
```

2. Or run directly:
```cmd
{project_name}.bat
```

## Uninstallation

```cmd
uninstall.bat
```

## Features

- Windows batch scripts
- Easy installation/uninstallation
- Windows-specific functionality

## Project Structure

- `{project_name}.bat` - Main application script
- `install.bat` - Installation script
- `uninstall.bat` - Uninstallation script
"""
        }
        
        return self.create_project_structure(project_name, structure)
    
    def create_api_project(self, project_name: str, idea: str):
        """Create an API project"""
        structure = {
            "main.py": self.generate_code(f"Create a FastAPI server for {idea}", "python"),
            "requirements.txt": "fastapi==0.104.1\nuvicorn==0.24.0\npydantic==2.5.0\n",
            "models.py": """from pydantic import BaseModel
from typing import Optional, List

class Item(BaseModel):
    id: Optional[int] = None
    name: str
    description: Optional[str] = None
    price: float

class Response(BaseModel):
    status: str
    message: str
    data: Optional[dict] = None
""",
            "README.md": f"""# {project_name.replace('_', ' ').title()} API

A FastAPI server for {idea}.

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the server:
```bash
uvicorn main:app --reload
```

3. API documentation available at http://localhost:8000/docs

## Endpoints

- `GET /` - Root endpoint
- `GET /items` - Get all items
- `POST /items` - Create new item
- `GET /items/{id}` - Get specific item

## Features

- FastAPI framework
- Automatic API documentation
- Pydantic models for validation
- Hot reload for development
"""
        }
        
        return self.create_project_structure(project_name, structure)
    
    def create_data_project(self, project_name: str, idea: str):
        """Create a data analysis project"""
        structure = {
            "analysis.py": self.generate_code(f"Create a data analysis script for {idea}", "python"),
            "requirements.txt": "pandas==2.1.3\nnumpy==1.25.2\nmatplotlib==3.8.2\nseaborn==0.13.0\njupyter==1.0.0\n",
            "data": {
                "sample_data.csv": """id,name,value,category
1,Item A,10.5,Category 1
2,Item B,15.2,Category 2
3,Item C,8.7,Category 1
4,Item D,22.1,Category 3
5,Item E,12.3,Category 2"""
            },
            "notebooks": {
                "analysis.ipynb": """{
 "cells": [
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "# Data Analysis Notebook\\n",
    "\\n",
    "This notebook contains the analysis for the project."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {},
   "outputs": [],
   "source": [
    "import pandas as pd\\n",
    "import numpy as np\\n",
    "import matplotlib.pyplot as plt\\n",
    "import seaborn as sns\\n",
    "\\n",
    "# Load data\\n",
    "df = pd.read_csv('../data/sample_data.csv')\\n",
    "print('Data loaded successfully!')\\n",
    "df.head()"
   ]
  }
 ],
 "metadata": {
  "kernelspec": {
   "display_name": "Python 3",
   "language": "python",
   "name": "python3"
  }
 },
 "nbformat": 4,
 "nbformat_minor": 4
}"""
            },
            "README.md": f"""# {project_name.replace('_', ' ').title()}

A data analysis project for {idea}.

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the analysis:
```bash
python analysis.py
```

3. Or use Jupyter notebooks:
```bash
jupyter notebook notebooks/
```

## Features

- Data analysis with pandas
- Visualization with matplotlib and seaborn
- Jupyter notebooks for interactive analysis
- Sample data included

## Project Structure

- `analysis.py` - Main analysis script
- `data/` - Data files
- `notebooks/` - Jupyter notebooks
- `requirements.txt` - Python dependencies
"""
        }
        
        return self.create_project_structure(project_name, structure)
    
    def create_cli_project(self, project_name: str, idea: str):
        """Create a CLI tool project"""
        structure = {
            f"{project_name}.py": self.generate_code(f"Create a CLI tool for {idea}", "python"),
            "requirements.txt": "click==8.1.7\nrich==13.7.0\n",
            "setup.py": f"""from setuptools import setup, find_packages

setup(
    name="{project_name}",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "click>=8.1.7",
        "rich>=13.7.0",
    ],
    entry_points={{
        "console_scripts": [
            "{project_name}={project_name}:main",
        ],
    }},
    author="Your Name",
    author_email="your.email@example.com",
    description="A CLI tool for {idea}",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/{project_name}",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)""",
            "README.md": f"""# {project_name.replace('_', ' ').title()}

A command-line tool for {idea}.

## Installation

```bash
pip install -e .
```

## Usage

```bash
{project_name} --help
{project_name} --input data.txt --output result.txt
```

## Features

- Command-line interface
- Rich output formatting
- Configurable options
- Easy to extend

## Development

1. Install in development mode:
```bash
pip install -e .
```

2. Run the tool:
```bash
python {project_name}.py --help
```
"""
        }
        
        return self.create_project_structure(project_name, structure)
    
    def create_generic_project(self, project_name: str, idea: str):
        """Create a generic project"""
        structure = {
            "main.py": f"""#!/usr/bin/env python3
\"\"\"
{project_name.replace('_', ' ').title()}
{idea}
\"\"\"

def main():
    print("Hello from {project_name}!")
    print("This project is for: {idea}")
    
    # Your main logic here
    process_data()
    
def process_data():
    \"\"\"Process data for the project\"\"\"
    print("Processing data...")
    # Add your processing logic here
    
if __name__ == "__main__":
    main()
""",
            "requirements.txt": "# Add your dependencies here\n# Example:\n# requests==2.31.0\n# pandas==2.1.3\n",
            "config.py": """# Configuration file
import os

# Default configuration
DEFAULT_CONFIG = {
    "debug": True,
    "log_level": "INFO",
    "output_dir": "output",
}

# Load configuration from environment variables
def get_config():
    config = DEFAULT_CONFIG.copy()
    
    # Override with environment variables
    if os.getenv("DEBUG"):
        config["debug"] = os.getenv("DEBUG").lower() == "true"
    
    if os.getenv("LOG_LEVEL"):
        config["log_level"] = os.getenv("LOG_LEVEL")
    
    if os.getenv("OUTPUT_DIR"):
        config["output_dir"] = os.getenv("OUTPUT_DIR")
    
    return config
""",
            "utils.py": """# Utility functions
import os
import json
from pathlib import Path

def ensure_dir(directory):
    \"\"\"Ensure a directory exists\"\"\"
    Path(directory).mkdir(parents=True, exist_ok=True)

def save_json(data, filepath):
    \"\"\"Save data as JSON\"\"\"
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)

def load_json(filepath):
    \"\"\"Load data from JSON\"\"\"
    with open(filepath, 'r') as f:
        return json.load(f)

def list_files(directory, pattern="*"):
    \"\"\"List files in directory matching pattern\"\"\"
    return list(Path(directory).glob(pattern))
""",
            "README.md": f"""# {project_name.replace('_', ' ').title()}

{idea}

## Setup

1. Install dependencies (if any):
```bash
pip install -r requirements.txt
```

2. Run the project:
```bash
python main.py
```

## Project Structure

- `main.py` - Main application file
- `config.py` - Configuration management
- `utils.py` - Utility functions
- `requirements.txt` - Python dependencies

## Features

- Modular design
- Configuration management
- Utility functions
- Easy to extend

## Development

1. Modify `main.py` to implement your logic
2. Add dependencies to `requirements.txt`
3. Use `config.py` for configuration
4. Add utility functions to `utils.py`
"""
        }
        
        return self.create_project_structure(project_name, structure)

def main():
    """Main function to run the AI Code Generator"""
    generator = AICodeGenerator()
    
    print("🤖 AI Code Generator for Windows 11 - Local AI Coding Assistant")
    print("=" * 60)
    print("This tool can create files, generate code, and help you build projects!")
    print("Works perfectly on Windows 11!")
    print()
    
    while True:
        print("\nOptions:")
        print("1. Create a new project from an idea")
        print("2. Generate code for a specific task")
        print("3. Create a single file")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == "1":
            idea = input("Describe your project idea: ").strip()
            if idea:
                project_path = generator.create_project_from_idea(idea)
                print(f"\n🎉 Project created successfully at: {project_path}")
                print("You can now start coding!")
        
        elif choice == "2":
            task = input("Describe the code you want to generate: ").strip()
            language = input("Language (python/javascript/html/batch): ").strip().lower() or "python"
            if task:
                code = generator.generate_code(task, language)
                print(f"\nGenerated code:\n{'-' * 40}")
                print(code)
                
                save = input("\nSave to file? (y/n): ").strip().lower()
                if save == 'y':
                    filename = input("Filename: ").strip()
                    if filename:
                        generator.create_file(filename, code)
        
        elif choice == "3":
            filename = input("Filename: ").strip()
            content = input("File content: ").strip()
            if filename and content:
                generator.create_file(filename, content)
        
        elif choice == "4":
            print("Goodbye! 👋")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()