#!/bin/bash

# Create project directory
mkdir -p security-research-toolkit
cd security-research-toolkit

# Create requirements.txt
cat > requirements.txt << 'REQ'
requests>=2.25.1
REQ

# Create .gitignore
cat > .gitignore << 'GIT'
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST
venv/
env/
ENV/
security_env/
results/
*.db
*.sqlite3
*.db-journal
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db
*.log
logs/
*.tmp
*.temp
GIT

# Create LICENSE
cat > LICENSE << 'LIC'
MIT License

Copyright (c) 2025 [YOUR NAME]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
LIC

# Create empty files
touch security_toolkit.py README.md setup.py

echo "✅ Project structure created!"
echo "📁 Files created:"
ls -la

echo ""
echo "🔧 Next steps:"
echo "1. Edit security_toolkit.py - add your main code"
echo "2. Edit README.md - add project description"
echo "3. Edit setup.py - add project metadata"
echo "4. Replace [YOUR NAME] in LICENSE"
