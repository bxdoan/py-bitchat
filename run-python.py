#!/usr/bin/env python3
"""
Launch script for BitChat Terminal Python

Usage:
    python run-python.py           # Run normally
    python run-python.py -d       # Basic debug mode  
    python run-python.py -dd      # Verbose debug mode
"""

import sys
import subprocess
from pathlib import Path

def main():
    """Launch BitChat Terminal Python"""
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or newer required")
        print(f"Current version: {sys.version}")
        return 1
    
    # Check if src module exists
    src_py_path = Path(__file__).parent / "src"
    if not src_py_path.exists():
        print("❌ src directory not found")
        print("Make sure you're in the project root directory")
        return 1
    
    # Prepare command
    cmd = [sys.executable, "-m", "src.main"]
    
    # Add debug arguments
    for arg in sys.argv[1:]:
        if arg in ["-d", "--debug", "-dd", "--debug-full"]:
            cmd.append(arg)
    
    try:
        print("🚀 Launching BitChat Terminal Python...")
        print(f"📁 Directory: {Path.cwd()}")
        print(f"🐍 Python: {sys.executable}")
        print(f"🔧 Command: {' '.join(cmd)}")
        print()
        
        # Run application
        subprocess.run(cmd, check=True)
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Error running application: {e}")
        return e.returncode
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        return 0
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 