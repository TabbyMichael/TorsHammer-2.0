# Installation Guide

## Requirements

### System Requirements

- **Python 3.11 or higher** - Required for asyncio features and type hints
- **Network connectivity** - To reach target systems
- **File descriptors** - Sufficient ulimit for desired concurrency (typically 1024+)

### Optional Requirements

- **Tor** - Running on `127.0.0.1:9050` for `--tor` flag
- **Proxy servers** - SOCKS5, SOCKS4a, or HTTP CONNECT proxies
- **Virtual environment** - Recommended for isolation

### Platform Support

- **Linux** - Fully supported
- **macOS** - Fully supported
- **Windows** - Fully supported

## Installation Methods

### Method 1: pip install (Recommended)

Install from the local directory:

```bash
cd /path/to/torshammer
pip install -e .
```

The `-e` flag creates an editable installation, allowing you to modify the code without reinstalling.

### Method 2: Development Installation

For development with testing dependencies:

```bash
cd /path/to/torshammer
pip install -e ".[dev]"
```

This installs additional dependencies:
- `pytest>=8` - Test framework
- `pytest-asyncio>=0.23` - Async test support

### Method 3: Direct Python Execution

Without installation (requires adding src to PYTHONPATH):

```bash
cd /path/to/torshammer
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
python -m torshammer --help
```

## Platform-Specific Instructions

### Linux

#### Debian/Ubuntu

```bash
# Install Python 3.11+ if not available
sudo apt update
sudo apt install python3.11 python3.11-venv python3-pip

# Clone or download the repository
cd /path/to/torshammer

# Create virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# Install
pip install -e .

# Verify installation
torshammer --version
```

#### Fedora/RHEL

```bash
# Install Python 3.11+ if not available
sudo dnf install python3.11 python3.11-pip

# Clone or download the repository
cd /path/to/torshammer

# Create virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# Install
pip install -e .

# Verify installation
torshammer --version
```

#### Arch Linux

```bash
# Install Python 3.11+ if not available
sudo pacman -S python python-pip

# Clone or download the repository
cd /path/to/torshammer

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install
pip install -e .

# Verify installation
torshammer --version
```

### macOS

#### Using Homebrew

```bash
# Install Python 3.11+ if not available
brew install python@3.11

# Clone or download the repository
cd /path/to/torshammer

# Create virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# Install
pip install -e .

# Verify installation
torshammer --version
```

#### Using System Python

```bash
# Clone or download the repository
cd /path/to/torshammer

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install
pip install -e .

# Verify installation
torshammer --version
```

### Windows

#### Using Command Prompt

```cmd
REM Install Python 3.11+ from python.com if not available
REM Ensure "Add Python to PATH" is checked during installation

cd C:\path\to\torshammer

REM Create virtual environment
python -m venv .venv

REM Activate virtual environment
.venv\Scripts\activate

REM Install
pip install -e .

REM Verify installation
torshammer --version
```

#### Using PowerShell

```powershell
# Install Python 3.11+ from python.com if not available
# Ensure "Add Python to PATH" is checked during installation

cd C:\path\to\torshammer

# Create virtual environment
python -m venv .venv

# Activate virtual environment
.venv\Scripts\Activate.ps1

# Install
pip install -e .

# Verify installation
torshammer --version
```

## Verification

After installation, verify the tool is working:

```bash
# Check version
torshammer --version

# Display help
torshammer --help

# Test with dry-run (no actual attack)
torshammer -u http://127.0.0.1:1 -c 1 -d 0.1
```

Expected output:
```
/*  Tor's Hammer 2.0.0
 *  Slow-requests DoS/Vulnerability testing tool (asyncio rewrite)
 *  Target: http://127.0.0.1:1/   Mode: slow-post   Connections: 1
 *
 *  LEGAL: You may only use this against systems you own or are
 *  explicitly authorized to test. Unauthorized denial-of-service
 *  activity is illegal in most jurisdictions.
 */
```

## Upgrading

To upgrade to the latest version:

```bash
# Activate virtual environment
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate  # Windows

# Reinstall
pip install -e .
```

## Uninstallation

To remove the tool:

```bash
# Activate virtual environment
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate  # Windows

# Uninstall
pip uninstall torshammer

# Optionally remove virtual environment
deactivate
rm -rf .venv  # Linux/macOS
# or
rmdir /s .venv  # Windows
```

## Troubleshooting Installation

### Python Version Too Old

**Error:** `Python 3.11 or higher is required`

**Solution:** Install Python 3.11 or higher from your package manager or python.com

### Permission Denied

**Error:** `Permission denied` when creating virtual environment

**Solution:** Use a user-writable directory or run with appropriate permissions:

```bash
# Use user-writable directory
python3.11 -m venv ~/.venv-torshammer
source ~/.venv-torshammer/bin/activate
pip install -e /path/to/torshammer
```

### pip Not Found

**Error:** `pip: command not found`

**Solution:** Install pip:

```bash
# Debian/Ubuntu
sudo apt install python3-pip

# Fedora/RHEL
sudo dnf install python3-pip

# macOS
brew install python
```

### SSL Certificate Issues

**Error:** SSL certificate verification failures during pip install

**Solution:** Use trusted certificates or temporarily disable verification (not recommended):

```bash
# Better: update certificates
sudo apt install ca-certificates  # Debian/Ubuntu

# Temporary workaround (not recommended)
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -e .
```

### Virtual Environment Activation Fails

**Error:** Script activation fails on Windows

**Solution:** Check PowerShell execution policy:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Tor Installation (Optional)

If you want to use the `--tor` flag:

### Linux

```bash
# Debian/Ubuntu
sudo apt install tor

# Fedora/RHEL
sudo dnf install tor

# Arch Linux
sudo pacman -S tor

# Start Tor
sudo systemctl start tor
sudo systemctl enable tor  # Enable on boot
```

### macOS

```bash
brew install tor
brew services start tor
```

### Windows

Download and install from: https://www.torproject.org/download/

Verify Tor is running on `127.0.0.1:9050`:

```bash
curl --socks5 127.0.0.1:9050 https://check.torproject.org
```

## File Descriptor Limits

For high concurrency (1000+ connections), you may need to increase file descriptor limits:

### Linux

```bash
# Check current limit
ulimit -n

# Temporary increase (current session only)
ulimit -n 65536

# Permanent increase (add to ~/.bashrc or /etc/security/limits.conf)
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf
```

### macOS

```bash
# Check current limit
ulimit -n

# Temporary increase
ulimit -n 65536

# Permanent increase (create/modify ~/Library/LaunchAgents/limit.maxfiles.plist)
```

### Windows

Windows typically has higher default limits. If you encounter issues, consider:

- Reducing concurrency with `-c` flag
- Using multiple instances with lower concurrency each

## Dependencies

Torshammer 2.0 has **zero runtime dependencies** - it uses only Python 3.11+ standard library.

### Development Dependencies

Only required for running tests:

- `pytest>=8` - Test framework
- `pytest-asyncio>=0.23` - Async test support

These are installed via `pip install -e ".[dev]"`.

## Next Steps

After installation:

1. Read the [CLI Reference](cli.md) for command-line options
2. Review [Security Documentation](security.md) before use
3. Check [Attack Modes](attack-modes.md) to understand available vectors
4. See [Examples](../README.md#usage) for common usage patterns
