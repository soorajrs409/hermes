# Access Control Bypass Tester v2.0

An advanced Python tool for testing access control bypass techniques on web pages that return 403 Forbidden responses. Features intelligent response analysis, multi-threading, and comprehensive vulnerability detection. Designed for bug bounty hunters and penetration testers.

## Features

- **Multiple Input Methods**: Test single URLs or load URLs from a text file
- **Intelligent Response Analysis**: Analyzes response content, not just status codes
- **Multi-threading**: Concurrent testing for improved performance
- **Comprehensive Bypass Techniques** (12+ built-in + 25+ custom techniques):
  - **Built-in Techniques**:
    - Path traversal (../, ..;/, etc.)
    - Case manipulation
    - Header manipulation (X-Forwarded-For, X-Originating-IP, etc.)
    - URL encoding/double encoding bypasses
    - HTTP method testing (HEAD, POST, PUT, DELETE, etc.)
    - Parameter-based bypasses
    - SQL injection in paths
    - GraphQL endpoint detection
    - JWT token manipulation
    - Cookie-based bypasses
    - Trailing slash variations
  - **Custom Techniques via Config** (25+ research-backed assessments):
    - Network-level bypasses (internal IPs, localhost, IPv6)
    - Host header attacks
    - Authentication bypasses (API keys, JWT, basic auth)
    - User-Agent spoofing (admin, crawlers, internal tools)
    - Referer-based attacks
    - Parameter pollution attacks
    - Protocol manipulation (HTTP/2, WebSocket upgrades)
    - Encoding bypasses (Unicode, hex, custom)
    - Time-based bypasses
    - CORS and origin bypasses
- **Advanced Detection**: Content analysis, confidence scoring, false positive reduction
- **Vulnerability Scoring**: CVSS-like severity ratings (Critical, High, Medium, Low, Info)
- **Configuration Files**: YAML-based config for custom techniques and settings
- **Proxy Support**: HTTP/SOCKS proxy support for testing through Burp/ZAP
- **Reporting**: JSON export and interactive HTML reports with charts
- **Performance**: Request caching, retry logic, configurable timeouts
- **Rate Limiting**: Configurable delays with exponential backoff

## Installation

### Option 1: Install as Python Package (Recommended for Development)

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Run the tool:
```bash
python access_bypass_tester_v2.py --help
```

### Option 2: Install as Linux Binary (Recommended for Production)

1. **Download from GitHub Releases:**
   - Go to the [Releases](https://github.com/yourusername/access-bypass-tester/releases) page
   - Download the latest `access-bypass-tester-linux-x64.tar.gz`
   - Verify checksum: `sha256sum access-bypass-tester-linux-x64.tar.gz`

2. **Install globally:**
```bash
tar -xzf access-bypass-tester-linux-x64.tar.gz
sudo cp access-bypass-tester /usr/local/bin/
sudo chmod +x /usr/local/bin/access-bypass-tester
```

3. **Test installation:**
```bash
access-bypass-tester --help
```

### Option 3: Build from Source

1. Clone the repository and install dependencies:
```bash
git clone https://github.com/yourusername/access-bypass-tester.git
cd access-bypass-tester
pip install -r requirements.txt
```

2. Build binary locally:
```bash
chmod +x build.sh
./build.sh
```

3. Test the binary (optional):
```bash
chmod +x demo-config.sh
./demo-config.sh
```

4. Install the built binary:
```bash
sudo cp dist/access-bypass-tester /usr/local/bin/
```

## Configuration (Optional)

The binary includes comprehensive embedded configuration with 25+ bypass techniques. For advanced customization, you can create a `config.yaml` file:

```yaml
user_agent: "Custom User-Agent String"
techniques:
  path_traversal: true
  sql_injection: true
  jwt_manipulation: true
  graphql: false
severity_weights:
  critical: 9.0
  high: 7.0
  medium: 5.0
  low: 3.0
  info: 1.0
custom_techniques:
  - name: "custom_header"
    method: "GET"
    headers:
      X-Custom: "admin"
    url_suffix: "?debug=1"
```

## Usage

## Usage

### Basic Usage

**If installed as binary:**
```bash
# Test a single URL
access-bypass-tester -u https://example.com/admin

# Test multiple URLs from a file
access-bypass-tester -f urls.txt
```

**If using Python directly:**
```bash
# Test a single URL
python access_bypass_tester_v2.py -u https://example.com/admin

# Test multiple URLs from a file
python access_bypass_tester_v2.py -f urls.txt
```

### Advanced Usage

**With multi-threading and custom config:**
```bash
# Using binary
access-bypass-tester -f urls.txt -t 10 -c config.yaml --proxy http://127.0.0.1:8080

# Using Python
python access_bypass_tester_v2.py -f urls.txt -t 10 -c config.yaml --proxy http://127.0.0.1:8080
```

**Generate HTML report:**
```bash
# Using binary
access-bypass-tester -u https://example.com/admin --html-report report.html -v

# Using Python
python access_bypass_tester_v2.py -u https://example.com/admin --html-report report.html -v
```

### Command-line Options

- `-u, --url`: Single URL to test
- `-f, --file`: File containing URLs to test (one per line)
- `-c, --config`: YAML configuration file (optional - embedded config used by default)
- `-d, --delay`: Delay between requests in seconds (default: 1.0)
- `-t, --threads`: Number of threads for concurrent testing (default: 5)
- `--proxy`: HTTP proxy URL (http://proxy:port or socks5://proxy:port)
- `--timeout`: Request timeout in seconds (default: 10)
- `-o, --output`: Output file for results (JSON format)
- `--html-report`: Generate interactive HTML report
- `--user-agent`: Custom User-Agent string
- `-v, --verbose`: Enable verbose output

## URL File Format

Create a text file with one URL per line:
```
https://example.com/admin
https://example.com/dashboard
https://example.com/config
```

Lines starting with `#` are treated as comments and ignored.

## Advanced Features

### Multi-threading
- Concurrent URL testing for improved performance
- Configurable thread pool size
- Progress bars for long scans

### Intelligent Detection
- **Content Analysis**: Detects admin panels, forms, and sensitive data
- **False Positive Reduction**: Advanced filtering based on response characteristics
- **Confidence Scoring**: AI-powered assessment of bypass success likelihood

### Proxy Support
- HTTP/SOCKS proxy support for testing through intercepting proxies
- Session persistence across requests
- Automatic proxy detection

### Custom Techniques
The tool includes **25+ research-backed custom techniques** covering real-world bypass scenarios from bug bounty reports. Define additional techniques in YAML config:
```yaml
custom_techniques:
  # Network-level bypasses
  - name: "internal_network_bypass"
    method: "GET"
    headers:
      X-Forwarded-For: "192.168.1.1"
      X-Real-IP: "10.0.0.1"
      X-Originating-IP: "172.16.0.1"

  # Host header attacks
  - name: "host_header_bypass"
    method: "GET"
    headers:
      Host: "localhost"
      X-Forwarded-Host: "127.0.0.1"

  # Authentication bypasses
  - name: "api_key_bypass"
    method: "GET"
    headers:
      X-API-Key: "admin"
      Authorization: "Bearer admin"

  # Parameter pollution
  - name: "param_pollution_admin"
    method: "GET"
    url_suffix: "?role=user&role=admin"

  # And 20+ more techniques including:
  # - User-Agent spoofing (admin, crawlers, internal tools)
  # - Authentication bypasses (API keys, JWT tokens, basic auth)
  # - Protocol manipulation (HTTP/2, WebSocket upgrades)
  # - Encoding bypasses (Unicode, hex, custom encodings)
  # - Time-based and CORS bypasses
```

### Embedded Configuration

The binary comes with **25+ embedded bypass techniques** covering comprehensive attack vectors. The embedded configuration includes:

#### Built-in Technique Categories:
- **Network Infrastructure**: Internal IPs, localhost, IPv6 bypasses
- **Web Application**: Host headers, debug parameters, maintenance modes
- **Authentication Systems**: API keys, JWT, basic auth, session manipulation
- **Client-Side Controls**: User-Agent, Referer, Origin validation
- **Protocol-Level**: HTTP methods, headers, encoding schemes
- **API Endpoints**: GraphQL, REST API, WebSocket upgrades
- **Parameter Handling**: Pollution attacks, type juggling, encoding bypasses

#### Customization Options:
- **External Config Files**: Override defaults with `-c config.yaml` (completely optional)
- **Runtime Configuration**: All embedded techniques work out-of-the-box
- **Selective Testing**: Enable/disable specific techniques via external config

**The binary is completely self-contained** - no external files required for full functionality!

#### Config File Resolution (Binary):
When using the binary with `-c config.yaml`, it searches for the config file in:
1. **Current working directory**: `./config.yaml`
2. **Absolute path**: `/full/path/to/config.yaml`
3. **Script directory**: Same directory as the binary

**Example (Optional):**
```bash
# With custom config (optional - embedded config used by default)
access-bypass-tester -u https://example.com/admin -c my-config.yaml

# No config needed - uses embedded 25+ techniques automatically
access-bypass-tester -u https://example.com/admin
```

**Binary Behavior:**
- The compiled binary can read config files from any accessible path (optional)
- Config files are loaded at runtime, not compile-time
- If no config file is provided, embedded configuration is used automatically
- Use `access-bypass-tester -c config.yaml --help` to verify config loading (optional)

## Output

The tool provides comprehensive output including:

- **Console Output**: Real-time progress with bypass detection
- **Severity Scoring**: Each bypass is rated Critical/High/Medium/Low/Info
- **Confidence Levels**: AI-powered analysis of bypass success likelihood
- **Content Analysis**: Detection of admin panels, forms, and sensitive content
- **Performance Metrics**: Scan duration, techniques tested, success rates

### Example Output

```
$ python access_bypass_tester_v2.py -u https://example.com/admin -v

[*] Testing URL: https://example.com/admin
[+] Original response: 403 (size: 234 bytes)

[+] Scan completed!
[+] Total bypasses found: 3

[+] Severity breakdown:
  - CRITICAL: 1
  - HIGH: 1
  - MEDIUM: 1

[+] Detailed bypasses:
  - SQL Injection (Critical, 95% confidence): https://example.com/admin' OR '1'='1 -> 200
    Content analysis: Admin keywords found (5); Forms detected (2)
  - Header Manipulation (High, 87% confidence): https://example.com/admin -> 200
    Content analysis: Response size increased (3.2x); Interactive elements found (4)
  - Parameter Bypass (Medium, 76% confidence): https://example.com/admin?admin=true -> 200
    Content analysis: Success indicators found (2)
```

### JSON Output Format

Results are saved in structured JSON format:
```json
{
  "https://example.com/admin": {
    "target_url": "https://example.com/admin",
    "original_status": 403,
    "original_size": 234,
    "original_hash": "a1b2c3...",
    "bypasses_found": [
      {
        "url": "https://example.com/admin' OR '1'='1",
        "technique": "sql_injection",
        "payload": "' OR '1'='1",
        "status_code": 200,
        "response_size": 15432,
        "content_hash": "d4e5f6...",
        "severity": "critical",
        "confidence": 0.95,
        "description": "Admin keywords found (5); Forms detected (2)",
        "response_preview": "<html><head><title>Admin Panel</title>..."
      }
    ],
    "scan_duration": 12.34,
    "techniques_tested": 12,
    "timestamp": "2024-01-15 10:30:45"
  }
}
```

### HTML Reports

Generate interactive HTML reports with charts and detailed analysis:
```bash
python access_bypass_tester_v2.py -f urls.txt --html-report scan_report.html
```

HTML reports include:
- Executive summary with statistics
- Severity distribution charts
- Detailed bypass information
- Response previews
- Scan performance metrics

## Legal Notice

This tool is intended for authorized security testing only. Use only on systems you have explicit permission to test. The authors are not responsible for misuse.