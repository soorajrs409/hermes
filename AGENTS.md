# AGENTS.md - Development Guidelines for Hermes Access Bypass Tester

## Build/Lint/Test Commands

### Installation
```bash
pip install -r requirements.txt
```

### Running the Tool
```bash
# Test single URL
python access_bypass_tester_v2.py -u https://example.com/admin

# Test multiple URLs from file
python access_bypass_tester_v2.py -f urls.txt

# Run with custom config
python access_bypass_tester_v2.py -u https://example.com/admin -c config.yaml
```

### Testing
No formal test framework is configured. The tool includes internal testing methods within the `AccessBypassTester` class:
- `test_single_technique()` - Tests individual bypass techniques
- `test_url()` - Tests a single URL with all techniques
- `test_urls_multithreaded()` - Tests multiple URLs concurrently

## Code Style Guidelines

### Imports
- Standard library imports first, then third-party packages
- Group imports logically with blank lines between groups
- Use absolute imports
- Example:
```python
import argparse
import sys
import json
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
import requests
import yaml
from bs4 import BeautifulSoup
```

### Naming Conventions
- **Classes**: PascalCase (e.g., `AccessBypassTester`, `BypassResult`)
- **Functions/Methods**: snake_case (e.g., `test_url()`, `make_request()`)
- **Variables**: snake_case (e.g., `original_response`, `bypass_results`)
- **Constants**: UPPER_CASE (not extensively used in this codebase)

### Type Hints
- Use type hints for function parameters and return values
- Import from `typing` module: `List`, `Dict`, `Optional`, `Tuple`
- Example:
```python
def test_url(self, url: str) -> ScanResult:
    pass
```

### Data Classes
- Use `@dataclass` decorator for simple data structures
- Include type hints for all fields
- Example:
```python
@dataclass
class BypassResult:
    url: str
    technique: str
    payload: str
    status_code: int
    response_size: int
    content_hash: str
    severity: str
    confidence: float
    description: str
    response_preview: str = ""
```

### Error Handling
- Use try/except blocks for network operations and file I/O
- Keep exception handling specific rather than catching all exceptions
- Log errors appropriately but don't expose sensitive information
- Example:
```python
try:
    response = self.make_request(test_url, allow_redirects=False)
    if response:
        results.append((test_url, response.status_code, response))
except Exception as e:
    # Handle specific exceptions appropriately
    pass
```

### Documentation
- Use docstrings for all classes and public methods
- Keep docstrings concise but descriptive
- Example:
```python
def path_traversal_bypass(self, url, original_response):
    """Test path traversal techniques"""
    pass
```

### Code Structure
- Group related methods together in classes
- Use private methods (prefixed with `_`) for internal helpers
- Keep methods focused on single responsibilities
- Use meaningful variable names that describe their purpose

### Security Considerations
- Never log or print sensitive information (API keys, tokens, credentials)
- Handle user input validation appropriately
- Use secure defaults for network operations
- Follow principle of least privilege

### Performance
- Use appropriate data structures (dicts for lookups, lists for sequences)
- Implement caching where beneficial (response cache is used)
- Consider memory usage for large result sets
- Use concurrent processing for I/O bound operations</content>
<parameter name="filePath">C:\Users\electron377\Desktop\hermes\AGENTS.md