# Agent Guidelines for Access Control Bypass Tester

## Build Commands
- **Install dependencies**: `pip install -r requirements.txt`
- **Build binary**: `./build.sh`
- **Run script**: `python access_bypass_tester_v2.py`
- **Run binary**: `./dist/access-bypass-tester`

## Test Commands
- **Basic functionality**: `./demo-config.sh`
- **Single URL test**: `python access_bypass_tester_v2.py -u https://example.com/admin`
- **File test**: `python access_bypass_tester_v2.py -f urls.txt`
- **CI/CD**: GitHub Actions in `.github/workflows/ci.yml`
- **Import test**: `python -c "import access_bypass_tester_v2"`
- **Unit test single technique**: `python access_bypass_tester_v2.py -u https://example.com/admin --verbose`

## Code Style Guidelines
- **Python**: 3.7+ required
- **Imports**: Group stdlib, third-party, local; sort alphabetically within groups
- **Naming**: snake_case functions/variables, PascalCase classes, UPPER_CASE constants
- **Types**: Type hints for all parameters and return values
- **Data structures**: Use dataclasses for structured data with @dataclass decorator
- **Docstrings**: Required for classes and public functions (Google/NumPy style)
- **Error handling**: try/except with specific exceptions, avoid bare except
- **Formatting**: 4-space indentation, 88-char line length (Black compatible)
- **Comments**: No inline comments unless complex logic; prefer descriptive names
- **Linting**: `flake8` and `black` for code quality
- **Security**: Never log or expose secrets/keys; validate all inputs</content>
<parameter name="filePath">C:\Users\electron377\Desktop\opencode-test\AGENTS.md