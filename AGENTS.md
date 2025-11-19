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
- **Run single test**: `python -m pytest tests/ -v` (if tests exist)
- **CI/CD**: GitHub Actions workflow in `.github/workflows/ci.yml`
- **Release**: Automated binary builds on version tags in `.github/workflows/build-release.yml`

## Code Style Guidelines
- **Python**: 3.7+ required
- **Imports**: Group standard library, third-party, local; sort alphabetically
- **Naming**: snake_case for functions/variables, PascalCase for classes
- **Types**: Use type hints for all function parameters and return values
- **Data structures**: Use dataclasses for structured data
- **Docstrings**: Required for classes and public functions
- **Error handling**: Use try/except with specific exceptions
- **Formatting**: 4-space indentation, 88-char line length
- **Comments**: No inline comments unless complex logic requires explanation
- **Linting**: Use `flake8` and `black` for code quality</content>
<parameter name="filePath">C:\Users\electron377\Desktop\opencode-test\AGENTS.md