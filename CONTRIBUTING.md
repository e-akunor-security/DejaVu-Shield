# Contributing to DejaVu Shield

Thank you for your interest in contributing to DejaVu Shield! We welcome contributions from the community.

## 📋 Code of Conduct

Please be respectful and constructive in all interactions. We are committed to providing a welcoming and inclusive environment.

---

## 🚀 Getting Started

### 1. Fork and Clone

```bash
# Fork the repository on GitHub
# Clone your fork
git clone https://github.com/YOUR_USERNAME/DejaVu-Shield.git
cd DejaVu-Shield

# Add upstream remote
git remote add upstream https://github.com/e-akunor-security/DejaVu-Shield.git
```

### 2. Set Up Development Environment

```bash
# Create virtual environment
python -m venv venv

# Activate it
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install development tools
pip install pytest black flake8 pylint
```

### 3. Create Feature Branch

```bash
# Update main branch
git checkout main
git pull upstream main

# Create your feature branch
git checkout -b feature/your-feature-name
```

---

## 💻 Development Guidelines

### Code Style

We follow **PEP 8** standards. Use these tools to maintain consistency:

```bash
# Format code with Black
black .

# Check code quality with Flake8
flake8 --max-line-length=100

# Detailed linting with Pylint
pylint *.py
```

### Commit Messages

Follow this format:

```
type: subject line (max 50 characters)

Body (max 72 characters per line, optional)

Fixes #issue_number
```

**Types:**
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `style:` Code style (formatting)
- `refactor:` Code refactoring
- `test:` Test additions/changes
- `chore:` Build, dependencies, etc.

**Examples:**
```
feat: Add URL filtering capability
fix: Resolve API timeout issue
docs: Update installation instructions
```

### Testing

Write tests for new features:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=.

# Run specific test file
pytest tests/test_module.py
```

---

## 🔍 Pull Request Process

### Before Submitting

1. **Sync your branch** with the latest main:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Test your changes**:
   ```bash
   pytest
   black --check .
   flake8 .
   ```

3. **Verify your implementation** locally

### Submitting a PR

1. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Create Pull Request with:
   - Clear title describing the change
   - Detailed description of what and why
   - Reference to related issues (Fixes #123)
   - Checklist completion (use the template)

3. Request review from maintainers

### PR Checklist

```
- [ ] Code follows PEP 8 style guidelines
- [ ] Tests added/updated for new functionality
- [ ] Documentation updated if needed
- [ ] Commit messages are clear and descriptive
- [ ] No unrelated changes included
- [ ] Verified locally (pytest, flake8, black)
- [ ] Resolves #issue_number
```

---

## 🐛 Bug Reports

Found a bug? Submit an issue with:

1. **Clear description** - What happened vs. what was expected
2. **Steps to reproduce** - Exact steps to replicate
3. **Environment info**:
   - Python version
   - OS (Windows/macOS/Linux)
   - DejaVu Shield version
4. **Error messages/logs** - Full stack traces
5. **Screenshots** - If applicable

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md)

---

## 💡 Feature Requests

Have an idea? Share it:

1. **Use case** - Why is this needed?
2. **Expected behavior** - What should happen?
3. **Alternative solutions** - Any workarounds?
4. **Examples** - Use cases or mockups

Use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md)

---

## 📚 Project Structure

```
DejaVu-Shield/
├── main.py              # Application entry point
├── config/
│   └── settings.py      # Configuration settings
├── ui/
│   └── gui.py          # Tkinter UI components
├── core/
│   ├── scanner.py      # Threat scanning logic
│   └── analyzer.py     # URL analysis logic
├── api/
│   └── virustotal.py   # VirusTotal API integration
├── utils/
│   ├── logger.py       # Logging utilities
│   └── helpers.py      # Helper functions
├── tests/
│   └── test_*.py       # Unit tests
├── requirements.txt    # Dependencies
└── README.md          # Documentation
```

---

## 🔐 Security

### Security Issues

**Do not create public issues for security vulnerabilities.**

Please report security issues privately to: [security contact info]

Include:
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if applicable)

---

## 📖 Documentation

### Writing Documentation

- Use clear, simple English
- Include code examples
- Update README.md for major changes
- Add docstrings to functions:

```python
def analyze_url(url: str) -> dict:
    """
    Analyze URL for threats using VirusTotal API.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Analysis results with threat information
        
    Raises:
        ValueError: If URL format is invalid
    """
```

---

## 🎯 Contribution Areas

### High Priority
- Security improvements
- Performance optimization
- Bug fixes
- Documentation

### Welcome Contributions
- New features (discuss in issues first)
- UI/UX improvements
- Additional API integrations
- Code examples

### For Beginners
- Documentation improvements
- Unit test coverage
- Code examples
- Bug fixes labeled "good first issue"

---

## ✅ Review Process

All contributions go through:

1. **Automated checks** - Tests, linting, formatting
2. **Code review** - One or more maintainers
3. **Feedback cycle** - We may request changes
4. **Approval** - Maintainer approval required
5. **Merge** - Rebased and merged to main

### Review Expectations

- We aim to review within 5 business days
- Be responsive to feedback
- Quality over speed
- Questions? Ask in the PR discussion

---

## 🎉 Recognition

Contributors will be:
- Mentioned in CHANGELOG
- Added to contributors list
- Recognized in release notes

---

## 📞 Questions?

- 💬 **Discussions**: [GitHub Discussions](../../discussions)
- 📧 **Email**: [maintainer email]
- 🔗 **Issues**: [GitHub Issues](../../issues)

---

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to DejaVu Shield! 🙏**
