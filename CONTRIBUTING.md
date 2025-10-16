# Contributing to RSAXploit

Thank you for your interest in contributing to RSAXploit! This document provides guidelines and information for contributors.

## 🤝 How to Contribute

### Reporting Bugs
- Use the GitHub issue tracker
- Provide clear reproduction steps
- Include system information (OS, Python version)
- Attach sample input files if relevant

### Suggesting Features
- Check existing issues first
- Describe the use case and benefits
- Provide implementation ideas if possible

### Submitting Code
1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes
4. Add tests for new functionality
5. Run the test suite: `./test.sh`
6. Submit a pull request

## 🧪 Testing

Before submitting changes:
```bash
# Run the full test suite
./test.sh

# Test with specific scenarios
python3 rsaxploit.py -n 143 -e 3 --decrypt 123
```

## 📝 Code Style

- Follow PEP 8 conventions
- Use meaningful variable names
- Add docstrings for new functions
- Maintain the existing code structure

## 🚀 Priority Areas

We welcome contributions in these areas:

### New Attack Methods
- **Boneh-Durfee Attack** - Better than Wiener for d < N^0.292
- **LSB/MSB Oracle Attacks** - Bit-by-bit plaintext recovery
- **Franklin-Reiter Attack** - Related message attacks
- **Blinding Attacks** - RSA signature forgery

### Enhanced Features
- **Configuration files** - YAML/JSON config support
- **Plugin system** - External attack modules
- **Web interface** - Browser-based UI
- **Performance optimization** - Multiprocessing support

### Input/Output Improvements
- **More file formats** - XML, YAML, TOML support
- **Database integration** - SQLite results storage
- **Export formats** - CSV, JSON result export
- **Visualization** - Attack success graphs

## 🏗️ Architecture Guidelines

When adding new attacks:
1. Inherit from the `Attack` base class
2. Set appropriate `priority` (lower = runs first)
3. Implement `can_run()` and `run()` methods
4. Add timing estimates to `ESTIMATED_SECONDS`
5. Include the attack in `ALL_ATTACKS` list

Example:
```python
class NewAttack(Attack):
    name = "new_attack"
    priority = 50  # Medium priority
    
    def can_run(self, keys, c_list, args):
        return len(keys) >= 1 and len(c_list) >= 1
    
    def run(self, keys, c_list, args, log):
        # Implementation here
        return AttackResult(self.name, success, plaintext, info)
```

## 📋 Pull Request Checklist

- [ ] Code follows existing style and patterns
- [ ] New attacks include comprehensive tests
- [ ] Documentation updated (README.md, docstrings)
- [ ] Test suite passes: `./test.sh`
- [ ] No regression in existing functionality
- [ ] Commit messages are descriptive

## 🎯 CTF-Specific Considerations

RSAXploit is designed for CTF competitions, so:
- Prioritize attacks commonly seen in CTFs
- Ensure fast execution for time-limited contests
- Support diverse input formats from challenge platforms
- Maintain backward compatibility

## 📞 Getting Help

- Open a GitHub issue for questions
- Check existing issues and documentation
- Contact the maintainer for major changes

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make RSAXploit better! 🚀