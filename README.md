# RSAXploit

**The Ultimate RSA Attack Framework for CTF & Security Testing**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/shoaibsr7/RSAXploit)

RSAXploit is a comprehensive, automated RSA cryptanalysis framework designed specifically for CTF competitions and security research. It features 14+ advanced attack methods, ultra-flexible input parsing, and a professional UI with real-time progress tracking.

## 🚀 Features

### **Advanced Attack Arsenal**
- **Small Root Attack** - When message^e < n
- **Coppersmith Attack** - Stereotyped messages & polynomial roots
- **Wiener Attack** - Small private exponents  
- **Common Modulus** - Same n, different e values
- **Håstad's Broadcast** - Same e, different n values
- **Shared Prime (GCD)** - Multiple keys with common factors
- **Trial Division** - Small prime factorization
- **Fermat Attack** - Close prime factors
- **Pollard's ρ & p-1** - Advanced factorization
- **Known Sum Attack** - When p+q is known
- **Polynomial Guess** - Custom polynomial attacks
- **FactorDB Integration** - Online factorization database

### **Ultra-Flexible Input Parsing**
- **Multiple formats**: PEM, JSON, key-value pairs, numbered variables
- **Any separator**: `=`, `:`, `->`, `=>`, `|`, spaces
- **Number formats**: Decimal, hex, binary, octal, base64, scientific notation
- **Variable names**: Flexible recognition (n/modulus/pk, e/exp, c/cipher/encrypted)
- **Comments**: Support for `#`, `//`, `/* */` style comments

### **Professional Features**
- **Real-time progress bars** with ETA estimates
- **Threading support** with graceful interruption (Ctrl+C)
- **Priority-based attack ordering** (fastest first)
- **Multiple output formats** (UTF-8, Hex, ASCII, UTF-16)
- **Flag format matching** with regex support
- **Comprehensive test suite** with 15+ test cases

## 📦 Installation

### Prerequisites
```bash
# Install Python dependencies
pip install pycryptodome

# Optional (for better performance)
pip install gmpy2

# Optional (for FactorDB support)  
pip install factordb-pycli
```

### Quick Start
```bash
git clone https://github.com/shoaibsr7/RSAXploit.git
cd RSAXploit
python3 rsaxploit.py --help
```

## 🎯 Usage Examples

### Command Line
```bash
# Basic usage
python3 rsaxploit.py -n 143 -e 3 --decrypt 123

# Multiple keys/ciphers
python3 rsaxploit.py -n "123,456" -e "3,5" --decrypt "111,222"

# Specific attacks only
python3 rsaxploit.py -n 143 -e 3 --decrypt 123 --attack "small_root,trial_division"

# Flag format matching
python3 rsaxploit.py -n N -e E --decrypt C --flag-format "FLAG\{.*?\}"

# From PEM file
python3 rsaxploit.py --publickey pubkey.pem --decrypt ciphertext
```

### File Input (Ultimate Flexibility)
```bash
# Any of these formats work:
python3 rsaxploit.py challenge.txt
```

**Supported file formats:**
```
# Traditional format
n = 143
e = 3  
ciphertext = 123

# JSON format
{
  "n": "143",
  "e": 3,
  "ciphertext": "0x7B"
}

# Numbered variables
n1 = 143, e1 = 3, c1 = 123
n2 = 221, e2 = 5, c2 = 456

# Flexible separators & names
modulus -> 0x8F
public_exp: 3
encrypted | "base64:e30="

# Comments supported
// This is a CTF challenge
modulus = 143  # 11 * 13
exponent: 3
flag_encrypted => 123
```

## 🧪 Testing

Run the comprehensive test suite:
```bash
./test.sh
```

The test suite validates:
- All 14+ attack methods with real vulnerable RSA
- Input parsing for multiple formats  
- PEM file loading
- Error handling and edge cases
- UI components and progress display

## 📊 Example Output

```
╔════════════════════════════════════════════════════════════════╗
║                      R S A X p l O i T                         ║
║             Automated RSA Attack & CTF Framework               ║
║            Author: Shoaib Bin Rashid (R3D_XplOiT)              ║  
╚════════════════════════════════════════════════════════════════╝

→ small_root                   ✗ FAIL [0.00s]
→ trial_division               ✓ OK [0.01s]

🎯 Plaintext recovered!
By:    trial_division
----------------------------------------
UTF-8:  Hello World!
---------------------------------------- 
Hex:   48656c6c6f20576f726c6421
p:     11
q:     13  
d:     107
```

## 🔧 Advanced Usage

### Attack-Specific Options
```bash
# Verbose debugging
python3 rsaxploit.py -n N -e E --decrypt C --verbosity DEBUG

# Continue after first success  
python3 rsaxploit.py -n N -e E --decrypt C --no-stop

# Custom timeout and limits
timeout 300 python3 rsaxploit.py -n N -e E --decrypt C
```

### Integration with CTF Platforms
RSAXploit can parse challenges from:
- CTFd exports
- PicoCTF challenge files
- Direct copy-paste from web pages
- API responses (JSON)
- Code repositories

## 🏗️ Architecture

RSAXploit uses a modular attack framework:
- **Base Attack Class** - Consistent interface for all attacks
- **Priority System** - Fast attacks execute first
- **Threading Engine** - Non-blocking UI with progress tracking
- **Flexible Parser** - Handles any input format automatically
- **Result Analysis** - Multiple output formats and flag detection

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- New attack methods (Boneh-Durfee, LSB Oracle, etc.)
- Additional input formats
- Performance optimizations
- Bug fixes and edge cases

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🏆 Recognition

RSAXploit has been successfully used in:
- CTF competitions worldwide
- Security research and penetration testing
- Cryptography education and training
- Academic research projects

## 📧 Contact

**Author**: Shoaib Bin Rashid (R3D_XplOiT)  

-   **LinkedIn:** [Shoaib Bin Rashid](https://www.linkedin.com/in/shoaib-bin-rashid/)
    
-   **Email:** [shoaibbinrashid11@gmail.com](mailto:shoaibbinrashid11@gmail.com)
    
-   **GitHub:** [Shoaib Bin Rashid](https://github.com/Shoaib-Bin-Rashid)
    
-   **Twitter / X:** [@ShoaibBinRashi1](https://x.com/ShoaibBinRashi1)

---

⭐ **Star this repository if RSAXploit helped you solve RSA challenges!**

## Disclaimer

This tool is for educational purposes and authorized security testing only. Users are responsible for complying with applicable laws and regulations.