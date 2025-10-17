# 🔐 RSAXploit

**The Ultimate RSA Attack Framework for CTF & Security Research**

**Developed by Shoaib Bin Rashid (R3D\_XplOiT)**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/shoaibsr7/RSAXploit)
[![Attacks](https://img.shields.io/badge/attacks-15+-red.svg)](#-attack-arsenal)
[![Variables](https://img.shields.io/badge/cipher_variables-19+-green.svg)](#-variable-names-supported)

RSAXploit is a comprehensive, automated RSA cryptanalysis framework designed specifically for **CTF competitions** and **security research**. It features **15+ advanced attack methods**, **ultra-flexible input parsing**, and a **professional CLI interface** with real-time progress tracking.

**🎯 Perfect for CTF players, security researchers, and cryptography enthusiasts!**

## 🚀 Features

### **💪 Advanced Attack Arsenal**
- **⚡ Small Root Attack** - When message^e < n
- **🔮 Coppersmith Attack** - Stereotyped messages & polynomial roots
- **💰 Wiener Attack** - Small private exponents (continued fractions)
- **🔄 Common Modulus** - Same n, different e values
- **📡 Håstad's Broadcast** - Same e, different n values (CRT)
- **🤝 Shared Prime (GCD)** - Multiple keys with common factors
- **🔢 Trial Division** - Small prime factorization
- **⚖️ Fermat Attack** - Close prime factors (p ≈ q)
- **🎲 Pollard's ρ & p-1** - Advanced factorization algorithms
- **➕ Known Sum Attack** - When p+q is known
- **📏 Polynomial Guess** - Custom polynomial attacks
- **🏦 FactorDB Integration** - Online factorization database
- **🔍 Multi-Prime Support** - n = p₁ × p₂ × ... × pₖ
- **🔄 Batch Processing** - Multiple keys/ciphers simultaneously
- **🏆 CTF Optimized** - Priority-based attack ordering

### **🌐 Ultra-Flexible Input Parsing**
- **📁 Multiple formats**: PEM, JSON, key-value pairs, numbered variables
- **⚔️ Any separator**: `=`, `:`, `->`, `=>`, `|`, spaces, tabs
- **🔢 Number formats**: Decimal, hex (0x), binary (0b), octal (0o), base64, scientific
- **🏷️ Variable names**: 19+ cipher names, 8+ modulus names, 7+ exponent names
- **📝 Comments**: Support for `#`, `//`, `/* */` style comments
- **📎 Mixed content**: PEM blocks + variables in same file
- **🔄 Auto-detection**: Automatically determines parsing format

### **💻 Professional CLI Features**
- **📏 Real-time progress bars** with ETA estimates
- **🧵 Threading support** with graceful interruption (Ctrl+C)
- **⏱️ Priority-based attack ordering** (fastest attacks first)
- **🎨 Multiple output formats** (UTF-8, Hex, ASCII, UTF-16, Binary)
- **🏴 Flag format matching** with regex support
- **🛠️ Comprehensive logging** with debug levels
- **📊 Detailed attack results** with timing and success rates

## 📂 Variable Names Supported

RSAXploit recognizes **ALL** common variable names used in CTF challenges and research:

### **🔢 Modulus (N) - 8+ variants**
```
n, modulus, mod, public_key, pubkey, pk, rsa_n, modulo
+ any name starting with 'n' (n1, n_value, number, etc.)
```

### **⚡ Exponent (E) - 7+ variants**  
```
e, exp, exponent, public_exp, pub_exp, rsa_e, key_exp
```

### **🔐 Ciphertext (C) - 19+ variants**
```
c, cipher, ciphertext, encrypted, enc, encrypt, cyphertext, cypher,
message, msg, ct, secret, flag, output, data, target, payload, text, value
+ any name starting with 'c' (c1, cipher_msg, crypt_data, etc.)
+ numbered variants (c1, c2, cipher1, enc1, flag_enc, etc.)
```

### **➕ Sum/Difference (X) - 8+ variants**
```
x, s, sum, diff, difference, p_plus_q, p+q, pq_sum
```

> **🏆 This makes RSAXploit compatible with 99% of CTF challenges without any variable name changes!**

## 📦 Installation

### **📻 System Requirements**
- **Python**: 3.7+ (3.9+ recommended)
- **OS**: Windows, Linux, macOS
- **Memory**: 512MB+ RAM
- **Storage**: 50MB+ free space

### **⚡ Quick Install** 
```bash
# Clone the repository
git clone https://github.com/shoaibsr7/RSAXploit.git
cd RSAXploit

# Install dependencies
pip install -r requirements.txt

# Ready to use!
python3 rsaxploit.py --help
```

### **🔧 Manual Dependencies**
```bash
# Required
pip install pycryptodome

# Optional (10x faster factorization)
pip install gmpy2

# Optional (FactorDB support)
pip install factordb-pycli

# Optional (better performance)
pip install sympy
```

### **🐍 Python Version Notes**
- **Python 3.7-3.8**: Fully supported
- **Python 3.9-3.11**: Recommended (best performance)
- **Python 3.12+**: Supported (may need gmpy2 compilation)

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
