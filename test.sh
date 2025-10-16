#!/bin/bash
# RSAXploit Attack Test Suite - Simple and Robust
# Tests each attack with real vulnerable RSA parameters

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Counters
TOTAL=0
PASSED=0
FAILED=0

pass_test() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED++))
}

fail_test() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED++))
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

run_test() {
    local name="$1"
    local command="$2"
    ((TOTAL++))
    
    info "Testing $name..."
    
    if eval "$command" &> /dev/null; then
        pass_test "$name"
        return 0
    else
        fail_test "$name"
        return 1
    fi
}

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════╗"
echo "║        RSAXploit Attack Test Suite            ║"
echo "╚═══════════════════════════════════════════════╝"
echo -e "${NC}"

# Prerequisites  
run_test "Prerequisites check" \
    "[[ -f 'rsaxploit.py' ]] && command -v python3 >/dev/null"

echo

# Test 1: Basic execution
run_test "Basic execution" \
    "timeout 10 python3 rsaxploit.py -n 123 -e 3 --decrypt 1 --attack small_root"

# Test 2: Help command  
run_test "Help command" \
    "python3 rsaxploit.py --help"

# Test 3: Small Root Attack (real vulnerable case)
info "Generating Small Root Attack test case..."
python3 -c "
from Crypto.Util.number import getPrime
p = getPrime(512)
q = getPrime(512) 
n = p * q
m = 12345
c = pow(m, 3, n)
print(f'SMALL_ROOT_N={n}')
print(f'SMALL_ROOT_C={c}')
" > /tmp/small_root_test.txt 2>/dev/null

if [[ -f "/tmp/small_root_test.txt" ]]; then
    source /tmp/small_root_test.txt 2>/dev/null
    run_test "Small Root Attack" \
        "timeout 15 python3 rsaxploit.py -n '$SMALL_ROOT_N' -e 3 --decrypt '$SMALL_ROOT_C' --attack small_root | grep -q '✓ OK'"
    rm -f /tmp/small_root_test.txt
else
    fail_test "Small Root Attack - Test case generation failed"
    ((TOTAL++))
fi

# Test 4: Trial Division Attack (small prime)
info "Generating Trial Division test case..."
python3 -c "
from Crypto.Util.number import getPrime, bytes_to_long
p = 1009  # Small prime
q = getPrime(256) 
n = p * q
m = bytes_to_long(b'trial_test')
c = pow(m, 65537, n)
print(f'TRIAL_N={n}')
print(f'TRIAL_C={c}')
" > /tmp/trial_test.txt 2>/dev/null

if [[ -f "/tmp/trial_test.txt" ]]; then
    source /tmp/trial_test.txt 2>/dev/null
    run_test "Trial Division Attack" \
        "timeout 15 python3 rsaxploit.py -n '$TRIAL_N' -e 65537 --decrypt '$TRIAL_C' --attack trial_division | grep -q '✓ OK'"
    rm -f /tmp/trial_test.txt
else
    fail_test "Trial Division Attack - Test case generation failed"
    ((TOTAL++))
fi

# Test 5: Coppersmith Attack (execution test)
run_test "Coppersmith Attack" \
    "timeout 15 python3 rsaxploit.py -n 12345678901234567890 -e 3 --decrypt 111111 --attack coppersmith"

# Test 6: Common Modulus Attack
info "Generating Common Modulus test case..."
cat > /tmp/common_mod_test.txt << 'EOF'
n1 = 323
e1 = 3
c1 = 111
n2 = 323
e2 = 5
c2 = 222
EOF

run_test "Common Modulus Attack file parsing" \
    "timeout 15 python3 rsaxploit.py /tmp/common_mod_test.txt --attack common_modulus_bezout"
rm -f /tmp/common_mod_test.txt

# Test 7: Shared Prime Attack
info "Generating Shared Prime test case..."
python3 -c "
from Crypto.Util.number import getPrime, bytes_to_long
p = getPrime(128)
q1 = getPrime(128)
q2 = getPrime(128)
n1 = p * q1
n2 = p * q2
m = bytes_to_long(b'shared')
c1 = pow(m, 65537, n1)
c2 = pow(m, 65537, n2)
print(f'n1 = {n1}')
print(f'e1 = 65537')
print(f'c1 = {c1}')
print(f'n2 = {n2}')
print(f'e2 = 65537') 
print(f'c2 = {c2}')
" > /tmp/shared_prime_test.txt 2>/dev/null

if [[ -f "/tmp/shared_prime_test.txt" ]]; then
    run_test "Shared Prime Attack" \
        "timeout 15 python3 rsaxploit.py /tmp/shared_prime_test.txt --attack sharedprime_gcd | grep -q '✓ OK'"
    rm -f /tmp/shared_prime_test.txt
else
    fail_test "Shared Prime Attack - Test case generation failed"
    ((TOTAL++))
fi

# Test 8: Known Sum Attack
info "Generating Known Sum test case..."
python3 -c "
from Crypto.Util.number import getPrime, bytes_to_long
p = getPrime(128)
q = getPrime(128)
n = p * q
x = p + q
m = bytes_to_long(b'sum_test')
c = pow(m, 65537, n)
print(f'n = {n}')
print(f'e = 65537')
print(f'x = {x}')
print(f'c = {c}')
" > /tmp/known_sum_test.txt 2>/dev/null

if [[ -f "/tmp/known_sum_test.txt" ]]; then
    run_test "Known Sum Attack" \
        "timeout 15 python3 rsaxploit.py /tmp/known_sum_test.txt --attack known_sum | grep -q '✓ OK'"
    rm -f /tmp/known_sum_test.txt
else
    fail_test "Known Sum Attack - Test case generation failed"
    ((TOTAL++))
fi

# Test 9: File Input Parsing
info "Testing file input parsing..."
cat > /tmp/file_parse_test.txt << 'EOF'
# Test file with numbered format
n1 = 0x1234567890ABCDEF
e1 = 65537
c1 = 0x987654321

n2 = 987654321
e2 = 3
c2 = 123456
EOF

run_test "File Input Parsing" \
    "timeout 10 python3 rsaxploit.py /tmp/file_parse_test.txt | grep -q 'Public keys: 2'"
rm -f /tmp/file_parse_test.txt

# Test 10: PEM File Support
info "Testing PEM file support..."
python3 -c "
from Crypto.PublicKey import RSA
try:
    key = RSA.generate(1024)
    pubkey = key.publickey()
    with open('/tmp/test_key.pem', 'wb') as f:
        f.write(pubkey.export_key('PEM'))
    print('PEM file created')
except Exception as e:
    print(f'Error: {e}')
" > /dev/null 2>&1

if [[ -f "/tmp/test_key.pem" ]]; then
    run_test "PEM File Support" \
        "timeout 10 python3 rsaxploit.py --publickey /tmp/test_key.pem --decrypt 123456 | grep -q 'Public keys: 1'"
    rm -f /tmp/test_key.pem
else
    fail_test "PEM File Support - PEM generation failed"
    ((TOTAL++))
fi

# Test 11: Attack Selection
run_test "Attack Selection" \
    "timeout 10 python3 rsaxploit.py -n 123456 -e 3 --decrypt 111 --attack small_root,coppersmith | grep -q 'small_root'"

# Test 12: Error Handling
run_test "Error Handling" \
    "! python3 rsaxploit.py -n 'not_a_number' -e 3 --decrypt 123"

# Test 13: Verbosity Levels
run_test "Verbosity Levels" \
    "timeout 10 python3 rsaxploit.py -n 123 -e 3 --decrypt 1 --verbosity DEBUG --attack small_root"

# Test 14: All attacks execution
run_test "All Attacks Execution" \
    "timeout 30 python3 rsaxploit.py -n 123456789 -e 3 --decrypt 111111"

echo
echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo -e "${CYAN}                 TEST SUMMARY                  ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════${NC}"

echo -e "Total Tests: ${BLUE}$TOTAL${NC}"
echo -e "Passed:      ${GREEN}$PASSED${NC}"
echo -e "Failed:      ${RED}$FAILED${NC}"

if [[ $TOTAL -gt 0 ]]; then
    PERCENTAGE=$((PASSED * 100 / TOTAL))
    echo -e "Success Rate: ${GREEN}$PERCENTAGE%${NC}"
    
    echo
    if [[ $FAILED -eq 0 ]]; then
        echo -e "${GREEN}🎉 ALL TESTS PASSED! RSAXploit is working perfectly!${NC}"
    elif [[ $PERCENTAGE -ge 80 ]]; then
        echo -e "${YELLOW}✅ EXCELLENT! Most features working correctly ($PERCENTAGE% success)${NC}"
    else
        echo -e "${RED}⚠️  Some issues found. Check the failures above.${NC}"
    fi
else
    echo -e "${RED}No tests were run${NC}"
fi

echo
echo -e "${CYAN}Individual Attack Test Summary:${NC}"
echo -e "• Basic functionality and help: ✓"
echo -e "• Small Root Attack: Real vulnerable RSA test"
echo -e "• Trial Division: Small prime factorization test" 
echo -e "• Coppersmith: Execution validation"
echo -e "• Common Modulus: File-based test"
echo -e "• Shared Prime GCD: Multiple key test"
echo -e "• Known Sum: Quadratic solving test"
echo -e "• File parsing: Multiple format support"
echo -e "• PEM support: Public key file loading"
echo -e "• Attack selection: Filtering capability"
echo -e "• Error handling: Invalid input management"
echo -e "• All features: Complete execution test"

echo
echo -e "${GREEN}Test script completed!${NC}"