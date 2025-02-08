import sys

def parse_pmp_config(file_path):
    with open(file_path, 'r') as f:
        lines = [line.strip() for line in f.readlines()]
    
    if len(lines) != 128:
        raise ValueError("PMP configuration file must contain exactly 128 lines.")
    
    pmpcfg = [int(lines[i], 16) for i in range(64)]
    pmpaddr = [int(lines[i], 16) for i in range(64, 128)]
    
    return pmpcfg, pmpaddr

def check_pmp_access(pmpcfg, pmpaddr, address, privilege_mode, operation):
    for i in range(64):
        cfg = (pmpcfg[i // 8] >> ((i % 8) * 8)) & 0xFF
        addr = pmpaddr[i] << 2  # pmpaddr is in 4-byte granularity

        A = (cfg >> 3) & 0b11  # Address-matching mode
        R = (cfg >> 0) & 1  # Read permission
        W = (cfg >> 1) & 1  # Write permission
        X = (cfg >> 2) & 1  # Execute permission

        print(f"PMP Entry {i}: A={A}, R={R}, W={W}, X={X}, addr={hex(addr)}")  # Debugging output

        if A == 0:  # Disabled
            continue
        elif A == 1:  # TOR (Top of Range)
            if i == 0:
                continue
            lower_bound = pmpaddr[i - 1] << 2
            upper_bound = addr
            print(f"  Checking TOR: [{hex(lower_bound)}, {hex(upper_bound)})")
            if lower_bound <= address < upper_bound:
                return validate_access(R, W, X, privilege_mode, operation)
        elif A == 2:  # NA4 (Naturally aligned 4-byte region)
            print(f"  Checking NA4: {hex(addr)}")
            if addr == address:
                return validate_access(R, W, X, privilege_mode, operation)
        elif A == 3:  # NAPOT (Naturally aligned power-of-two region)
            size = 1 << ((~addr & (addr + 1)).bit_length())  # Corrected NAPOT size calculation
            base = addr & ~(size - 1)
            print(f"  Checking NAPOT: Base={hex(base)}, Size={hex(size)}")
            if base <= address < base + size:
                return validate_access(R, W, X, privilege_mode, operation)

    # If no PMP entry matches, access is **allowed in M-mode** but **faulted in U-mode**
    return privilege_mode == 'U'  # True = fault, False = allowed

def validate_access(R, W, X, privilege_mode, operation):
    if operation == 'R' and not R:
        return True
    if operation == 'W' and not W:
        return True
    if operation == 'X' and not X:
        return True
    return False  # No fault

def main():
    if len(sys.argv) != 5:
        print("Usage: python pmp_check.py <pmp_config_file> <address> <privilege_mode> <operation>")
        sys.exit(1)

    pmp_config_file = sys.argv[1]
    address = int(sys.argv[2], 16)
    privilege_mode = sys.argv[3]
    operation = sys.argv[4]

    if privilege_mode not in {'M', 'S', 'U'} or operation not in {'R', 'W', 'X'}:
        print("Invalid privilege mode or operation.")
        sys.exit(1)

    pmpcfg, pmpaddr = parse_pmp_config(pmp_config_file)
    access_fault = check_pmp_access(pmpcfg, pmpaddr, address, privilege_mode, operation)

    print("Access Fault" if access_fault else "Access Allowed")

if __name__ == "__main__":
    main()
