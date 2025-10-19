import sys
import pefile

if len(sys.argv) != 2:
    print("Usage: python GetExports.py <path_to_dll>")
    sys.exit(1)

pe = pefile.PE(sys.argv[1])
if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    print("No export table found.")
    sys.exit(0)

print(f"Exports for: {sys.argv[1]}\n")
print(f"{'Ordinal':>7}  {'RVA':>10}  Name")
for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    name = exp.name.decode() if exp.name else b'<none>'
    print(f"{exp.ordinal:7}  0x{exp.address:08X}  {name}")
