import subprocess
import marshal
import struct
import sys
import re
import os


def code_to_bytecode(code):
    def uint32(val):
        return struct.pack("<I", val)
    
    if sys.version_info >= (3,4):
        from importlib.util import MAGIC_NUMBER

    data = bytearray(MAGIC_NUMBER)
    if sys.version_info >= (3,7):
        data.extend(uint32(0))

    data.extend(uint32(int(0)))

    if sys.version_info >= (3,2):
        data.extend(uint32(0))

    data.extend(marshal.dumps(code))
    return data


def deobfuscate(a: list, k: int) -> str:
    return ''.join(''.join(chr(int(c) - k) for c in b.split('\\x00')) for b in a)


if __name__ == "__main__":
    if (len(sys.argv)) > 1:
        file_path = sys.argv[1]
    else:
        file_path = input("Please enter the path of the file to deobfuscate: ")

    with open(file_path, 'r') as f:
        data = f.read()

    parts = re.findall(r"Func.calculate\(\d*?\)\s*?,Func.define\('__.*?__', b'(.*?)'\)", data)
    obf = marshal.loads(eval("+".join(["b'" + p + "'" for p in parts])))
    with open("obf.pyc", 'wb') as f:
        f.write(code_to_bytecode(obf))

    asm = subprocess.run(["pycdas.exe", "obf.pyc"], stdout=subprocess.PIPE, universal_newlines=True).stdout
    key = re.search(r"0: b'(.*?)'", asm).group(1)

    values = re.findall(r"(?:LOAD_CONST|LOAD_NAME)\s*?(?:\d.*?): (?:b|globals)(.*)", asm)[1:]
    keys = re.findall(r"STORE_NAME\s*?(?:\d*?): (__.*?__)", asm)[:-1]
    order = re.findall(r"LOAD_NAME\s*?(?:\d*?): (__.*?__)", asm)

    unordered = {}
    for i in range(len(values)):
        unordered[keys[i]] = values[i]

    ordered = []
    for i in range(len(order)):
        ordered.append(unordered[order[i]].replace("'", ""))

    extension = file_path.split('.')[-1]
    out_path = file_path.replace(extension, 'deobf.' + extension)
    with open(out_path, 'w') as f:
        f.write(deobfuscate(ordered, int(key)).replace("\r", ""))

    os.remove("obf.pyc")