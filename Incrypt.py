"""
Incrypt By Mora

Copyright (c) 2023-2023 Mora

Incrypt is a module for Encryption of data.
"""

def encrypt(key, arg, size: int = 25600):
	size = round(size)*12
	if isinstance(key, bytes):
		key_value=0
		for char in [*key]:
			key_value+=(char*127)%size
	elif isinstance(key, str):
		key_value=0
		for char in [*key]:
			key_value+=(ord(char)*127)%size
	else:
		raise ValueError("Key is not a string or a bytes like object.")
	_0x1 = ""
	arg = ''.join(arg).encode()
	for i in [*arg]:
		_0x1 = _0x1+chr((i+1114100%0x109000)%0x110000)
	arg = _0x1
	del _0x1
	encryped = []
	for i, c in enumerate(arg):
		key_c = ord(key[i % len(key)])
		arg_c = ord(str(c)[:1])
		encryped.append(chr((arg_c + key_c) % size))
	return ''.join(encryped).encode()

def encrypt(key, arg, size: int = 25600):
    size = round(size)*12
    if isinstance(key, bytes):
        key_value=0
        for char in [*key]:
            key_value+=(char*127)%size
    elif isinstance(key, str):
        key_value=0
        for char in [*key]:
            key_value+=(ord(char)*127)%size
    else:
        raise ValueError("Key is not a string or a bytes-like object.")
    len_key = len(key)

    _0x1 = ""
    arg = ''.join(str(arg)).encode()
    for i in [*arg]:
        _0x1 = _0x1+chr((i+1114100%0x109000)%0x110000)
    arg = _0x1
    del _0x1
    encryped = []
    for i, c in enumerate(arg):
        if len_key == 0: key_c = ord('\x00')
        else: key_c = ord(key[i % len_key])
        arg_c = ord(str(c)[:1])
        encryped.append(chr((arg_c + key_c) % size))
    return ''.join(encryped)

def decrypt(key, encryped, size: int = 25600):
    size = round(size)*12
    if isinstance(key, bytes):
        key_value=0
        for char in [*key]:
            key_value+=char%size
    elif isinstance(key, str):
        key_value=0
        for char in [*key]:
            key_value+=(ord(char)/127)%size
    else:
        raise ValueError("Key is not a string or a bytes-like object")
    len_key = len(key)
    
    #if not isinstance(encryped, bytes):
        #raise ValueError(f"'{encryped}' is not a bytes like object")
    
    _0x1 = ""
    for i in [*encryped]:
        _0x1 = _0x1+chr((ord(str(i))-1114100%0x109000)%0x110000)
    encryped = _0x1
    del _0x1
    decrypted = []
    for i, c in enumerate(encryped):
        if len_key == 0: key_c = ord('\x00')
        else: key_c = ord(key[i % len_key])
        enc_c = ord(str(c)[:1])
        decrypted.append(chr((enc_c - key_c) % size))
    return ''.join(decrypted)

def main():
	import sys, os

	if len(sys.argv) == 4:
		name = sys.argv[2]
		mode = sys.argv[1]

		if os.path.isfile(sys.argv[0]) is False: sys.exit()
		if os.path.isfile(name) is False: sys.exit(f"'{name}' isn't a File.")
	else:
		sys.exit(f"""
Please run Incrypt with 3 Arguments.
Usage: Incrypt [Mode] [File] [Key]
Modes: e or d""")
	if mode == "e":
		print(encrypt(sys.argv[3], open(name, 'r', encoding="ISO-8859-1").read()))
	elif mode == "d":
		print(decrypt(sys.argv[3], open(name, 'r', encoding="ISO-8859-1").read()))
	else:
		sys.exit(f"""
Please run Incrypt with 1 of the 2 Modes.
Usage: Incrypt [Mode] [File] [Key]
Modes: e or d""")

if __name__ == '__main__':
	main()
