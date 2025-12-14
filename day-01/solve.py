import base64

binary = []

with open('start.txt', 'r') as f:
    binary = f.read().strip().split()

binary = [int(val, 2) for val in binary]
binary = ''.join([chr(val) for val in binary])
binary = [binary[i:i+2] for i in range(0, len(binary), 2)]
binary = ''.join([chr(int(val, 16)) for val in binary])
flag = base64.b64decode(binary).decode()

print(flag)