# Solution
We are given a [start file](https://github.com/s1d15/Advent-of-CTF-2025/blob/main/day-01/start.txt) containing a binary sequence.
> 00110101 00111001 00110011 00110011 00110100 01100101 00110110 01100010 00110110 00110101 00110011 00110001 00110110 00110011 00110111 01100001 00110110 00110010 00110100 00110111 00110100 01100100 00110111 00110111 00110110 00110010 00110101 00110100 00110100 01100101 00110110 00110110 00110100 01100110 00110100 00110111 00110100 00110110 00110100 00110100 00110101 00110011 00110011 00110001 00110011 00111000 00110011 00110011 00110100 01100100 00110100 00110110 00110011 00111001 00110110 00111000 00110101 01100001 00110100 00111000 00110101 00111001 00110111 01100001 00110101 00110100 00110110 01100001 00110110 00110100 00110110 00110110 00110100 01100100 00110110 01100001 00110100 00110001 00110111 00111001 00110100 01100101 00110101 00111000 00110011 00110000 00110011 01100100
---
The idea here is to first convert these binary into ASCII characters.

First, I read the input file and split it by the spaces
```python
binary = []

with open('start.txt', 'r') as f:
    binary = f.read().strip().split()
```

Second, I convert each binary value into its corresponding integer
```python
binary = [int(val, 2) for val in binary]`
```

The current value of `binary` is
```python
59334e6b6531637a62474d7762544e664f474644533138334d4639685a48597a546a64664d6a41794e58303d
```

Then, I recognize these are hexadecimal values so I group each 2 characters, and convert it into another sequence of ASCII characters.
```python
binary = [binary[i:i+2] for i in range(0, len(binary), 2)]
binary = ''.join([chr(int(val, 16)) for val in binary])
```

The current value of `binary` is `Y3Nke1czbGMwbTNfOGFDS183MF9hZHYzTjdfMjAyNX0=`

By using a cipher identifier, I figured out that this is a `base64` encoded message

We can decode this message using `base64` module
```python
import base64
flag = base64.b64decode(binary).decode()
```
---
So our `flag` is `csd{W3lc0m3_8aCK_70_adv3N7_2025}`
