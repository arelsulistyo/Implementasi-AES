# # AES
import numpy as np


AES_TYPE = {
    'AES_128': {'key_size': 16, 'rounds': 10, 'key_schedule_size': 176},
    'AES_192': {'key_size': 24, 'rounds': 12, 'key_schedule_size': 208},
    'AES_256': {'key_size': 32,'rounds': 14, 'key_schedule_size': 240},
}


# # Constants
S_BOX = {
    'FORWARD': np.array([
        [0x63,	0x7c,	0x77,	0x7b,	0xf2,	0x6b,	0x6f,	0xc5,	0x30,	0x01,	0x67,	0x2b,	0xfe,	0xd7,	0xab,	0x76],
        [0xca,	0x82,	0xc9,	0x7d,	0xfa,	0x59,	0x47,	0xf0,	0xad,	0xd4,	0xa2,	0xaf,	0x9c,	0xa4,	0x72,	0xc0],
        [0xb7,	0xfd,	0x93,	0x26,	0x36,	0x3f,	0xf7,	0xcc,	0x34,	0xa5,	0xe5,	0xf1,	0x71,	0xd8,	0x31,	0x15],
        [0x04,	0xc7,	0x23,	0xc3,	0x18,	0x96,	0x05,	0x9a,	0x07,	0x12,	0x80,	0xe2,	0xeb,	0x27,	0xb2,	0x75],
        [0x09,	0x83,	0x2c,	0x1a,	0x1b,	0x6e,	0x5a,	0xa0,	0x52,	0x3b,	0xd6,	0xb3,	0x29,	0xe3,	0x2f,	0x84],
        [0x53,	0xd1,	0x00,	0xed,	0x20,	0xfc,	0xb1,	0x5b,	0x6a,	0xcb,	0xbe,	0x39,	0x4a,	0x4c,	0x58,	0xcf],
        [0xd0,	0xef,	0xaa,	0xfb,	0x43,	0x4d,	0x33,	0x85,	0x45,	0xf9,	0x02,	0x7f,	0x50,	0x3c,	0x9f,	0xa8],
        [0x51,	0xa3,	0x40,	0x8f,	0x92,	0x9d,	0x38,	0xf5,	0xbc,	0xb6,	0xda,	0x21,	0x10,	0xff,	0xf3,	0xd2],
        [0xcd,	0x0c,	0x13,	0xec,	0x5f,	0x97,	0x44,	0x17,	0xc4,	0xa7,	0x7e,	0x3d,	0x64,	0x5d,	0x19,	0x73],
        [0x60,	0x81,	0x4f,	0xdc,	0x22,	0x2a,	0x90,	0x88,	0x46,	0xee,	0xb8,	0x14,	0xde,	0x5e,	0x0b,	0xdb],
        [0xe0,	0x32,	0x3a,	0x0a,	0x49,	0x06,	0x24,	0x5c,	0xc2,	0xd3,	0xac,	0x62,	0x91,	0x95,	0xe4,	0x79],
        [0xe7,	0xc8,	0x37,	0x6d,	0x8d,	0xd5,	0x4e,	0xa9,	0x6c,	0x56,	0xf4,	0xea,	0x65,	0x7a,	0xae,	0x08],
        [0xba,	0x78,	0x25,	0x2e,	0x1c,	0xa6,	0xb4,	0xc6,	0xe8,	0xdd,	0x74,	0x1f,	0x4b,	0xbd,	0x8b,	0x8a],
        [0x70,	0x3e,	0xb5,	0x66,	0x48,	0x03,	0xf6,	0x0e,	0x61,	0x35,	0x57,	0xb9,	0x86,	0xc1,	0x1d,	0x9e],
        [0xe1,	0xf8,	0x98,	0x11,	0x69,	0xd9,	0x8e,	0x94,	0x9b,	0x1e,	0x87,	0xe9,	0xce,	0x55,	0x28,	0xdf],
        [0x8c,	0xa1,	0x89,	0x0d,	0xbf,	0xe6,	0x42,	0x68,	0x41,	0x99,	0x2d,	0x0f,	0xb0,	0x54,	0xbb,	0x16],
    ]),

    'INVERSE': np.array([
        [0x52,  0x09,   0x6a,   0xd5,   0x30,   0x36,   0xa5,   0x38,   0xbf,   0x40,   0xa3,   0x9e,   0x81,   0xf3,   0xd7,   0xfb],
        [0x7c,  0xe3,   0x39,   0x82,   0x9b,   0x2f,   0xff,   0x87,   0x34,   0x8e,   0x43,   0x44,   0xc4,   0xde,   0xe9,   0xcb],
        [0x54,  0x7b,   0x94,   0x32,   0xa6,   0xc2,   0x23,   0x3d,   0xee,   0x4c,   0x95,   0x0b,   0x42,   0xfa,   0xc3,   0x4e],
        [0x08,  0x2e,   0xa1,   0x66,   0x28,   0xd9,   0x24,   0xb2,   0x76,   0x5b,   0xa2,   0x49,   0x6d,   0x8b,   0xd1,   0x25],
        [0x72,  0xf8,   0xf6,   0x64,   0x86,   0x68,   0x98,   0x16,   0xd4,   0xa4,   0x5c,   0xcc,   0x5d,   0x65,   0xb6,   0x92],
        [0x6c,  0x70,   0x48,   0x50,   0xfd,   0xed,   0xb9,   0xda,   0x5e,   0x15,   0x46,   0x57,   0xa7,   0x8d,   0x9d,   0x84],
        [0x90,  0xd8,   0xab,   0x00,   0x8c,   0xbc,   0xd3,   0x0a,   0xf7,   0xe4,   0x58,   0x05,   0xb8,   0xb3,   0x45,   0x06],
        [0xd0,  0x2c,   0x1e,   0x8f,   0xca,   0x3f,   0x0f,   0x02,   0xc1,   0xaf,   0xbd,   0x03,   0x01,   0x13,   0x8a,   0x6b],
        [0x3a,  0x91,   0x11,   0x41,   0x4f,   0x67,   0xdc,   0xea,   0x97,   0xf2,   0xcf,   0xce,   0xf0,   0xb4,   0xe6,   0x73],
        [0x96,  0xac,   0x74,   0x22,   0xe7,   0xad,   0x35,   0x85,   0xe2,   0xf9,   0x37,   0xe8,   0x1c,   0x75,   0xdf,   0x6e],
        [0x47,  0xf1,   0x1a,   0x71,   0x1d,   0x29,   0xc5,   0x89,   0x6f,   0xb7,   0x62,   0x0e,   0xaa,   0x18,   0xbe,   0x1b],
        [0xfc,  0x56,   0x3e,   0x4b,   0xc6,   0xd2,   0x79,   0x20,   0x9a,   0xdb,   0xc0,   0xfe,   0x78,   0xcd,   0x5a,   0xf4],
        [0x1f,  0xdd,   0xa8,   0x33,   0x88,   0x07,   0xc7,   0x31,   0xb1,   0x12,   0x10,   0x59,   0x27,   0x80,   0xec,   0x5f],
        [0x60,  0x51,   0x7f,   0xa9,   0x19,   0xb5,   0x4a,   0x0d,   0x2d,   0xe5,   0x7a,   0x9f,   0x93,   0xc9,   0x9c,   0xef],
        [0xa0,  0xe0,   0x3b,   0x4d,   0xae,   0x2a,   0xf5,   0xb0,   0xc8,   0xeb,   0xbb,   0x3c,   0x83,   0x53,   0x99,   0x61],
        [0x17,  0x2b,   0x04,   0x7e,   0xba,   0x77,   0xd6,   0x26,   0xe1,   0x69,   0x14,   0x63,   0x55,   0x21,   0x0c,   0x7d],
    ]),
}


MIX_COLUMNS_MATRIX = {
    'FORWARD': np.array([
        [2, 3, 1, 1],
        [1, 2, 3, 1],
        [1, 1, 2, 3],
        [3, 1, 1, 2],
    ]),

    'INVERSE': np.array([
        [14, 11, 13,  9],
        [ 9, 14, 11, 13],
        [13,  9, 14, 11],
        [11, 13,  9, 14]
    ]),
}


def get_state(key_str):
    key = [ord(char) for char in key_str]
    state = np.array(key).reshape(4, len(key) // 4)
    return state

def get_msg(state):
    msg = state.copy()
    msg = [char for row in state for char in row]
    msg = ''.join(chr(char) for char in msg)
    return msg

def print_hex(state):
    state = state.flatten()
    for item in state:
        print(f'{item:02x}', end=' ')
    print()

def str_to_hex(plaintext):
    hex_encoded = plaintext.encode().hex()
    formatted_hex = ' '.join(hex_encoded[i:i+2] for i in range(0, len(hex_encoded), 2))
    return formatted_hex

# ## Substitute Bytes
def substitute_bytes(state, inverse=False):
    s_box = S_BOX['INVERSE'] if inverse else S_BOX['FORWARD']
    res = state.copy()

    for i in range(4):
        for j in range(4):
            res[i][j] = s_box[res[i][j] // 16][res[i][j] % 16]
    return res


# ## Shift Rows
def shift_rows(state, inverse=False):
    res = state.copy()
    for i in range(4):
        for j in range(4):
            if inverse:
                res[i][j] = state[i][(j-i) % 4]
            else:
                res[i][j] = state[i][(j+i) % 4]
    return res


# ## Mix Columns
def gmul(a, b):
    p = 0

    for _ in range(8):
        if b & 1:
            p ^= a

        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1B

        b >>= 1

    return p & 0xFF

def mix_columns(state, inverse=False):
    matrix = MIX_COLUMNS_MATRIX['INVERSE'] if inverse else MIX_COLUMNS_MATRIX['FORWARD']
    res = state.copy()

    for i in range(4):
        for j in range(4):
            res[i][j] = 0
            for k in range(4):
                res[i][j] ^= gmul(matrix[i][k], state[k][j])
    return res


# ## Add Round Key
def add_round_key(state, round_key):
    res = state.copy()
    for i in range(4):
        for j in range(4):
            res[i][j] ^= round_key[i][j]
    return res


# # Key Expansion
def rot_word(word):
    return word[1:] + word[:1]

def sub_word(word):
    s_box = S_BOX['FORWARD']
    return [s_box[b // 16][b % 16] for b in word]

def rcon(in_val):
    c = 1
    if in_val == 0:
        return 0
    while in_val != 1:
        c = gmul(c, 2)
        in_val -= 1
    return c

def key_expansion(key_str):
    key = get_state(key_str).flatten()
    key_size = len(key)

    if key_size == 16:
        config = AES_TYPE['AES_128']
    elif key_size == 24:
        config = AES_TYPE['AES_192']
    elif key_size == 32:
        config = AES_TYPE['AES_256']
    else:
        raise ValueError("Invalid key size")

    rounds = config['rounds']
    key_schedule_size = config['key_schedule_size']
    
    key_schedule = list(key)
    c = key_size
    i = 1

    while c < key_schedule_size:
        t = key_schedule[c - 4:c]

        if c % key_size == 0:
            t = sub_word(rot_word(t))
            t[0] ^= rcon(i)
            i += 1
        elif key_size == 32 and c % key_size == 16:
            t = sub_word(t)

        for a in range(4):
            key_schedule.append(key_schedule[c - key_size] ^ t[a])
            c += 1

    round_keys = [key_schedule[i:i + 16] for i in range(0, len(key_schedule), 16)]
    round_keys = [np.array(key).reshape(4, 4).transpose() for key in round_keys]

    return round_keys


# # AES
def encrypt_aes(msg, key):
    key_size = len(key)
    if key_size == 16:
        config = AES_TYPE['AES_128']
    elif key_size == 24:
        config = AES_TYPE['AES_192']
    elif key_size == 32:
        config = AES_TYPE['AES_256']
    else:
        raise ValueError("Invalid key size")

    rounds = config['rounds']
    round_keys = key_expansion(key)
    
    state = get_state(msg)
    state = add_round_key(state, round_keys[0])
    
    for i in range(1, rounds):
        state = substitute_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[i])
        
    state = substitute_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[rounds])
    
    return get_msg(state)

def decrypt_aes(msg, key):
    key_size = len(key)
    if key_size == 16:
        config = AES_TYPE['AES_128']
    elif key_size == 24:
        config = AES_TYPE['AES_192']
    elif key_size == 32:
        config = AES_TYPE['AES_256']
    else:
        raise ValueError("Invalid key size")

    rounds = config['rounds']
    round_keys = key_expansion(key)
    
    state = get_state(msg)
    state = add_round_key(state, round_keys[rounds])
    
    for i in range(rounds - 1, 0, -1):
        state = shift_rows(state, inverse=True)
        state = substitute_bytes(state, inverse=True)
        state = add_round_key(state, round_keys[i])
        state = mix_columns(state, inverse=True)
        
    state = shift_rows(state, inverse=True)
    state = substitute_bytes(state, inverse=True)
    state = add_round_key(state, round_keys[0])
    
    return get_msg(state)


# # Padding
def add_pkcs7_padding(data, block_size=16):
    padding_length = block_size - len(data) % block_size
    padding = chr(padding_length) * padding_length
    return data + padding

def remove_pkcs7_padding(data, block_size=16):
    padding_length = ord(data[-1])
    if padding_length < 1 or padding_length > block_size:
        raise ValueError("Invalid padding length")
    if data[-padding_length:] != chr(padding_length) * padding_length:
        raise ValueError("Invalid padding bytes")
    return data[:-padding_length]


# # Cipher Block Chaining (CBC)
def xor_bytes(a, b):
    return ''.join(chr(ord(x) ^ ord(y)) for x, y in zip(a, b))

def encrypt_aes_cbc(msg, key, iv):
    msg = add_pkcs7_padding(msg)
    print('Padded Plaintext (in Hex): ', end = '')
    print(str_to_hex(msg))
    print()
    blocks = [msg[i:i+16] for i in range(0, len(msg), 16)]

    encrypted_blocks = []
    previous_block = iv

    for i, block in enumerate(blocks):
        print(f'Block {i+1} (in Hex) =')
        print('• Plaintext  : ', end = '')
        print_hex(get_state(block))

        print('• Prev Block : ', end = '')
        print_hex(get_state(previous_block))

        xor_block = xor_bytes(block, previous_block)
        print('• Xor Block  : ', end = '')
        print_hex(get_state(xor_block))

        encrypted_block = encrypt_aes(xor_block, key)
        print('• Ciphertext : ', end = '')
        print_hex(get_state(encrypted_block))

        encrypted_blocks.append(encrypted_block)
        previous_block = encrypted_block
        

    return ''.join(encrypted_blocks)

def decrypt_aes_cbc(ciphertext, key, iv):
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]

    decrypted_blocks = []
    previous_block = iv

    for i, block in enumerate(blocks):
        print(f'Block {i+1} (in Hex) =')
        print('• Ciphertext : ', end = '')
        print_hex(get_state(block))

        print('• Prev Block : ', end = '')
        print_hex(get_state(previous_block))

        decrypted_xor_block = decrypt_aes(block, key)
        print('• Xor Block  : ', end = '')
        print_hex(get_state(decrypted_xor_block))

        decrypted_block = xor_bytes(decrypted_xor_block, previous_block)
        print('• Plaintext  : ', end = '')
        print_hex(get_state(decrypted_block))

        decrypted_blocks.append(decrypted_block)
        previous_block = block

    return remove_pkcs7_padding(''.join(decrypted_blocks))


def encode_base64(input_data):
    if isinstance(input_data, str):
        input_bytes = input_data.encode()
    else:
        input_bytes = input_data

    base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    binary_string = ''.join([f'{byte:08b}' for byte in input_bytes])

    padding_len = (6 - len(binary_string) % 6) % 6
    binary_string = binary_string.ljust(len(binary_string) + padding_len, '0')

    base64_encoded = ''
    for i in range(0, len(binary_string), 6):
        six_bit_chunk = binary_string[i:i+6]
        index = int(six_bit_chunk, 2)
        base64_encoded += base64_chars[index]

    base64_encoded += '=' * ((4 - len(base64_encoded) % 4) % 4)

    return base64_encoded


def decode_base64(base64_string):
    base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    base64_chars_dict = {char: index for index, char in enumerate(base64_chars)}

    base64_string = base64_string.rstrip('=')

    binary_string = ''.join([f'{base64_chars_dict[char]:06b}' for char in base64_string])

    binary_string = binary_string[:len(binary_string) - len(binary_string) % 8]
    decoded_bytes = bytearray()
    for i in range(0, len(binary_string), 8):
        byte = binary_string[i:i+8]
        decoded_bytes.append(int(byte, 2))

    return decoded_bytes.decode('utf-8')


# # Demo
while True:
    choice = input("[AES-CBC] (e)ncrypt, (d)ecrypt, or q(uit)? ").lower()

    if choice == 'e':
        msg = input("Enter Plain Text to Encrypt: ")
        key = input("Enter the Key (in 128, 192, or 256 bits): ")
        iv = input("Enter the IV (leave empty for default zero vector): ")
        print()
        
        if not iv:
            iv = get_msg([[00, 00, 00, 00], 
                          [00, 00, 00, 00], 
                          [00, 00, 00, 00], 
                          [00, 00, 00, 00]])

        print('||ENCRYPTION PROCESS||')
        ciphertext = encrypt_aes_cbc(msg, key, iv)

        print()
        print('Joined Ciphertext (in Hex)\t: ', end = '')
        print_hex(get_state(ciphertext))

        ciphertext_base64 = encode_base64(ciphertext)
        print(f'Joined Ciphertext (in Base64)\t: {ciphertext_base64}')
        print()

    elif choice == 'd':
        ciphertext_base64 = input("Enter Base64 Encoded Ciphertext to Decrypt: ")
        key = input("Enter the Key (in 128, 192, or 256 bits): ")
        iv = input("Enter the IV (leave empty for default zero vector): ")
        print()
        
        if not iv:
            iv = get_msg([[00, 00, 00, 00], 
                          [00, 00, 00, 00], 
                          [00, 00, 00, 00], 
                          [00, 00, 00, 00]])

        print('||DECRYPTION PROCESS||')
        decoded_cipher = decode_base64(ciphertext_base64)
        print('Ciphertext (in Hex) : ', end = '')
        print_hex(get_state(decoded_cipher))
        print()

        plaintext = decrypt_aes_cbc(decoded_cipher, key, iv)
        print()

        print('Joined Plaintext (in Hex)\t: ', end = '')
        print(str_to_hex(plaintext))

        print(f'Joined Plaintext (in Base64)\t: {plaintext}', end = '')
        print('\n')

    elif choice == 'q':
        print("Quitting the program.")
        break

    else:
        print("Invalid choice. Please enter 'e' to encrypt, 'd' to decrypt, or 'q' to quit.")
