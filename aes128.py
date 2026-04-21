RCON = (
            0x00, 0x01, 0x02, 0x04, 0x08, 
            0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

def gmul(a,coeff):
    if coeff == 1:
        return a
    elif coeff == 2:
        # GF(2^8) mult by 0x02: shift left 1, XOR 0x1b if MSB=1 (xtime)        
        temp = ((a<<1) & 0xff)
        
        if a & 0x80:
            temp ^= 0x1b
        return temp
    
    else:
        return a ^ gmul(a,2)

def transpose_matrix(matrix: list[list[any]]):
    return [[matrix[j][i] for j in range(len(matrix))] for i in range(len(matrix[0]))]
    
def text_to_matrix(text: str)-> list[list[int]]:
    matrix = [[], [], [], []]
    for i in range(16):
        byte = ord(text[i])
        matrix[i%4].append(byte)
    return matrix     

def matrix_to_text(matrix: list[list[int]]) -> str:
    return ''.join(hex(matrix[i][j])[2:].zfill(2) for j in range(4) for i in range(4))

class AES128:
    def __init__(self, secret_key: str):
        if len(secret_key) != 16:
            raise ValueError('Length of input key must be equal 128bit!')
        self.change_keys(secret_key)
    
    def __sub_bytes(self,state_matrix: list[list[str]]):
        for i in range(len(state_matrix)):
            for j in range(len(state_matrix)):
                state_matrix[i][j] = SBOX[state_matrix[i][j]]

    def __shift_rows(self, state_matrix: list[list[str]]):
        for i in range(1,4):
            state_matrix[i] = state_matrix[i][i:] + state_matrix[i][:i]

    def __mix_single_columns(self, *col: list[int]):
        a = gmul(col[0],2) ^ gmul(col[1],3) ^ col[2] ^ col[3]
        b = col[0] ^ gmul(col[1],2) ^ gmul(col[2],3) ^ col[3]
        c = col[0] ^ col[1] ^ gmul(col[2],2) ^ gmul(col[3],3)
        d = gmul(col[0],3) ^ col[1] ^ col[2] ^ gmul(col[3],2)
        return a, b, c, d

    def __mix_columns(self, state_matrix: list[list[str]]):
        for i in range(4):
            state_matrix[0][i], state_matrix[1][i], state_matrix[2][i], state_matrix[3][i] = self.__mix_single_columns(state_matrix[0][i], state_matrix[1][i], state_matrix[2][i], state_matrix[3][i])

    def change_keys(self, secret_key):
        self.round_keys = transpose_matrix(text_to_matrix(secret_key))
        for i in range(4, 11*4):
            self.round_keys.append([])

            if i%4==0:
                first_temp_byte = self.round_keys[i-4][0] ^ SBOX[self.round_keys[i-1][1]] ^ RCON[i//4]
                self.round_keys[i].append(first_temp_byte)

                for j in range(1,4):
                    temp_byte = SBOX[self.round_keys[i-1][(j+1)%4]] ^ self.round_keys[i-4][j]
                    self.round_keys[i].append(temp_byte)

            else:
                for j in range(4):
                    temp_byte = self.round_keys[i-1][j] ^ self.round_keys[i-4][j]
                    self.round_keys[i].append(temp_byte)
        
        for i in range(0,44,4):
            self.round_keys[i:i+4] = transpose_matrix(self.round_keys[i:i+4])

    def __add_round_key(self, state_matrix: list[list[int]], round_key: list[list[int]]):
        for i in range(4):
            for j in range(4):
                state_matrix[i][j] = state_matrix[i][j] ^ round_key[i][j]

    def __round_encrypt(self, state_matrix, round_key_matrix):
        
        self.__sub_bytes(state_matrix)
        self.__shift_rows(state_matrix)
        self.__mix_columns(state_matrix)
        self.__add_round_key(state_matrix, round_key_matrix)

    def encrypt(self, plaintext: str):
        self.state_matrix = text_to_matrix(plaintext)
        
        # Initialize State Matrix before Round 1
        self.__add_round_key(self.state_matrix, self.round_keys[:4])
        for i in range(1,10):
            self.__round_encrypt(self.state_matrix, self.round_keys[4*i:4*(i+1)])

        # No MixColumns func in final round
        self.__sub_bytes(self.state_matrix)
        self.__shift_rows(self.state_matrix)
        self.__add_round_key(self.state_matrix, self.round_keys[40:])
        
        return matrix_to_text(self.state_matrix) 

