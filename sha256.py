
# Cube roots of first 32 prime numbers
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

H0 = 0x6a09e667
H1 = 0xbb67ae85
H2 = 0x3c6ef372
H3 = 0xa54ff53a
H4 = 0x510e527f
H5 = 0x9b05688c
H6 = 0x1f83d9ab
H7 = 0x5be0cd19

def format_hex_output(hash_list: list[int]) -> str:
    return "".join(f"{x:08x}" for x in hash_list)

class SHA256:
    def __init__(self, message: bytearray):
        self.message = message
        if isinstance(self.message,str):
            self.message = bytearray(self.message,'ascii')
        elif isinstance(self.message,bytes):
            self.message = bytearray(self.message)
        else:
            raise TypeError    

    def generating_hash(self):
        self.__padding(self.message)
        self.hashed_message = self.__hash_computation()
        return format_hex_output(self.hashed_message)

    def __ch(self, x: int, y: int, z: int):
        return ((x & y) ^ (~x & z)) & 0xffffffff
    
    def __maj(self, x: int, y: int, z: int):
        return ((x & y) ^ (x & z) ^ (y & z)) & 0xffffffff

    def __rotating_right(self, x: int, shift: int, size = 32):
        return ((x >> shift) | (x << (size - shift))) & 0xffffffff

    def __sigma0(self, x: int):
        return (self.__rotating_right(x, 7) ^ 
                self.__rotating_right(x, 18) ^ 
                (x >> 3)) & 0xffffffff

    def __sigma1(self, x: int):
        return (self.__rotating_right(x, 17) ^ 
                self.__rotating_right(x, 19) ^ 
                (x >> 10)) & 0xffffffff

    def __capsigma0(self, x: int):
        return (self.__rotating_right(x, 2) ^ 
                self.__rotating_right(x, 13) ^ 
                self.__rotating_right(x, 22)) & 0xffffffff

    def __capsigma1(self, x: int):
        return (self.__rotating_right(x, 6) ^ 
                self.__rotating_right(x, 11) ^ 
                self.__rotating_right(x, 25)) & 0xffffffff
    

    def __padding(self,message):
        self.message_size = len(message)*8 # Length of message in byte

        # Added 1 bit at the end of current message in byte
        self.message.append(0x80)

        # Adding 0x00 until 64bits left
        while len(self.message) % 64 != 56:
            self.message.append(0x00)
        
        # Adding last 64bits to fit 512bit, 64bits is the actual length of input message
        self.message+=self.message_size.to_bytes(8,'big')

    def __parsing(self, message):
        blocks = []
        for i in range(0,len(self.message),64):
            blocks.append(message[i:i+64])
        return blocks

            
    def __message_expansion_schedule(self):
        padded_messages  = self.__parsing(self.message)

        for block in padded_messages:
            message_scheduled = []
            for i in range(0,64):
                if i < 16:
                    # A word = each 4 bytes from current block 
                    message_scheduled.append(bytes(block[i*4:(i*4)+4]))
                else:
                    ele1 = self.__sigma1(int.from_bytes(message_scheduled[i-2], 'big'))
                    ele2 = int.from_bytes(message_scheduled[i-7], 'big')
                    ele3 = self.__sigma0(int.from_bytes(message_scheduled[i-15], 'big'))
                    ele4 = int.from_bytes(message_scheduled[i-16], 'big')                   
                    message_scheduled.append(((ele1+ele2+ele3+ele4)&0xffffffff).to_bytes(4,'big'))
                    
            yield message_scheduled

    def __compression_round(self,
                            a: int,b: int,c: int,
                            d: int,e: int,f: int,
                            g: int,h: int,idx: int,
                            word: bytes
                            ) -> tuple[int,int,int,int,int,int,int,int]:
        word = int.from_bytes(word,'big') & 0xffffffff
        t1 = (h + self.__capsigma1(e) + self.__ch(e,f,g) + K[idx] + word) & 0xffffffff
        t2 = (self.__capsigma0(a) + self.__maj(a,b,c)) & 0xffffffff
        return (t1+t2)&0xffffffff, a,b,c,(d+t1)&0xffffffff,e,f,g

    def __hash_computation(self):
        current_h = [H0, H1, H2, H3, H4, H5, H6, H7]
        for schedule in self.__message_expansion_schedule():
            a,b,c,d,e,f,g,h = current_h
            for i in range(64):
                a,b,c,d,e,f,g,h = self.__compression_round(a,b,c,d,e,f,g,h,i,schedule[i])
            
            for idx, val in enumerate([a,b,c,d,e,f,g,h]):
                current_h[idx] = (current_h[idx] + val) & 0xffffffff

        return current_h