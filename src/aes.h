#include <iostream>

typedef unsigned char uchar;
class aes
{
    private:
        unsigned char state[16];
        unsigned char iv[16];
        unsigned char buffer[16];
        unsigned char key[32];
        uchar in[16];
        uchar out[16];
        unsigned int Nb;
        unsigned int Nk;
        unsigned int Nr;
        unsigned int padding_bytes;
        unsigned char expkey[240];
    
    public:
        aes();
        void ShiftRows();
        void InvShiftRows();
        void MixSubColumns();
        void InvMixSubColumns();
        void AddRoundKey(unsigned *state, unsigned *key);
        void ExpandKey(uchar *key, uchar *expkey);
        void EncryptBlock(uchar *expkey);
        void DecryptBlock(uchar *expkey);
        void decrypt(char *mykey, char *name);
        void encrypt(char *mykey, char *name);
        
};
