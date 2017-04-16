#include "src/AES.h"
#include "src/Rijndael.h"
#include <string>

/** 
 * Initialize the parameters of AES-256.
 */	
AES::AES()
{
	Nb = 4;
	Nk = 8;
	Nr = 14;
}

void AES::init_key(std::string k)
{
	for (int i = 0, j = 0; i < k.size(); i += 2, j++)
  	key[j] = (char)std::stoi(k.substr(i, i+2), nullptr, 16);	

	int i = 0;
	while (i < Nk)
	{
		int w0 = key[4*i];
		int w1 = key[4*i+1];
		int w2 = key[4*i+2];
		int w3 = key[4*i+3];
		int w = w0 | (w1 << 8) | (w2 << 16) | (w3 << 24);
		key_schedule[i] = w;
		++i;
	}

	i = AES::Nk;

	while (i < AES::Nb * (AES::Nr+1))
	{
		int temp = key_schedule[i-1];

		if (i % AES::Nk == 0)
			temp = SubWord(RotWord(temp)) ^ Rcon[i/Nk];
		else if (AES::Nk > 6 && i % AES::Nk == 4)
			temp = SubWord(temp);
		key_schedule[i] = key_schedule[i-AES::Nk] ^ temp;

		++i;

	}
	
	return;
}

unsigned int AES::SubWord(unsigned int w)
{
	unsigned int i1 = (w >> 24) & 0xFF;
	unsigned int i2 = (w >> 16) & 0xFF;
	unsigned int i3 = (w >> 8) & 0xFF;
	unsigned int i4 = w & 0xFF;
	unsigned char c1 = (unsigned char)i1;
	unsigned char c2 = (unsigned char)i2;
	unsigned char c3 = (unsigned char)i3;
	unsigned char c4 = (unsigned char)i4;
	return (Sbox[c1] << 24) | (Sbox[c2] << 16) | (Sbox[c3] << 8) | Sbox[c4];
}

inline unsigned int AES::RotWord(unsigned int w)
{
	return (w << 8) | ((w >> 24) & 0xFF);
}

void AES::init_state(std::string bytes)
{
	return;
}

void AES::encrypt(std::string keyFileName, std::string plaintextFileName)
{
	//TODO: no hardcoded key or plaintext
	init_key("00000000000000000000000000000000");
	init_state("00112233445566778899AABBCCDDEEFF");
	return;			
}

void AES::decrypt(std::string keyFileName, std::string ciphertextfileName)
{

}	

