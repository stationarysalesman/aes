#include "AES.h"
#include "Rijndael.h"
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
/*
		if (i % AES::Nk == 0)
			temp = SubWord(RotWord(temp)) ^ Rcon(i/Nk);
		else if (AES::Nk > 6 && i % AES::Nk == 4)
			temp = SubWord(temp);
		key_schedule[i] = key_schedule[i-AES::Nk] ^ temp;
*/
		++i;

	}
	
	return;
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

void decrypt(std::string keyFileName, std::string ciphertextfileName)
{

}	

