#include "AES.h"
#include "RijndaelConstants.h"

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

int main(int argc, char *argv[])
{
	std::cout << "Welcome to zombocom" << std::endl;
	return 0;	
}
