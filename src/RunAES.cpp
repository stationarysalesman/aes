#include "aes.h"
#include <iostream>
#include <unistd.h>

/** Main program driver. */

int main(int argc, char *argv[])
{
	std::string keyFile, textFile, output_filename;
	bool encrypt = false;	
	bool decrypt = false;	

	int opt;
	while ((opt = getopt(argc, argv, "o:edk:i:")) != -1)
	{
		switch (opt)
		{
			case 'o':
				output_filename = optarg;
				break;
			case 'e':							
				encrypt = true;
				break;
			case 'd':
				decrypt = true;
				break;
			case 'k':
				keyFile = optarg;
				break;
			case 'i':
				textFile = optarg;
				break;
			default:
				std::cerr << "Argument error" << std::endl;
				exit(1);
		}
	}

	aes cipher = aes();

	/* Encrypt a file */	
	if (encrypt && !decrypt)
		cipher.encrypt(keyFile, textFile, output_filename);
	else if (decrypt && !encrypt)
		cipher.decrypt(keyFile, textFile, output_filename);
	else
	{
		std::cout << "Please select either encryption or decryption." << std::endl;
		return 1;
	}	
	return 0;	
}
