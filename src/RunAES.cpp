#include "AES.h"
#include <iostream>

/** Main program driver. */

int main(int argc, char *argv[])
{
	std::string e = "e", d = "d";
	if (argc != 4)
	{
		std::cout << "Error: " << argc-1 << " arguments given (need 3)" << std::endl;
		return 1;
	}

	std::string keyFile = argv[2], textFile = argv[3];

	AES cipher = AES();

	/* Encrypt a file */	
	if (e.compare(argv[1]) == 0)
		cipher.encrypt(keyFile, textFile);
	else if (d.compare(argv[1]) == 0)
		cipher.decrypt(keyFile, textFile);
	else
	{
		std::cout << "Error: invalid option '" << argv[1] << "'" << std::endl;
		return 1;
	}	
	return 0;	
}
