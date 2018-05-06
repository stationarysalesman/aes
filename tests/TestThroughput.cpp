#include <iostream>

/* Test the throughput of aes */
#define FSIZE 104 //file size in MB
int main()
{
	int i;
	unsigned long start = (unsigned long)time(NULL);
	i = system("../src/aes -e -k Acceptance1key.txt -i largefile");
	unsigned long end = (unsigned long)time(NULL);
	unsigned long encrypt_time = end - start;
	double encrypt_throughput = FSIZE / encrypt_time;
	
	start = (unsigned long)time(NULL);
	i = system("../src/aes -d -k Acceptance1key.txt -i largefile");
	end = (unsigned long)time(NULL);
	unsigned long decrypt_time = (end - start);
	double decrypt_throughput = FSIZE / decrypt_time;
	
	std::cout << "Encryption throughput: " << encrypt_throughput << std::endl;	
	std::cout << "Decryption throughput: " << decrypt_throughput << std::endl;	
	return 0;
}
