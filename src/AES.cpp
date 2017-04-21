#include "src/AES.h"
#include "src/Rijndael.h"
#include <string>
#include <iomanip>

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
	for (unsigned int i = 0, j = 0; i < k.size(); i += 2, j++)
  	key[j] = (unsigned char)std::stoi(k.substr(i, 2), nullptr, 16);	

	unsigned int i = 0;
	while (i < Nk)
	{
		unsigned int w0 = key[4*i];
		unsigned int w1 = key[4*i+1];
		unsigned int w2 = key[4*i+2];
		unsigned int w3 = key[4*i+3];
		unsigned int w = w0 | (w1 << 8) | (w2 << 16) | (w3 << 24);
		key_schedule[i] = w;
		++i;
	}

	i = Nk;

	while (i < Nb * (Nr+1))
	{
		unsigned int temp = key_schedule[i-1];

		if (i % Nk == 0)
			temp = SubWord(RotWord(temp)) ^ Rcon[i/Nk];
		else if (Nk > 6 && i % Nk == 4)
			temp = SubWord(temp);
		key_schedule[i] = key_schedule[i-Nk] ^ temp;

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

unsigned int AES::RotWord(unsigned int w)
{
	return (w << 8) | ((w >> 24) & 0xFF);
}

void AES::init_state(std::string bytes)
{
	unsigned char b[16];
	unsigned int pos = 0;
	for (unsigned int a = 0; a < 16; ++a)
	{
		std::string sub = bytes.substr(pos, 2);
		pos += 2;
		b[a] = (unsigned char)std::stoi(sub, nullptr, 16);		
	}
	
	for (unsigned int i = 0; i < 4; ++i)
		for (unsigned int j = 0; j < 4; ++j)
			state[i][j] = b[i+4*j];	
}

void AES::SubBytes()
{
	for (unsigned int i = 0; i < 4; ++i)
		for (unsigned int j = 0; j < 4; ++j)
			state[i][j] = Sbox[state[i][j]];
}

void AES::ShiftRows()
{
	unsigned char *r1 = state[1];
	unsigned char *r2 = state[2];
	unsigned char *r3 = state[3];

	/* Rotate the 2nd row (state[1]) by 1 */
	unsigned char c1 = r1[0];
	r1[0] = r1[1];
	r1[1] = r1[2];
	r1[2] = r1[3];
	r1[3] = c1;

	/* Rotate 3rd row (state[2]) by 2 */
	c1 = r2[0];
	unsigned char c2 = r2[1];
	r2[0] = r2[2];
	r2[1] = r2[3];
	r2[2] = c1;
	r2[3] = c2;

	/* Rotate 4th row (state[3]) by 3 */
	c1 = r3[3];
	r3[3] = r3[2];
	r3[2] = r3[1];
	r3[1] = r3[0];
	r3[0] = c1;

}

unsigned char AES::gmul(int a, int b)
{
	int inda = (a < 0) ? (a + 256) : a;
	int indb = (b < 0) ? (b + 256) : b;

	if ( (a != 0) && (b != 0) ) 
	{
		int index = (LogTable[inda] + LogTable[indb]);
		unsigned char val = (unsigned char)(AlogTable[ index % 255 ] );
		return val;
	}
  else 
      return 0;

}

void AES::MixColumns()
{
	for (unsigned int i = 0; i < 4; ++i)
		MixHelper(i);
}

void AES::MixHelper(unsigned int c)
{
	unsigned char a[4];

  // note that a is just a copy of st[.][c]
  for (unsigned int i = 0; i < 4; i++)
      a[i] = state[i][c];

	state[0][c] = (unsigned char)(gmul(2,a[0]) ^ a[2] ^ a[3] ^ gmul(3,a[1]));
	state[1][c] = (unsigned char)(gmul(2,a[1]) ^ a[3] ^ a[0] ^ gmul(3,a[2]));
	state[2][c] = (unsigned char)(gmul(2,a[2]) ^ a[0] ^ a[1] ^ gmul(3,a[3]));
	state[3][c] = (unsigned char)(gmul(2,a[3]) ^ a[1] ^ a[2] ^ gmul(3,a[0]));

}

std::string AES::encrypt_line(std::string line)
{
	//TODO: deal with malformed input?
	
	if (line.size() < 32)
		line.append(32 - line.size(), '0');
	init_state(line);
	AddRoundKey(0);
#ifdef DEBUG
	std::cout << "After addRoundKey(0): " << std::endl << export_state() << std::endl;
#endif
	
	for (unsigned int round = 1; round < Nr; ++round)
	{
		SubBytes();
#ifdef DEBUG
		std::cout << "After subBytes: " << std::endl<< export_state() << std::endl;
#endif
		ShiftRows();
#ifdef DEBUG
		std::cout << "After shiftRows: " << std::endl<< export_state() << std::endl;
#endif
		MixColumns();
#ifdef DEBUG
		std::cout << "After mixColumns: "<< std::endl << export_state() << std::endl;
#endif
		AddRoundKey(round*Nb);
#ifdef DEBUG
		std::cout << "After addRoundKey(" << round << "): " << std::endl<< export_state() << std::endl;
#endif
	}

	SubBytes();
#ifdef DEBUG
	std::cout << "After subBytes: " << std::endl<< export_state() << std::endl;
#endif
	ShiftRows();
#ifdef DEBUG
	std::cout << "After shiftRows: " << std::endl<< export_state() << std::endl;
#endif
	AddRoundKey(Nr*Nb);
#ifdef DEBUG
	std::cout << "After addRoundKey(" << Nr << "): " << std::endl<< export_state() << std::endl;
#endif

	return export_state();	
}
void AES::encrypt(std::string keyFileName, std::string plaintextFileName)
{
	//TODO: no hardcoded key or plaintext
	init_key("00000000000000000000000000000000");
	print_expanded_key();
	encrypt_line("00112233445566778899AABBCCDDEEFF");
		
	return;			
}

void AES::InvSubBytes()
{
	for (unsigned int i = 0; i < 4; ++i)
		for (unsigned int j = 0; j < 4; ++j)
			state[i][j] = InvSbox[state[i][j]];
}

void AES::InvShiftRows()
{
	unsigned char *r1 = state[1];
	unsigned char *r2 = state[2];
	unsigned char *r3 = state[3];

	/* Rotate the 2nd row (state[1]) by 1 (left) */
	unsigned char c1 = r3[3];
	r3[3] = r3[2];
	r3[2] = r3[1];
	r3[1] = r3[0];
	r3[0] = c1;

/* Rotate 3rd row (state[2]) by 2 */
	c1 = r2[0];
	unsigned char c2 = r2[1];
	r2[0] = r2[2];
	r2[1] = r2[3];
	r2[2] = c1;
	r2[3] = c2;

	/* Rotate 4th row (state[3]) by 3 */
	c1 = r1[0];
	r1[0] = r1[1];
	r1[1] = r1[2];
	r1[2] = r1[3];
	r1[3] = c1;

}

void AES::InvMixColumns()
{
	for (unsigned int i = 0; i < 4; ++i)
		InvMixHelper(i);
}

void AES::InvMixHelper(unsigned int c)
{
	unsigned char a[4];

  // note that a is just a copy of st[.][c]
  for (unsigned int i = 0; i < 4; i++)
      a[i] = state[i][c];

	state[0][c] = (unsigned char)(gmul(0xE,a[0]) ^ gmul(0xB,a[1]) ^ gmul(0xD, a[2]) ^ gmul(0x9,a[3]));
	state[1][c] = (unsigned char)(gmul(0xE,a[1]) ^ gmul(0xB,a[2]) ^ gmul(0xD, a[3]) ^ gmul(0x9,a[0]));
	state[2][c] = (unsigned char)(gmul(0xE,a[2]) ^ gmul(0xB,a[3]) ^ gmul(0xD, a[0]) ^ gmul(0x9,a[1]));
	state[3][c] = (unsigned char)(gmul(0xE,a[3]) ^ gmul(0xB,a[0]) ^ gmul(0xD, a[1]) ^ gmul(0x9,a[2]));
 
}


void AES::AddRoundKey(unsigned int index)
{
	unsigned int cols[4];
	for (unsigned int i = 0, j = index; i < 4; ++i, ++j)
		cols[i] = column_from_key_schedule(j);

	for (unsigned int j = 0; j < 4; ++j)
	{
		unsigned int w = cols[j];
		for (unsigned int i=0; i < 4; ++i)
			state[j][i] ^= ((w >> (24 - (i * 8))) & 0xFF);
	}
}

void AES::decrypt(std::string keyFileName, std::string ciphertextfileName)
{

}	


/***** Utilities *****/
unsigned int AES::column_from_key_schedule(unsigned int i)
{
	unsigned int i1 = (i / 4) * 4; /* Index of 1st word in array that contains column */
	unsigned int i2 = 24 - ((i % 4) * 8); /* Amount to shift each word to get desired byte */
	unsigned int b1 = (key_schedule[i1] >> i2) & 0xFF;
	unsigned int b2 = (key_schedule[i1+1] >> i2) & 0xFF;
	unsigned int b3 = (key_schedule[i1+2] >> i2) & 0xFF;
	unsigned int b4 = (key_schedule[i1+3] >> i2) & 0xFF;
	return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4; 
}

/***** Debugging *****/
void AES::print_expanded_key()
{

	for (unsigned int i = 0; i < sizeof(key_schedule)/sizeof(key_schedule[0]); ++i)
		std::cout << std::setfill('0') << std::setw(8) << std::setbase(16) <<  \
			column_from_key_schedule(i) << " ";
	std::cout << std::endl;	
}

void AES::print_state(std::ostream& o)
{
	for (unsigned int i = 0; i < 4; ++i)
		for (unsigned int j = 0; j < 4; ++j)
			o << std::setfill('0') << std::setw(2) << std::hex << (unsigned int)state[i][j];
	
	o << std::endl;	
}

std::string AES::export_state()
{
	std::ostringstream o;
	for (unsigned int i = 0; i < 4; ++i)
		for (unsigned int j = 0; j < 4; ++j)
			o << std::setfill('0') << std::setw(2) << std::hex << (unsigned int)state[j][i];
	return o.str();		
}
