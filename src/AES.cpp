#include "src/AES.h"
#include "src/Rijndael.h"
#include <string>
#include <iomanip>
#include <fstream>

/** 
 * Initialize the parameters of AES-256.
 */	
AES::AES()
{
	Nb = 4;
	Nk = 8;
	Nr = 14;
	padded_bytes = 0;
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

std::string AES::encrypt_line()
{
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

std::string AES::decrypt_line()
{
	AddRoundKey(Nr*Nb);
#ifdef DEBUG	
	std::cout << "After addRoundKey(" << Nr << "): " << std::endl<< export_state() << std::endl;
#endif

	for (unsigned int round = Nr-1; round > 0; --round)
	{
		InvShiftRows();
#ifdef DEBUG
	std::cout << "After invShiftRows: " << std::endl<< export_state() << std::endl;
#endif
		InvSubBytes();
#ifdef DEBUG
	std::cout << "After invSubBytes: " << std::endl<< export_state() << std::endl;
#endif
		AddRoundKey(round*Nb);
#ifdef DEBUG
	std::cout << "After addRoundKey(" << round << "): " << std::endl<< export_state() << std::endl;
#endif
		InvMixColumns();
#ifdef DEBUG
	std::cout << "After invMixColumns: " << std::endl<< export_state() << std::endl;
#endif
	}
	
	InvShiftRows();
#ifdef DEBUG
	std::cout << "After invShiftRows: " << std::endl<< export_state() << std::endl;
#endif
		InvSubBytes();
#ifdef DEBUG
	std::cout << "After invSubBytes: " << std::endl<< export_state() << std::endl;
#endif
		AddRoundKey(0);
#ifdef DEBUG
	std::cout << "After addRoundKey(0): " << std::endl<< export_state() << std::endl;
#endif

	return export_state();

}
void AES::encrypt(std::string keyFileName, std::string plaintextFileName, std::string outFileName)
{
	std::ifstream k;
	std::ifstream pt;
	std::ofstream ct;	
	std::string outputName = (outFileName.compare("") == 0) ? plaintextFileName + ".tmp" : outFileName;
	std::string t;	
	k.open(keyFileName);
	pt.open(plaintextFileName);	
	ct.open(outputName);
	std::string s;
	k >> s;
	init_key(s);
	s = get_line(pt);
	while (s != "")
	{
#ifdef DB_2
		std::cerr << "(e) plaintext: " << s << std::endl;
#endif
		init_state(s);		
		t = encrypt_line();
#ifdef DB_2
		std::cerr << "(e) ciphertext: " << t << std::endl;
#endif
		for (unsigned int i = 0; i < 32; i+=2)
			ct << (unsigned char)std::stoi(t.substr(i, 2), nullptr, 16);

		s = get_line(pt);
	}

	/* Append the number of padded bytes so we can stip off any padding during decryption */

	zero_state();
	state[0][0] = padded_bytes;
#ifdef DB_2
	std::cerr << "padding: " << export_state() << std::endl;
#endif
	t = encrypt_line();
#ifdef DB_2
	std::cerr << "(e) ciphertext: " << t << std::endl;
#endif
	for (unsigned int i = 0; i < 32; i+=2)
		ct << (unsigned char)std::stoi(t.substr(i, 2), nullptr, 16);

	/* If encrypting in place, remove the original, and rename the temporary file */
	if (outFileName.compare("") == 0)
	{
		int i;
		std::string cmd = "rm " + plaintextFileName;
		i = system(cmd.c_str());
		if (i) std::cerr << "Error: cmd '" << cmd << "' returned " << i << std::endl;	
		cmd = "mv " + plaintextFileName + ".tmp " + plaintextFileName; 
		i = system(cmd.c_str());
		if (i) std::cerr << "Error: cmd '" << cmd << "' returned " << i << std::endl;	
	}	
	return;
}

void AES::decrypt(std::string keyFileName, std::string ciphertextFileName, std::string outFileName)
{
	std::ifstream k;
	std::ifstream ct;	
	std::fstream pt;	/* need RW to deal with padding */
	std::string outputName = (outFileName.compare("") == 0 ? ciphertextFileName + ".tmp" : outFileName);
	unsigned char c;	
	k.open(keyFileName);
	ct.open(ciphertextFileName);
	pt.open("decrypt.tmp", std::fstream::out); /* placeholder */
	std::string s;
	k >> s;
	init_key(s);
	s = get_line(ct);
	while (s != "")
	{
#ifdef DB_2
		std::cerr << "(d) ciphertext: " << s << std::endl;
#endif
		init_state(s);
		std::string t = decrypt_line();
#ifdef DB_2
		std::cerr << "(d) plaintext: " << t << std::endl;
#endif
		for (unsigned int i = 0; i < 32; i+=2)
		{
			c = (unsigned char)std::stoi(t.substr(i, 2), nullptr, 16);
			pt << c; 	
		}
		s = get_line(ct);
	}

	/* Need to determine if any padding was added */
	pt.close();
	std::ifstream dec;
	dec.open("decrypt.tmp", std::fstream::in);
	dec.seekg(-16, dec.end);
	s = get_line(dec);
	unsigned int num_bytes = std::stoi(s.substr(0, 2), nullptr, 16);
	
	/* Get total length of file */
	dec.clear();
	dec.seekg(0, dec.end);
	int len = dec.tellg();
	dec.clear();
	dec.seekg(0, dec.beg);

	/* Copy the decrypted file without the padding */
	std::ofstream dec_tmp;
	dec_tmp.open(outputName);
	c = dec.get();
	for (unsigned int i = 0; i < len - 16 - num_bytes; ++i)
	{
		dec_tmp.put(c);
		c = dec.get();
	}
	
	int i;
	std::string cmd; 
	/* If we are decrypting in place, remove the original and rename the tmp file */	
	if (outFileName.compare("") == 0)
	{	
		cmd = "rm " + ciphertextFileName;
		i = system(cmd.c_str());
		if (i) std::cerr << "Error: cmd '" << cmd << "' returned " << i << std::endl;	
		cmd = "mv " + outputName + " " + ciphertextFileName; 
		i = system(cmd.c_str()); //TODO: change pls		
		if (i) std::cerr << "Error: cmd '" << cmd << "' returned " << i << std::endl;	
	}

	/* remove original tmp file */
	cmd = "rm decrypt.tmp";
	i = system(cmd.c_str());
	if (i) std::cerr << "Error: cmd '" << cmd << "' returned " << i << std::endl;	
		
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
	unsigned char c1 = r1[3];
	r1[3] = r1[2];
	r1[2] = r1[1];
	r1[1] = r1[0];
	r1[0] = c1;

/* Rotate 3rd row (state[2]) by 2 */
	c1 = r2[0];
	unsigned char c2 = r2[1];
	r2[0] = r2[2];
	r2[1] = r2[3];
	r2[2] = c1;
	r2[3] = c2;

	/* Rotate 4th row (state[3]) by 3 */
	c1 = r3[0];
	r3[0] = r3[1];
	r3[1] = r3[2];
	r3[2] = r3[3];
	r3[3] = c1;

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
			o << std::setfill('0') << std::setw(2) << std::hex << (unsigned int)state[j][i];
	
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

std::string AES::get_line(std::ifstream& file)
{
	if (file.eof()) return "";

	std::stringstream s;
	unsigned char c;
	c = file.get();
//	s << std::hex << ((c & 0xF0) >> 4) << (c & 0xF);
	for (unsigned int i = 0; i < 16; ++i)
	{
		s << std::hex << ((c & 0xF0) >> 4) << (c & 0xF);
		c = file.get();	
		if (file.eof())
		{
			padded_bytes = 16 - (i + 1);
			for (unsigned int j = i+1; j < 16; ++j)
				s << "00";
#ifdef DEBUG
			std::cerr << "get_line getting: " << s.str() << std::endl;	
#endif	
			return s.str();	
		}	
	}
	file.unget();
#ifdef DEBUG
	std::cerr << "get_line getting: " << s.str() << std::endl;	
#endif
	return s.str();	
}

void AES::zero_state()
{
	for (unsigned int i = 0; i < 4; ++i)
		for (unsigned int j = 0; j < 4; ++j)
			state[i][j] ^= state[i][j];
}
