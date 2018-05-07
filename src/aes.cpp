#include "aes.h"
#include "Rijndael.h"
#include <string.h>
#include <memory.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>

//C++ functionality for convenience
#include <string>
#include <iostream>
aes::aes()
{
  Nb = 4;
  Nk = 8;
  Nr = 14;
  padding_bytes = 0;
}

// exchanges columns in each of 4 rows
// row0 - unchanged, row1- shifted left 1, 
// row2 - shifted left 2 and row3 - shifted left 3

void aes::ShiftRows ()
{
uchar tmp;

	// just substitute row 0
	state[0] = Sbox[state[0]], state[4] = Sbox[state[4]];
	state[8] = Sbox[state[8]], state[12] = Sbox[state[12]];

	// rotate row 1
	tmp = Sbox[state[1]], state[1] = Sbox[state[5]];
	state[5] = Sbox[state[9]], state[9] = Sbox[state[13]], state[13] = tmp;

	// rotate row 2
	tmp = Sbox[state[2]], state[2] = Sbox[state[10]], state[10] = tmp;
	tmp = Sbox[state[6]], state[6] = Sbox[state[14]], state[14] = tmp;

	// rotate row 3
	tmp = Sbox[state[15]], state[15] = Sbox[state[11]];
	state[11] = Sbox[state[7]], state[7] = Sbox[state[3]], state[3] = tmp;
}

// restores columns in each of 4 rows
// row0 - unchanged, row1- shifted right 1, 
// row2 - shifted right 2 and row3 - shifted right 3
void aes::InvShiftRows ()
{
uchar tmp;

	// restore row 0
	state[0] = InvSbox[state[0]], state[4] = InvSbox[state[4]];
	state[8] = InvSbox[state[8]], state[12] = InvSbox[state[12]];

	// restore row 1
	tmp = InvSbox[state[13]], state[13] = InvSbox[state[9]];
	state[9] = InvSbox[state[5]], state[5] = InvSbox[state[1]], state[1] = tmp;

	// restore row 2
	tmp = InvSbox[state[2]], state[2] = InvSbox[state[10]], state[10] = tmp;
	tmp = InvSbox[state[6]], state[6] = InvSbox[state[14]], state[14] = tmp;

	// restore row 3
	tmp = InvSbox[state[3]], state[3] = InvSbox[state[7]];
	state[7] = InvSbox[state[11]], state[11] = InvSbox[state[15]], state[15] = tmp;
}

// recombine and mix each row in a column
void aes::MixSubColumns ()
{
uchar tmp[4 * Nb];

	// mixing column 0
	tmp[0] = Xtime2Sbox[state[0]] ^ Xtime3Sbox[state[5]] ^ Sbox[state[10]] ^ Sbox[state[15]];
	tmp[1] = Sbox[state[0]] ^ Xtime2Sbox[state[5]] ^ Xtime3Sbox[state[10]] ^ Sbox[state[15]];
	tmp[2] = Sbox[state[0]] ^ Sbox[state[5]] ^ Xtime2Sbox[state[10]] ^ Xtime3Sbox[state[15]];
	tmp[3] = Xtime3Sbox[state[0]] ^ Sbox[state[5]] ^ Sbox[state[10]] ^ Xtime2Sbox[state[15]];

	// mixing column 1
	tmp[4] = Xtime2Sbox[state[4]] ^ Xtime3Sbox[state[9]] ^ Sbox[state[14]] ^ Sbox[state[3]];
	tmp[5] = Sbox[state[4]] ^ Xtime2Sbox[state[9]] ^ Xtime3Sbox[state[14]] ^ Sbox[state[3]];
	tmp[6] = Sbox[state[4]] ^ Sbox[state[9]] ^ Xtime2Sbox[state[14]] ^ Xtime3Sbox[state[3]];
	tmp[7] = Xtime3Sbox[state[4]] ^ Sbox[state[9]] ^ Sbox[state[14]] ^ Xtime2Sbox[state[3]];

	// mixing column 2
	tmp[8] = Xtime2Sbox[state[8]] ^ Xtime3Sbox[state[13]] ^ Sbox[state[2]] ^ Sbox[state[7]];
	tmp[9] = Sbox[state[8]] ^ Xtime2Sbox[state[13]] ^ Xtime3Sbox[state[2]] ^ Sbox[state[7]];
	tmp[10]  = Sbox[state[8]] ^ Sbox[state[13]] ^ Xtime2Sbox[state[2]] ^ Xtime3Sbox[state[7]];
	tmp[11]  = Xtime3Sbox[state[8]] ^ Sbox[state[13]] ^ Sbox[state[2]] ^ Xtime2Sbox[state[7]];

	// mixing column 3
	tmp[12] = Xtime2Sbox[state[12]] ^ Xtime3Sbox[state[1]] ^ Sbox[state[6]] ^ Sbox[state[11]];
	tmp[13] = Sbox[state[12]] ^ Xtime2Sbox[state[1]] ^ Xtime3Sbox[state[6]] ^ Sbox[state[11]];
	tmp[14] = Sbox[state[12]] ^ Sbox[state[1]] ^ Xtime2Sbox[state[6]] ^ Xtime3Sbox[state[11]];
	tmp[15] = Xtime3Sbox[state[12]] ^ Sbox[state[1]] ^ Sbox[state[6]] ^ Xtime2Sbox[state[11]];

	memcpy (state, tmp, sizeof(tmp));
}

// restore and un-mix each row in a column
void aes::InvMixSubColumns ()
{
uchar tmp[4 * Nb];
int i;

	// restore column 0
	tmp[0] = XtimeE[state[0]] ^ XtimeB[state[1]] ^ XtimeD[state[2]] ^ Xtime9[state[3]];
	tmp[5] = Xtime9[state[0]] ^ XtimeE[state[1]] ^ XtimeB[state[2]] ^ XtimeD[state[3]];
	tmp[10] = XtimeD[state[0]] ^ Xtime9[state[1]] ^ XtimeE[state[2]] ^ XtimeB[state[3]];
	tmp[15] = XtimeB[state[0]] ^ XtimeD[state[1]] ^ Xtime9[state[2]] ^ XtimeE[state[3]];

	// restore column 1
	tmp[4] = XtimeE[state[4]] ^ XtimeB[state[5]] ^ XtimeD[state[6]] ^ Xtime9[state[7]];
	tmp[9] = Xtime9[state[4]] ^ XtimeE[state[5]] ^ XtimeB[state[6]] ^ XtimeD[state[7]];
	tmp[14] = XtimeD[state[4]] ^ Xtime9[state[5]] ^ XtimeE[state[6]] ^ XtimeB[state[7]];
	tmp[3] = XtimeB[state[4]] ^ XtimeD[state[5]] ^ Xtime9[state[6]] ^ XtimeE[state[7]];

	// restore column 2
	tmp[8] = XtimeE[state[8]] ^ XtimeB[state[9]] ^ XtimeD[state[10]] ^ Xtime9[state[11]];
	tmp[13] = Xtime9[state[8]] ^ XtimeE[state[9]] ^ XtimeB[state[10]] ^ XtimeD[state[11]];
	tmp[2]  = XtimeD[state[8]] ^ Xtime9[state[9]] ^ XtimeE[state[10]] ^ XtimeB[state[11]];
	tmp[7]  = XtimeB[state[8]] ^ XtimeD[state[9]] ^ Xtime9[state[10]] ^ XtimeE[state[11]];

	// restore column 3
	tmp[12] = XtimeE[state[12]] ^ XtimeB[state[13]] ^ XtimeD[state[14]] ^ Xtime9[state[15]];
	tmp[1] = Xtime9[state[12]] ^ XtimeE[state[13]] ^ XtimeB[state[14]] ^ XtimeD[state[15]];
	tmp[6] = XtimeD[state[12]] ^ Xtime9[state[13]] ^ XtimeE[state[14]] ^ XtimeB[state[15]];
	tmp[11] = XtimeB[state[12]] ^ XtimeD[state[13]] ^ Xtime9[state[14]] ^ XtimeE[state[15]];

	for( i=0; i < 4 * Nb; i++ )
		state[i] = InvSbox[tmp[i]];
}

// encrypt/decrypt columns of the key
// n.b. you can replace this with
//      byte-wise xor if you wish.

void aes::AddRoundKey (unsigned *state, unsigned *key)
{
int idx;
	for( idx = 0; idx < 4; idx++ )
		state[idx] ^= key[idx];
}

uchar Rcon[11] = {
0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

// produce Nb bytes for each round
void aes::ExpandKey (uchar *key, uchar *expkey)
{
uchar tmp0, tmp1, tmp2, tmp3, tmp4;
unsigned idx;

	memcpy (expkey, key, Nk * 4);

	for( idx = Nk; idx < Nb * (Nr + 1); idx++ ) {
		tmp0 = expkey[4*idx - 4];
		tmp1 = expkey[4*idx - 3];
		tmp2 = expkey[4*idx - 2];
		tmp3 = expkey[4*idx - 1];
		if( !(idx % Nk) ) {
			tmp4 = tmp3;
			tmp3 = Sbox[tmp0];
			tmp0 = Sbox[tmp1] ^ Rcon[idx/Nk];
			tmp1 = Sbox[tmp2];
			tmp2 = Sbox[tmp4];
		} else if( Nk > 6 && idx % Nk == 4 ) {
			tmp0 = Sbox[tmp0];
			tmp1 = Sbox[tmp1];
			tmp2 = Sbox[tmp2];
			tmp3 = Sbox[tmp3];
		}

		expkey[4*idx+0] = expkey[4*idx - 4*Nk + 0] ^ tmp0;
		expkey[4*idx+1] = expkey[4*idx - 4*Nk + 1] ^ tmp1;
		expkey[4*idx+2] = expkey[4*idx - 4*Nk + 2] ^ tmp2;
		expkey[4*idx+3] = expkey[4*idx - 4*Nk + 3] ^ tmp3;
	}
}

// encrypt one 128 bit block
void aes::EncryptBlock (uchar *expkey)
{
uchar state[Nb * 4];
unsigned round;

	memcpy (state, in, Nb * 4);
	AddRoundKey ((unsigned *)state, (unsigned *)expkey);

	for( round = 1; round < Nr + 1; round++ ) {
		if( round < Nr )
			MixSubColumns ();
		else
			ShiftRows ();

		AddRoundKey ((unsigned *)state, (unsigned *)expkey + round * Nb);
	}

	memcpy (out, state, sizeof(state));
}

void aes::DecryptBlock (uchar *expkey)
{
uchar state[Nb * 4];
unsigned round;

	memcpy (state, in, sizeof(state));

	AddRoundKey ((unsigned *)state, (unsigned *)expkey + Nr * Nb);
	InvShiftRows();

	for( round = Nr; round--; )
	{
		AddRoundKey ((unsigned *)state, (unsigned *)expkey + round * Nb);
		if( round )
			InvMixSubColumns ();
	} 

	memcpy (out, state, sizeof(state));
}

/*
#include <stdio.h>
#include <fcntl.h>
uchar in[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

uchar key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

uchar out[16];

#ifndef unix
void rd_clock (__int64 *ans)
{
unsigned dwLow, dwHigh;

	__asm {
		rdtsc
		mov dwLow, eax
		mov dwHigh, edx
	}
	*ans = (__int64)dwHigh << 32 | (__int64)dwLow;
}
#else
typedef long long __int64;

void rd_clock (__int64 *ans)
{
unsigned long long dwBoth;

	__asm__ volatile(".byte 0x0f, 0x31" : "=A"(dwBoth)); 
	*ans = dwBoth;
}
#endif

uchar samplekey[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab,
0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

uchar samplein[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31,
0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};

void sample ()
{
uchar expkey[4 * Nb * (Nr + 1)];
unsigned idx, diff;
__int64 start, stop;

	ExpandKey (samplekey, expkey);
	Encrypt (samplein, expkey, out);

	rd_clock(&start);

	Encrypt (samplein, expkey, out);

	rd_clock(&stop);
	diff = stop - start;
	printf ("encrypt time: %d, %d cycles per byte\n", diff, diff/16);

	for( idx = 0; idx < 16; idx++ )
		printf ("%.2x ", out[idx]);

	printf ("\n");
	Decrypt (out, expkey, in);
	rd_clock(&start);
	Decrypt (out, expkey, in);

	rd_clock(&stop);
	diff = stop - start;
	printf ("decrypt time: %d, %d cycles per byte\n", diff, diff/16);

	for( idx = 0; idx < 16; idx++ )
		printf ("%.2x ", in[idx]);

	printf ("\n");
}


void certify ()
{
uchar expkey[4 * Nb * (Nr + 1)];
unsigned idx, diff;
__int64 start, stop;

	ExpandKey (key, expkey);
	Encrypt (in, expkey, out);

	rd_clock(&start);

	Encrypt (in, expkey, out);

	rd_clock(&stop);
	diff = stop - start;
	printf ("encrypt time: %d, %d cycles per byte\n", diff, diff/16);

	for( idx = 0; idx < 16; idx++ )
		printf ("%.2x ", out[idx]);

	printf ("\n");
	Decrypt (out, expkey, in);
	rd_clock(&start);
	Decrypt (out, expkey, in);

	rd_clock(&stop);
	diff = stop - start;
	printf ("decrypt time: %d, %d cycles per byte\n", diff, diff/16);

	for( idx = 0; idx < 16; idx++ )
		printf ("%.2x ", in[idx]);

	printf ("\n");
}
*/

void aes::decrypt (char *mykey, char *name)
{
uchar expkey[4 * Nb * (Nr + 1)];
FILE *fd = fopen (name, "rb");
const char of_name[] = "out.tmp";
FILE *of = fopen (of_name, "wb");
int ch, idx = 0;

	strncpy ((char *)key, mykey, sizeof(key));
	ExpandKey (key, expkey);

  //get padding metadata
  int p = fseek(fd, -16, SEEK_END);
  padding_bytes = getc(fd);
  std::cerr << "read padding as " << padding_bytes << std::endl;
  fseek(fd, 0, SEEK_END);
  unsigned long long end = ftell(fd);
  std::cerr << "end is: " << end << std::endl;
  rewind(fd);
  unsigned long long int counter = 0; 
	while( ch = getc(fd), ch != EOF ) {
		in[idx++] = ch;
		if( idx % 16 )
			continue;

		DecryptBlock (expkey);

		for( idx = 0; idx < 16; idx++ )
			fputc (out[idx], of);
		idx = 0;
	}

  fclose(fd);
  unsigned long long int amt = end - (padding_bytes + 16);
  std::cerr << "amt to trunc: " << amt << std::endl;
  fclose(of); 
  std::string cmd = "truncate -s " + std::to_string(end-(padding_bytes+16)) + " " + of_name;
  system(cmd.c_str());


}

void aes::encrypt (char *mykey, char *name)
{
uchar expkey[4 * Nb * (Nr + 1)];
FILE *fd = fopen (name, "rb");
int ch, idx = 0;

	strncpy ((char *)key, mykey, sizeof(key));
	ExpandKey (key, expkey);

	while( ch = getc(fd), ch != EOF ) {
		in[idx++] = ch;
		if( idx % 16 )
			continue;

		EncryptBlock (expkey);

		for( idx = 0; idx < 16; idx++ )
			putchar (out[idx]);
		idx = 0;
	}

	if( idx ){
    padding_bytes = 16 - idx;
    std::cerr << "idx is " << idx << " and padding is " << padding_bytes << std::endl;
	  while( idx % 16 )
	    in[idx++] = 0;
    }
	else
	  return;

	EncryptBlock (expkey);

	for( idx = 0; idx < 16; idx++ )
		putchar (out[idx]);

  //padding metadata
  state[0] = padding_bytes;
  for (idx = 1; idx < 16; ++idx)
    state[idx] ^= state[idx];
 
 // EncryptBlock (expkey); 

	for( idx = 0; idx < 16; ++idx)
		putchar (state[idx]);


}

/*
uchar expkey[4 * Nb * (Nr + 1)];
void mrandom (int, char *);
unsigned xrandom (void);

int aescycles ()
{
__int64 start, end;
int t;

	do {
		rd_clock(&start);
		Encrypt (in, expkey, out);
		rd_clock (&end);
		t = end - start;
	} while( t<= 0 || t>= 4000);
	return t;
}

int bestx (int b, int loops)
{
int bestx = 0, bestxt = 0;
int x, xt, i, j;

	for( x = 0; x < 256; x++ ) {
		xt = 0;
		for( i = 0; i < loops; i++ ) {
			for( j = 0; j < 16; j++ )
				in[j] = xrandom() >> 16;
			in[b] = x;
			xt += aescycles(); xt += aescycles(); xt += aescycles();
			xt += aescycles(); xt += aescycles();
		}
		if( xt > bestxt )
			bestx = x, bestxt = xt;
	}
	return bestx;
}

void bernstein (char *seed)
{
int loops, b, j, k;

	mrandom (strlen(seed), seed);

	for( loops = 4; loops <= 65536; loops *= 16) {
		for( b = 0; b < 16; b++ ) {
			printf ("%.2d, %.5d loops:", b, loops);
			for( k = 0; k < 10; k++ ) {
				for( j = 0; j < 16; j++ )
					key[j] = xrandom() >> 16;
				ExpandKey (key, expkey);
				printf (" %.2x", bestx (b, loops) ^ key[b]);
				fflush (stdout);
			}
			printf ("\n");
		}
	}
}

void tables()
{
int i;

	for( i = 0; i < 256; i++)
	{
		printf("0x%.2x, ", Sbox[i] ^ Xtime2[Sbox[i]]);
		if( !((i+1) % 16) )
			printf("\n");
	}

	printf("\n");

	for( i = 0; i < 256; i++)
	{
		printf("0x%.2x, ", Xtime2[Sbox[i]]);
		if ( !((i+1) % 16) )
			printf("\n");
	}
}
*/

int main (int argc, char *argv[])
{
/*
#ifndef unix
extern int __cdecl _setmode (int, int);

	_setmode (_fileno(stdout), _O_BINARY);
#endif
*/   
    aes driver;
	switch( argv[1][0] ) {
//	case 'c': certify(); break;
	case 'e': driver.encrypt(argv[2], argv[3]); break;
	case 'd': driver.decrypt(argv[2], argv[3]); break;
//	case 'b': bernstein(argv[2]);	break;
//	case 's': sample(); break;
//	case 't': tables(); break;
	}
}

