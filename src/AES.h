#include <iostream>
#include <sstream>

/** The debugging flag. Uncomment to print debugging messages. */
//#define DEBUG 1
//#define DB_2 1


/**
 *  A class designed to encapsulate all block cipher functions used in the 
 *  AES-256 algorithm. This implementation operates only in CBC mode. 
 */
class AES
{
  private:
    unsigned char state[4][4];        /*< the state array */
    unsigned char key[32];            /*< the 256-bit key */
    unsigned int Nb;                	/*< the number of words in state */
    unsigned int Nk;                  /*< the number of words in key */
    unsigned int Nr;                 	/*< the number of rounds */
		unsigned int key_schedule[60];		/*< the expanded key */
		unsigned int padded_bytes;				/*< the number of bytes added as padding */

  public:

		/** Initialze the state for AES-256.
		 */
		AES();

		/** Encrypt a plaintext file. Can optionally provide an output file 
		 *	for testing, etc. 
		 *  @param keyFileName file name of the file containing the key
		 *  @param plaintextFileName file name of the plaintext file
		 *	@param outputFileName file name of output file
		 */ 
    void encrypt(std::string keyFileName, std::string plaintextFileName, 
									std::string outFileName = "");

		/** Grab a 8 bytes of input from the input file and load them into 
		 *	the state array. Pads the input with zeroes if necessary. 
		 *	@param file the input file
		 *	@return -1 on EOF, 0 otherwise
		 */
		int get_line(std::ifstream& file);
	
		/** Encrypt a line of hex characters.
		 *	@pre a line of plaintext has been loaded into the state array 
		 *	@return a line of encrypted hex characters
		 */
		std::string encrypt_line();
	
		/** Decrypt a ciphertext. Can optionally provide an output file 
		 * 	for testing, etc.
		 *  @param keyFileName file name of the file containing the key
		 *  @param plaintextFileName file name of the ciphertext file
		 */
		void decrypt(std::string keyFileName, std::string plaintextFileName, 
									std::string outFileName = "");

		/** Decrypt a line of hex characters.
		 *	@pre a line of ciphertext has been loaded into the state array
		 *	@return a line of decrypted hex characters
		 */
		std::string decrypt_line();
	
		/** Initialize the key schedule based on the provided 256-bit key.
		 * 	@param k the string of hex-coded byte values of the key
		 */
		void init_key(std::string k);

		/** Obtain a column from the row-major ordered key schedule.
		 *	@param i the index of the column
		 *	@return a column from the key schedule packed into a single word
		 */
		unsigned int column_from_key_schedule(unsigned int i);

		/** Initialize the state array.
		 *	@param bytes the string of hex-coded byte values 
		 */
		void init_state(std::string bytes);

		/** Substitute bytes in the state with bytes in the Rijndael S-box.
		 */
		void SubBytes();

		/** Shift the rows of the state. */
		void ShiftRows();

		/** XOR columns of the state with columns from the key schedule. */
		void MixColumns();

		/** Helper function for MixColumns. Adapted from implementation written by 
		 *	Dr. Bill Young. 
		 *	@param c the index of the column */
		void MixHelper(unsigned int c);

		/** XOR the round key with the state. 
		 *	@param index the index of the first column of the round key */
		void AddRoundKey(unsigned int index);	

		/** Inverse operation with respect to SubBytes. */
		void InvSubBytes();
		
		/** Inverse operation with respect to ShiftRows. */
		void InvShiftRows();
			
		/** Inverse operation with respect to MixColumns. */
		void InvMixColumns();
		
		/** Helper function for InvMixColumns. Adapted from implementation written by
		 *	Dr. Bill Young.
		 *	@param c the index of the column
		 */
		void InvMixHelper(unsigned int c);
	
		/** Rotate a 32-bit word by one byte, so that the MSB gets moved to the 
		 *	LSB position. 
		 *	@param w the word
		 *	@return the rotated word
		 */
		unsigned int RotWord(unsigned int w);

		/** Substitute the bytes in a word with bytes from Sbox.
		 *  @param w the word
		 *	@return the substituted bytes packed into a word
		 */
		unsigned int SubWord(unsigned int w);	
		
		/* debugging routines */
		void print_expanded_key();
		void print_state(std::ostream& o);		
		std::string export_state();

		/** Multiply two numbers via a Log table lookup. 
		 *	@param a the first number
		 *	@param b the second number
		 * 	@return the multiplication of the numbers
		 */
		unsigned char gmul(int a, int b);

		/** Zero out the state array */
		void zero_state();

};
