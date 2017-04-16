#include <iostream>


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

  public:

		/** Initialze the state for AES-256.
		 */
		AES();

		/** Encrypt a plaintext file. 
		 *  @param keyFileName file name of the file containing the key
		 *  @param plaintextFileName file name of the plaintext file
		 */ 
    void encrypt(std::string keyFileName, std::string plaintextFileName);
		
		/** Decrypt a ciphertext.
		 *  @param keyFileName file name of the file containing the key
		 *  @param plaintextFileName file name of the ciphertext file
		 */
		void decrypt(std::string keyFileName, std::string plaintextFileName);

		/** Initialize the key schedule based on the provided 256-bit key.
		 * 	@param k the string of hex-coded byte values of the key
		 */
		void init_key(std::string k);

		/** Initialize the state array.
		 *	@param bytes the string of hex-coded byte values 
		 */
		void init_state(std::string bytes);
		
		/** Rotate a 32-bit word by one byte, so that the MSB gets moved to the 
		 *	LSB position. 
		 *	@param w the word
		 *	@return the rotated word
		 */
		inline unsigned int RotWord(unsigned int w);

		/** Substitute the bytes in a word with bytes from Sbox.
		 *  @param w the word
		 *	@return the substituted bytes packed into a word
		 */
		unsigned int SubWord(unsigned int w);	
		
};