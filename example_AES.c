#include "example_AES.h"
#include <avr/io.h>

/**
*	set the trigger PIN
*/
#define set_pin(port, value) ((port)|=(value))
/**
*	clear the trigger PIN
*/
#define clear_pin(port, value) ((port)&=(value))

/**
*	The number of 32 bit words in a key.
*/
#define NumberOfWords 4
/**
*	The number of rounds in AES Cipher.
*/
#define NumberOfRounds 10
/**
*	The number of columns comprising a state in AES
*/
#define NumberOfColumns 4

unsigned char buffer[16];

static unsigned char s_box[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const unsigned char Rcon[11] = { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

/*
static uint8_t getSBoxValue(unsigned char  num)
{
return sbox[num];
}
*/
#define getSBoxValue(num) (s_box[(num)])

/**
*	Produce 4*(NumberOfRounds+1) round keys in each round to encrypt the states.
*/
void KeyExpansion(unsigned char *key,unsigned char *roundKey)
{
	unsigned char tmp[4];
	unsigned int i, j, k;

	// The first round key is the key itself.
	for (i = 0; i < NumberOfWords; i++)
	{
		roundKey[(i * 4) + 0] = key[(i * 4) + 0];
		roundKey[(i * 4) + 1] = key[(i * 4) + 1];
		roundKey[(i * 4) + 2] = key[(i * 4) + 2];
		roundKey[(i * 4) + 3] = key[(i * 4) + 3];
	}

	// All other round keys are found from the previous round keys.
	for (j = NumberOfWords; j< 4 * (NumberOfRounds + 1); j++)
	{
		tmp[0] = roundKey[4 * (j - 1) + 0];
		tmp[1] = roundKey[4 * (j - 1) + 1];
		tmp[2] = roundKey[4 * (j - 1) + 2];
		tmp[3] = roundKey[4 * (j - 1) + 3];

		if (j%NumberOfWords == 0)
		{
			// Shifts the 4 bytes in a word to the left once.
			{
				k = tmp[0];
				tmp[0] = tmp[1];
				tmp[1] = tmp[2];
				tmp[2] = tmp[3];
				tmp[3] = k;
			}

			// Take a four-byte input word and applies the S-box to each of the four bytes to produce an output word.
			{
				tmp[0] = getSBoxValue(tmp[0]);
				tmp[1] = getSBoxValue(tmp[1]);
				tmp[2] = getSBoxValue(tmp[2]);
				tmp[3] = getSBoxValue(tmp[3]);
			}

			tmp[0] = (tmp[0] ^ Rcon[j / NumberOfWords]);
		}

		roundKey[4 * j + 0] = roundKey[4 * (j - NumberOfWords) + 0] ^ tmp[0];
		roundKey[4 * j + 1] = roundKey[4 * (j - NumberOfWords) + 1] ^ tmp[1];
		roundKey[4 * j + 2] = roundKey[4 * (j - NumberOfWords) + 2] ^ tmp[2];
		roundKey[4 * j + 3] = roundKey[4 * (j - NumberOfWords) + 3] ^ tmp[3];
	}
}

/**
*	Substitutes the values in the state with values in an S-box.
*/
void sub_bytes(unsigned char *state) {

	unsigned char i, j;
	unsigned char row, col, sboxvalue;

	for (i = 0; i < 4; i++) {
		for (j = 0; j < NumberOfColumns; j++) {
			unsigned char temp = state[NumberOfColumns*i + j];
			row = (state[NumberOfColumns*i + j] & 0xf0) >> 4;
			col = state[NumberOfColumns*i + j] & 0x0f;
			temp = getSBoxValue(16 * row + col);
			state[NumberOfColumns*i + j] = getSBoxValue(16 * row + col);
		}
	}
}

/**
* Shifts the rows in the state to the left with different offset corresponding to row number
* The first row is not shifted.
*/
void shift_rows(unsigned char *state)
{
	unsigned char tmp1, tmp2;

	tmp1 = state[1];

	state[1] = state[5];
	state[5] = state[9];
	state[9] = state[13];
	state[13] = tmp1;

	tmp1 = state[6];
	tmp2 = state[2];

	state[2] = state[10];
	state[6] = state[14];
	state[10] = tmp2;
	state[14] = tmp1;

	tmp1 = state[3];
	state[3] = state[15];
	state[15] = state[11];
	state[11] = state[7];
	state[7] = tmp1;

}

static unsigned char xtime(unsigned char x)
{
	return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

/**
* Galois field multiplication
*/
unsigned char galois_mult(unsigned char a, unsigned char b)
{
	unsigned char p = 0, i = 0, hbs = 0;
	for (i = 0; i < 8; i++)
	{
		if (b & 1)
		{
			p ^= a;
		}
		hbs = a & 0x80;
		a <<= 1;
		if (hbs)
		{
			a ^= 0x1b; 
		}
		b >>= 1;
	}
	return p;
}

/**
*	Mix the columns of the state matrix
*/
void mix_columns(unsigned char *state) {

	unsigned char tmp0, tmp1, tmp2;

		tmp0 = state[0];
		tmp1 = state[1];
		tmp2 = state[2];

		state[0] = galois_mult(0x02,state[0]) ^ galois_mult(0x03,state[1]) ^ galois_mult(0x01,state[2]) ^ galois_mult(0x01,state[3]);
		state[1] = galois_mult(0x01,tmp0) ^ galois_mult(0x02, state[1]) ^ galois_mult(0x03, state[2]) ^ galois_mult(0x01, state[3]);
		state[2] = galois_mult(0x01, tmp0) ^ galois_mult(0x01, tmp1) ^ galois_mult(0x02, state[2]) ^ galois_mult(0x03, state[3]);
		state[3] = galois_mult(0x03, tmp0) ^ galois_mult(0x01, tmp1) ^ galois_mult(0x01, tmp2) ^ galois_mult(0x02, state[3]);

		tmp0 = state[4];
		tmp1 = state[5];
		tmp2 = state[6];

		state[4] = galois_mult(0x02, state[4]) ^ galois_mult(0x03, state[5]) ^ galois_mult(0x01, state[6]) ^ galois_mult(0x01, state[7]);
		state[5] = galois_mult(0x01, tmp0) ^ galois_mult(0x02, state[5]) ^ galois_mult(0x03, state[6]) ^ galois_mult(0x01, state[7]);
		state[6] = galois_mult(0x01, tmp0) ^ galois_mult(0x01, tmp1) ^ galois_mult(0x02, state[6]) ^ galois_mult(0x03, state[7]);
		state[7] = galois_mult(0x03, tmp0) ^ galois_mult(0x01, tmp1) ^ galois_mult(0x01, tmp2) ^ galois_mult(0x02, state[7]);

		tmp0 = state[8];
		tmp1 = state[9];
		tmp2 = state[10];

		state[8] = galois_mult(0x02, state[8]) ^ galois_mult(0x03, state[9]) ^ galois_mult(0x01, state[10]) ^ galois_mult(0x01, state[11]);
		state[9] = galois_mult(0x01, tmp0) ^ galois_mult(0x02, state[9]) ^ galois_mult(0x03, state[10]) ^ galois_mult(0x01, state[11]);
		state[10] = galois_mult(0x01, tmp0) ^ galois_mult(0x01, tmp1) ^ galois_mult(0x02, state[10]) ^ galois_mult(0x03, state[11]);
		state[11] = galois_mult(0x03, tmp0) ^ galois_mult(0x01, tmp1) ^ galois_mult(0x01, tmp2) ^ galois_mult(0x02, state[11]);

		tmp0 = state[12];
		tmp1 = state[13];
		tmp2 = state[14];

		state[12] = galois_mult(0x02, state[12]) ^ galois_mult(0x03, state[13]) ^ galois_mult(0x01, state[14]) ^ galois_mult(0x01, state[15]);
		state[13] = galois_mult(0x01, tmp0) ^ galois_mult(0x02, state[13]) ^ galois_mult(0x03, state[14]) ^ galois_mult(0x01, state[15]);
		state[14] = galois_mult(0x01, tmp0) ^ galois_mult(0x01, tmp1) ^ galois_mult(0x02, state[14]) ^ galois_mult(0x03, state[15]);
		state[15] = galois_mult(0x03, tmp0) ^ galois_mult(0x01, tmp1) ^ galois_mult(0x01, tmp2) ^ galois_mult(0x02, state[15]);
}

/**
*	Add the round key to state by a XOR function.
*/
void add_round_key(unsigned char *input, unsigned char *roundKey, unsigned char r) {

	unsigned char c, temp;

	for (c = 0; c < NumberOfColumns; c++) {
		input[NumberOfColumns * 0 + c] = input[NumberOfColumns * 0 + c] ^ roundKey[NumberOfColumns * 0 + c + 16 * r];
		input[NumberOfColumns * 1 + c] = input[NumberOfColumns * 1 + c] ^ roundKey[NumberOfColumns * 1 + c + 16 * r];
		input[NumberOfColumns * 2 + c] = input[NumberOfColumns * 2 + c] ^ roundKey[NumberOfColumns * 2 + c + 16 * r];
		input[NumberOfColumns * 3 + c] = input[NumberOfColumns * 3 + c] ^ roundKey[NumberOfColumns * 3 + c + 16 * r];
	}
}

/**
*	Encrypt the Plain Text
*/
void cipher(unsigned char *input, unsigned char *roundKey)
{
	unsigned char r;
	// Add the First round key to the state before starting the rounds.
	add_round_key(input, roundKey, 0);

	for (r = 1; r < NumberOfRounds; r++)
	{
		sub_bytes(input);
		shift_rows(input);
		mix_columns(input);
		add_round_key(input, roundKey, r);
	}

	// The MixColumns function is not in the last round.
	sub_bytes(input);
	shift_rows(input);
	add_round_key(input, roundKey, NumberOfRounds);
}

/**
*	Copy the final state
*/
void copy(unsigned char *in, unsigned char *output)
{
	for (unsigned char i = 0; i < 16; i++)
	{
		output[i] = in[i];
	}
}

/**
*	Main function
*/
void encrypt_aes_16(unsigned char *input, unsigned char *output, unsigned char *key)
{

	// set trigger PIN
	set_pin(DDRB, 0b10100000);
	set_pin(PORTB, 0b10100000);

	//... Initialize ...

	unsigned char roundKey[1024] = {0};

	//Generate a series of Round Keys from the Cipher Key. 	
	KeyExpansion(key, roundKey);

	//Encrypt input
	cipher(input, roundKey);


	//... Copy output ...
	copy(input,output);

		// clear trigger PIN
	clear_pin(PORTB, 0b01011111);
}

