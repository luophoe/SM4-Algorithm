/*
 * AES_main.c
 *
 * Created on: 02/04/2021
 *     Author: Anyka
 *      	   Phoebe Luo
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*------------------------------------------------------------------------------------------------
--------------------------------------- Function Declaration -------------------------------------
--------------------------------------------------------------------------------------------------*/
int main();

void SM4(unsigned int text[4], unsigned int key[4]);
void KeyExpansion(unsigned int key[4], unsigned int roundkey_complete[4][8]);
unsigned int GetRoundKey(unsigned int roundkey_complete[4][8], int choice, int round);
void Round(unsigned int roundkey, unsigned int text[4], int round);
void ReverseTrans(unsigned int text[4]);
unsigned int SBox(unsigned int hex);
unsigned int ShiftLeft(unsigned int hex, int digit);

void GetArray(unsigned int text[4], int choice);
void OnetoFour( unsigned int hex, unsigned int hex_separate[4]);
unsigned int FourtoOne(unsigned int hex_separate[4]);

/*------------------------------------------------------------------------------------------------
--------------------------------------- Function Definition --------------------------------------
--------------------------------------------------------------------------------------------------*/

int main(){
	// initialize arrays
	unsigned int text[4] = {0}; //initialize array to hold text
	unsigned int key[4] = { 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210 }; //initialize array to hold key

	SM4(text, key);

	return 0;
}

/*--------------------------------------------------------------------------------------
---------------------------------- Algorithm Functions ---------------------------------
----------------------------------------------------------------------------------------*/

/* SM4 Function Calling Subfunctions */
void SM4(unsigned int text[4], unsigned int key[4]){
	// get user input to identify operation
	int choice = 0;
	int count;
	printf("Choose designated function:\n1. Encryption\n2. Decryption\n");
	fflush(stdout);
	scanf("%d", &choice);

	GetArray(text, choice); // get user input for text

	// print input text
	if(choice == 1){
		printf("Plaintext: \n");
	}else if(choice == 2){
		printf("Ciphertext: \n");
	}
	for(count = 0; count < 4; count++){
		printf("0x%08x ", text[count]);
	}
	printf("\n\n");

	// roundkey 1-32 stored in column 0 to 31
	unsigned int roundkey_complete[4][8] = {0}; // roundkey_complete matrix to hold roundkey 0-31
	KeyExpansion(key, roundkey_complete); // fill in roundkey_complete matrix

	// start round function
	int round;
	unsigned int roundkey; // roundkey of each round
	for(round = 1; round <= 32; round++){
		roundkey = GetRoundKey(roundkey_complete, choice, round); // get roundkey for current round
		Round(roundkey, text, round); // round function to manipulate text[4]
	}

	// final operation of reverse transformation
	ReverseTrans(text);

	// print output text
	if(choice == 1){
		printf("Ciphertext: \n");
	}else if(choice == 2){
		printf("Plaintext: \n");
	}
	for(count = 0; count < 4; count++){
		printf("0x%08x ", text[count]);
	}
	printf("\n");
}

/* Key Expansion to Get Key of Each Round */
void KeyExpansion(unsigned int key[4], unsigned int roundkey_complete[4][8]){
	const int FK[4] =
   {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

	const int CK[32] =
   {0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279 };

	// 1. update key to K0, K1, K2, K3 by key XOR FK
	int count;
	int column, row;
	for(count = 0; count < 4; count++){
		key[count] = key[count] ^ FK[count];
	}

	// 2. Ki+4 = Ki XOR T'(Ki+1 XOR Ki+2 XOR Ki+3 XOR CKi)
	unsigned int roundkey_temp[4][9] = {0}; // roundkey_temp that can include K0, K1, K2, K3 for operation
	unsigned int newroundkey; // the variable that gets passed in and out of function T'
	unsigned int newroundkey1, newroundkey2; // newroundkey1 is newroundkey shifted left 13 bits, newroundkey2 is newroundkey shifted left 23 bits
	int Kcolumn[4] = {0}; // column of Ki, Ki+1, Ki+2, Ki+3 in roundkey_temp
	int Krow[4] = {0}; // row of Ki, Ki+1, Ki+2, Ki+3 in roundkey_temp
	int position = 4; // keep track of the current number in the matrix

	for(count = 0; count < 4; count++){
		roundkey_temp[count][0] = key[count];
	}// initialize column 0 with K0, K1, K2, K3

	for(column = 1; column < 9; column++){
		for(row = 0; row < 4; row++){
			// calculate the column and row of Ki, Ki+1, Ki+2, Ki+3 using position
			for(count = 0; count < 4; count++){
				Kcolumn[count] = (position - 4 + count)/4;
				Krow[count] = (position - 4 + count) % 4;
			}
			// Ki+1 XOR Ki+2 XOR Ki+3 XOR CKi
			newroundkey = roundkey_temp[Krow[1]][Kcolumn[1]] ^ roundkey_temp[Krow[2]][Kcolumn[2]] ^ roundkey_temp[Krow[3]][Kcolumn[3]] ^ CK[position - 4];
			// SBox operation
			newroundkey = SBox(newroundkey);
			// shift left operation Ki+4 = Ki+4 XOR (Ki+4 << 13) XOR (Ki+4 << 23)
			newroundkey1 = ShiftLeft(newroundkey, 13);
			newroundkey2 = ShiftLeft(newroundkey, 23);
			newroundkey = newroundkey ^ newroundkey1 ^ newroundkey2;
			// Ki+4 = Ki XOR T'(Ki+1 XOR Ki+2 XOR Ki+3 XOR CKi)
			roundkey_temp[row][column] = roundkey_temp[Krow[0]][Kcolumn[0]] ^ newroundkey;
			position++;
		}
	}

	// 3. copy roundkey_temp column 1 to 9 to rounkey_complete column 0 to 8
	for(column = 1; column < 9; column++){
		for(row = 0; row < 4; row++){
			roundkey_complete[row][column - 1] = roundkey_temp[row][column];
		}
	}

	printf("roundkey: \n");
	for(row = 0; row < 4; row++){
		for(column = 0; column < 8; column++){
			printf("0x%08x ", roundkey_complete[row][column]);
		}
		printf("\n");
	}
	printf("\n");
}

/* Get Roundkey of Current Round */
unsigned int GetRoundKey(unsigned int roundkey_complete[4][8], int choice, int round){
	int row, column;
	unsigned int roundkey;
	if(choice == 1){ // encryption, get roundkey from top left to bottom right
		column = (round - 1)/4;
		row = (round - 1)%4;
		roundkey = roundkey_complete[row][column];
	}else if (choice == 2){ // encryption, get roundkey from bottom right to top left
		column = 7 - (round - 1)/4;
		row = 3 - (round - 1)%4;
		roundkey = roundkey_complete[row][column];
	}
	return roundkey;
}

/* Round Function */
void Round(unsigned int roundkey, unsigned int text[4], int round){
	// Xi+4 = Xi XOR T(Xi+1 XOR Xi+2 XOR Xi+3 XOR roundkey)
	// update Xi+4 into text[4] by keeping track of the position of i
	printf("Roundkey %d:\n0x%08x", round, roundkey);
	printf("\n\n");
	int i = 0;
	unsigned int newX = 0; // keep updating until variable Xi+4
	if(round%4 == 1){
		i = 0; // i will be at position 0 when round is 1, 5, 9, 13, etc.
	}else if(round%4 == 2){
		i = 1; // i will be at position 1 when round is 2, 6, 10, 14, etc.
	}else if(round%4 == 3){
		i = 2; // i will be at position 2 when round is 3, 7, 11, 15, etc.
	}else if(round%4 == 0){
		i = 3; // i will be at position 3 when round is 4, 8, 12, 16, etc.
	}

	// 1. Xi+1 XOR Xi+2 XOR Xi+3 XOR roundkey
	int count;
	for(count = 0; count < 4; count++){ // go through the array to XOR all the elements besides the Xi
		if(count != i){
			newX = newX ^ text[count];
		}
	}
	newX = newX ^ roundkey; // XOR roundkey

	// 2. SBox operation
	newX = SBox(newX);

	// 3. shift left operation Xi+4 = Xi+4 XOR (Xi+4 << 2) XOR (Xi+4 << 10) XOR (Xi+4 << 18) XOR (Xi+4 << 24)
	unsigned int newX1, newX2, newX3, newX4;
	// newX1 is newX shifted left 2 bits, newX2 is newX shifted left 10 bits, newX3 is newX shifted left 18 bits, newX4 is newX shifted left 24 bits
	newX1 = ShiftLeft(newX, 2);
	newX2 = ShiftLeft(newX, 10);
	newX3 = ShiftLeft(newX, 18);
	newX4 = ShiftLeft(newX, 24);
	newX = newX ^ newX1 ^ newX2 ^ newX3 ^ newX4;

	// 4. Xi+4 = Xi XOR T(Xi+1 XOR Xi+2 XOR Xi+3 XOR roundkey)
	newX = text[i] ^ newX;
	text[i] = newX;

	printf("Roundtext %d:\n0x%08x", round, newX);
	printf("\n\n");
}

/* Reverse Transformation of text[4] */
void ReverseTrans(unsigned int text[4]){
	// X32, X33, X34, X35 -> X35, X34, X33, X32
	int temp;
	temp = text[0]; // X32
	text[0] = text[3]; // put X35 into X32
	text[3] = temp; // put X32 into X35
	temp = text[1]; // X33
	text[1] = text[2]; // put X34 into X33
	text[2] = temp; // put X33 into X34
}

/* SBox for Substitution */
unsigned int SBox(unsigned int hex){
	unsigned int hex_new = 0; // new hex value to be returned

	const int SBoxTable[16][16] =
	{
	/*        0    1    2    3    4    5    6    7    8    9    a    b    c    d    e    f */
	/* 0 */ {0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05},
	/* 1 */ {0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99},
	/* 2 */ {0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62},
	/* 3 */ {0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6},
	/* 4 */ {0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8},
	/* 5 */ {0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35},
	/* 6 */ {0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87},
	/* 7 */ {0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e},
	/* 8 */ {0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1},
	/* 9 */ {0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3},
	/* a */ {0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f},
	/* b */ {0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51},
	/* c */ {0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8},
	/* d */ {0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0},
	/* e */ {0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84},
	/* f */ {0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48}
	};

	// separate hex into 2 digit values
	unsigned int hex_separate[4];
	OnetoFour(hex, hex_separate);

	// extract new values form SBox
	int column, row;
	int count;
	for(count = 0; count < 4; count++){
		row = hex_separate[count]/16;
		column = hex_separate[count] - row*16;
		hex_separate[count] = SBoxTable[row][column];
	}

	// get final value
	hex_new = FourtoOne(hex_separate);

	return hex_new;
}

/* Rotational Shift Left */
unsigned int ShiftLeft(unsigned int hex, int digit){
	// rotate bits to shift left according to the required digit
	unsigned int new_hex;

	unsigned int temp_hex = 0;
	if(digit == 2){
		// get the leftmost 2 bits for temp_hex
		temp_hex = hex & 0xc0000000; // hex AND 11000000000000000000000000000000
		temp_hex = temp_hex >> 30; // right shift temp_hex 30 bits to get 2 bits
		// left shift hex
		hex = hex << 2;
	}
	if(digit == 10){
		// get the leftmost 10 bits for temp_hex
		temp_hex = hex & 0xffc00000; // hex AND 11111111110000000000000000000000
		temp_hex = temp_hex >> 22; // right shift temp_hex 22 bits to get 10 bits
		// left shift hex
		hex = hex << 10;
	}
	if(digit == 13){
		// get the leftmost 13 bits for temp_hex
		temp_hex = hex & 0xfff80000; // hex AND 11111111111110000000000000000000
		temp_hex = temp_hex >> 19; // right shift temp_hex for 19 bits to get 13 bits
		// left shift hex
		hex = hex << 13;
	}
	if(digit == 18){
		// get the leftmost 18 bits for temp_hex
		temp_hex = hex & 0xffffc000; // hex AND 11111111111111111100000000000000
		temp_hex = temp_hex >> 14; // right shift temp_hex for 14 bits to get 18 bits
		// left shift hex
		hex = hex << 18;
	}
	if(digit == 23){
		// get the leftmost 23 bits for temp_hex
		temp_hex = hex & 0xfffffe00; // hex AND 11111111111111111111111000000000
		temp_hex = temp_hex >> 9; // right shift temp_hex for 9 bits to get 23 bits
		// left shift hex
		hex = hex << 23;
	}
	if(digit == 24){
		// get the leftmost 24 bits for temp_hex
		temp_hex = hex & 0xffffff00; // hex AND 11111111111111111111111100000000
		temp_hex = temp_hex >> 8; // right shift temp_hex for 8 bits to get 24 bits
		// left shift hex
		hex = hex << 24;
	}
	// put back the leftmost 10 bits to the right
	hex = hex | temp_hex;
	new_hex = hex;
	return new_hex;
}

/*--------------------------------------------------------------------------------------
---------------------------------- Operational Functions --------------------------------
----------------------------------------------------------------------------------------*/

/* Get Array from User Input */
void GetArray(unsigned int text[4], int choice){
	// get user input for plaintext OR ciphertext
	unsigned int temptext[16] = {0};
	if (choice == 1){
		printf("Input plaintext:\n");
	}else if (choice == 2){
		printf("Input ciphertext:\n");
	}

	//putting plaintext OR ciphertext into text array
	int count;
	for(count = 0; count < 16; count++){
		fflush(stdout);
		scanf("%x", temptext+count);
	}

	for(count = 0; count < 4; count++){
		text[count] = temptext[count*4]*16777216 + temptext[count*4 + 1]*65536 + temptext[count*4 + 2]*256 + temptext[count*4 + 3]; // convert to 8 digit numbers
		// first 2 digits times 16^6, second 2 digits times 16^4, third 2 digits times 16^2, last 2 digits remain original value.
	}
}

/* Transform one 8-digit hex number to four 2-digit hex number */
void OnetoFour(unsigned int hex, unsigned int hex_separate[4]){
	hex_separate[0] = hex/16777216;
	hex_separate[1] = (hex - hex_separate[0]*16777216)/65536;
	hex_separate[2] = (hex - hex_separate[0]*16777216 - hex_separate[1]*65536)/256;
	hex_separate[3] = hex - hex_separate[0]*16777216 - hex_separate[1]*65536 - hex_separate[2]*256;
}

/* Transform 2-digit hex number to four one 8-digit hex number */
unsigned int FourtoOne(unsigned int hex_separate[4]){
	unsigned int hex;
	hex = hex_separate[0]*16777216 + hex_separate[1]*65536 + hex_separate[2]*256 + hex_separate[3];
	return hex;
}
