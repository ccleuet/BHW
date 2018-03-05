/*
	Simple Operating System for Smartcard Education
	Copyright (C) 2002  Matthias Bruestle <m@mbsks.franken.de>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
	This Project has been modified by Filip Stepanek <filip.stepanek@fit.cvut.cz>,
	FIT-CTU <www.fit.cvut.cz/en> for the purpose of smartcard education 
	using the SOSSE <http://www.mbsks.franken.de/sosse/html/index.html> 
	created by Matthias Bruestle and files 	from the Chair for Embedded Security (EMSEC), 
	Ruhr-University Bochum <http://www.emsec.rub.de/chair/home/>.

	This Project has been modified by Vojtech Myslivec <vojtech.myslivec@fit.cvut.cz>
	and Zdenek Novy <novyzde3@fit.cvut.cz>,	FIT-CTU <www.fit.cvut.cz/en> 
	Due to fixing buffer overflow error and LC/LE mismatch error.
	For further info see comments with tags #buffer_overflow #LC_LE #return_types #parameters_check
	
*/

/** 
 *	@file	main.c
 *
 *	@brief 	main() function with command loop.
 *
 *	This file contains the main command loop that receives and sends back 
 *	appropriate APDUs.
 *
 *	Supported instructions: @a (ins byte)
 *	-	0x40	encryption using the ASM example
 *	-	0x42	decryption using the ASM example
 *	-	0x50	encryption using the C example
 *	-	0x52	decryption using the C example
 *	-	0x60	encryption using the AES
 *
 *	Supported return codes:	@a (SW1 & SW2)
 *	-	0x9000	command executed successfuly
 *	-	0x6a87	LRC error
 *	-	0x6700	unexpected length of the command or of the expected response
 *	-	0x6e00	class of the command not supported
 *	-	0x6d00	instruction of the command not supported
 *	-	0x6610	Command APDU is longer then buffer size (LC).
 *              If you need more data to be sent, check constant INPUT_DATA_SIZE
 *	-	0x6620	Response is longer then buffer size (LE).
 *              If you need more data to be sent, check constant INPUT_DATA_SIZE
 *  -   ... see types.h for more
 */

#include "commands.h"
#include "types.h"
#include "t1.h"

/**
 * 	struct for command APDU 
 */
str_command_APDU command_APDU;        	
/** 
 *	pointer to a command APDU 
 */
str_command_APDU *p_command_APDU;     	
/** 
 *	struct for response APDU 
 */
str_response_APDU response_APDU;       	
/** 
 *	pointer to a command APDU 
 */
str_response_APDU *p_response_APDU;


/** 
 *	@brief	Main function containing command interpreter loop.
 *
 *	The function uses 2 data-structures for the Command and Response APDU.
 *	All operations done with APDU uses allocated pointers to parse
 *	the input data, execute the command and send back the response APDU.
 *
 *	- Command and response APDUs are initialized/reset,
 *	- ATR is sent (answer-to-reset),
 *	- loop:
 *		- receive C-APDU,
 *		- execute the command,
 *		- send back R-APDU,
 *	- goto loop.
 *
 *	This function never returns.
 */ 

int main( void )
{
    static unsigned char key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
	encrypt_aes_16("test", "", key);
	return 0;
}

