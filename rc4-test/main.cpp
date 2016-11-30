#include "stdafx.h"
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>

#include <botan/stream_cipher.h>
#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>


using namespace std;

// Function prototypes
void hex2ascii(const string& in, string& out);
unsigned char hexval(unsigned char c);

int main(void)
{
	try
	{

		std::unique_ptr<Botan::StreamCipher> cipher(Botan::StreamCipher::create("RC4"));
		std::unique_ptr<Botan::StreamCipher> cipher2(Botan::StreamCipher::create("RC4"));

		cout << endl << cipher->name() << endl;

		const std::vector<uint8_t> key = { 0x11, 0x22, 0x33, 0x44 };
		cipher->set_key(key);
		cipher2->set_key(key);

		std::vector<uint8_t> plaintext = {0xAA, 0xBB, 0xCC, 0xDD};
		
		// Perform encryption and print results
		cipher->encipher(plaintext);
		string ciphertext = Botan::hex_encode(plaintext);
		cout << "The output of RC4(0x11223344, 0xAABBCCDD) is: " << ciphertext << endl;

		// Here we use a brand new cipher object to reset the IV/bit-stream
		cipher2->encipher(plaintext);
		ciphertext = Botan::hex_encode(plaintext);
		cout << "The output of RC4(0xFACF5374, 0xAABBCCDD) is: " << ciphertext << endl;
			
		string ctHex = Botan::hex_encode(plaintext);

		cipher2->encipher(Botan::hex_decode(ciphertext));

		// Convet ctHex to ASCII
		//hex2ascii(ctHex, ciphertext);
		//cout << "Converted " << ctHex << " -> " << ciphertext << endl;
	}
	catch (std::exception& e)
	{
		std::cerr << e.what() << "\n";
	}
};

void hex2ascii(const string& in, string& out)
{
	out.clear();
	out.reserve(in.length() / 2);
	for (string::const_iterator p = in.begin(); p != in.end(); p++)
	{
		unsigned char c = hexval(*p);
		p++;
		if (p == in.end()) break; // incomplete last digit - should report error
		c = (c << 4) + hexval(*p); // + takes precedence over <<
		out.push_back(c);
	}
}

unsigned char hexval(unsigned char c)
{
	if ('0' <= c && c <= '9')
		return c - '0';
	else if ('a' <= c && c <= 'f')
		return c - 'a' + 10;
	else if ('A' <= c && c <= 'F')
		return c - 'A' + 10;
	else abort();
}

