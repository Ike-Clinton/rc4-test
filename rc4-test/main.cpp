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
		//Init cipher
		std::string plaintext("hello");
		std::vector<uint8_t> pt(plaintext.data(), plaintext.data() + plaintext.length());
		const std::vector<uint8_t> key = Botan::hex_decode("736563726574");
		std::unique_ptr<Botan::StreamCipher> cipher(Botan::StreamCipher::create("RC4"));

		//set key and show algorithm used
		cipher->set_key(key);
		std::cout << std::endl << cipher->name() << std::endl;
		// Perform encryption and print results
		cipher->encipher(pt);
		std::cout << Botan::hex_encode(pt) << endl;

		cout << "\n";

		std::unique_ptr<Botan::StreamCipher> cipher2(Botan::StreamCipher::create("RC4"));
		cipher2->set_key(key);
		std::cout << std::endl << cipher2->name() << std::endl;

		string ctHex = Botan::hex_encode(pt);
		string ciphertext = "";

		// Convet ctHex to ASCII
		hex2ascii(ctHex, ciphertext);
		cout << "Converted " << ctHex << " -> " << ciphertext << endl;

		std::vector<uint8_t> ct(ciphertext.data(), ciphertext.data() + ciphertext.length());
		cipher->encipher(ct);
		std::cout << Botan::hex_encode(ct) << endl;


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

