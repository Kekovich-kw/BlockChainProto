#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

using namespace std;

namespace Utils {

	void generateKeyPair(string& privateKey, string& publicKey);

	string signData(const string& data, const string& privateKey);

	bool verifySignature(const string& data,
		const string& signatureHex,
		const string& publicKey);

	string sha256(const string& input);

	string bitToHex(const unsigned char* data, size_t lenght);

	vector<unsigned char> hexToBin(const string& hex);

	string getCurrentTimestamp();
}

#endif