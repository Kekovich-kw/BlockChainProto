#include "Utils.hpp"
#include <sstream>
#include <iomanip>
#include <stdexcept>

using namespace std;

namespace Utils {

	// --- Генерация публичного и приватного ключей ---


	void generateKeyPair(string& privateKey, string& publicKey) {
		EVP_PKEY* pkey = EVP_EC_gen("secp256k1");
		if (!pkey) {

		}
	}

}