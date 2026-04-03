#include <iostream>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <ctime>
#include <vector>
#include <conio.h>
#include <Windows.h>
#include <map>
#include <chrono>

using namespace std;

string getCurrentDate() {
    time_t now = time(0);

    tm ltm;
    localtime_s(&ltm, &now);

    stringstream ss;
    ss << 1900 + ltm.tm_year << "-"
        << setw(2) << setfill('0') << 1 + ltm.tm_mon << "-"
        << setw(2) << setfill('0') << ltm.tm_mday << " "
        << setw(2) << setfill('0') << ltm.tm_hour << ":"
        << setw(2) << setfill('0') << ltm.tm_min << ":"
        << setw(2) << setfill('0') << ltm.tm_sec;

    return ss.str();
}

struct PairKeys {
    EVP_PKEY* pkey = nullptr;

    string generatePrivateKey() {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) {
            cerr << "Error creating EVP_PKEY_CTX" << endl;
            exit(1);
        }

        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            cerr << "Error initializing key generation" << endl;
            exit(1);
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
            cerr << "Error setting RSA key size" << endl;
            exit(1);
        }

        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            cerr << "Error generating RSA key pair" << endl;
            exit(1);
        }

        EVP_PKEY_CTX_free(ctx);

        BIO* bio = BIO_new(BIO_s_mem());
        if (!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL)) {
            cerr << "Error writing private key" << endl;
            exit(1);
        }

        char* privateKey;
        long privateKeyLength = BIO_get_mem_data(bio, &privateKey);

        string result(privateKey, privateKeyLength);
        BIO_free_all(bio);
        return result;
    }

    string generatePublicKey(const string& privateKey) {
        BIO* bio = BIO_new_mem_buf(privateKey.data(), privateKey.size());
        EVP_PKEY* privateKeyPkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        if (privateKeyPkey == nullptr) {
            cerr << "Error reading private key" << endl;
            exit(1);
        }

        BIO* pubBio = BIO_new(BIO_s_mem());
        if (!PEM_write_bio_PUBKEY(pubBio, privateKeyPkey)) {
            cerr << "Error writing public key" << endl;
            exit(1);
        }

        char* publicKey;
        long publicKeyLength = BIO_get_mem_data(pubBio, &publicKey);

        string result(publicKey, publicKeyLength);
        BIO_free_all(pubBio);
        EVP_PKEY_free(privateKeyPkey);
        return result;
    }


    ~PairKeys() {
        EVP_PKEY_free(pkey);
    }
};

struct Block {
    long int id;
    long int nonce;
    string data;
    string signature;
    string prev;
    string hash;
    string date;

    Block(long int id, long int nonce, string data, string signature, string prev, string date = "", string hash = "")
        : id(id), nonce(nonce), data(data), signature(signature), prev(prev), date(date), hash(hash) {
        if (hash.empty()) {
            this->hash = calculateHash();
        }
    }

    string calculateHash() {
        stringstream ss;
        ss << id << nonce << data << prev << date;
        return sha256(ss.str());
    }

    string sha256(const string& input) {
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int length = 0;

        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (mdctx == nullptr) {
            cerr << "Error creating context" << endl;
            exit(1);
        }

        if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
            cerr << "Error initialize Digest" << endl;
            exit(1);
        }

        if (EVP_DigestUpdate(mdctx, input.c_str(), input.size()) != 1) {
            cerr << "Error updating Digest" << endl;
            exit(1);
        }

        if (EVP_DigestFinal_ex(mdctx, hash, &length) != 1) {
            cerr << "Error finalizing Digest" << endl;
            exit(1);
        }

        EVP_MD_CTX_free(mdctx);

        stringstream hexStream;
        for (unsigned int i = 0; i < length; ++i) {
            hexStream << hex << setw(2) << setfill('0') << (int)hash[i];
        }

        return hexStream.str();
    }

    void mineBlock() {
        cout << "Starting mining..." << endl;
        while (true) {
            hash = calculateHash();
            if (this->id == 0) {
                if (hash.substr(0, 4) == "0000") {
                    cout << "Genesis block mined: " << hash << endl;
                    break;
                }
            }
            if (hash.substr(0, 4) == "0000") {
                cout << "Block " << this->id << " mined: " << hash << endl;
                break;
            }
            /*           system("cls");
                       cout << "Trying nonce: " << nonce << " - Hash: " << hash << endl;
                       Sleep(10);*/
            nonce++;
        }
    }
};

struct Asset {
    string type;
    double amount;

    Asset(string type, double amount) : type(type), amount(amount) {}

    void showAssetInfo() const {
        cout << type << " : " << amount << endl;
    }

};

struct User {
    string name;
    double balance;
    string privateKey;
    string publicKey;
    vector<Asset> wallet;

    User(const string& name, long int balance) : name(name), balance(balance) {
        generateKeys();
    }

    string getPublicKey() {
        return publicKey;
    }

    void generateKeys() {
        PairKeys pairKeys;
        privateKey = pairKeys.generatePrivateKey();
        publicKey = pairKeys.generatePublicKey(privateKey);
    }

    void addAsset(const string& type, double amount) {
        wallet.push_back(Asset(type, amount));
    }

    void showUserInfo(bool showKeys) {
        cout << "\tUser: " << name << endl;
        cout << "\tBalance: " << balance << "$" << endl;
        cout << "Wallet:" << endl;
        if (wallet.empty()) {
            cout << "Have no asset!" << endl;
        }
        for (const auto& asset : wallet) {
            asset.showAssetInfo();
            cout << "-----------" << endl;
        }
        if (showKeys) {
            cout << "\n\t~PrivateKey\n\n" << privateKey;
            cout << "\n\t~PublicKey~\n\n" << publicKey;
        }
    }

};

struct BlockChain {
    vector<Block> chain;
    int difficulty;

    BlockChain() {
        Block genesisBlock(0, 0, "Genesis Block", "key", "0000000000000000000000000000000000000000000000000000000000000000", getCurrentDate(), "");
        genesisBlock.mineBlock();
        chain.push_back(genesisBlock);
        difficulty = 4;
    }

    void addBlock(Block newBlock) {
        newBlock.prev = chain.back().hash;
        newBlock.mineBlock();
        chain.push_back(newBlock);
    }

    void showBlockChain() {
        system("cls");
        cout << "\tBlock Chain\n\n";
        for (const Block& block : chain) {
            cout << "------------------------" << endl;
            cout << "Block ID: " << block.id << endl;
            cout << "Nonce: " << block.nonce << endl;
            cout << "Hash: " << block.hash << endl;
            cout << "Previous hash: " << block.prev << endl;
            cout << "Data: " << block.data << endl;
            cout << "Created at: " << block.date << endl;
            cout << "------------------------" << endl;
        }
    }

};

int main() {

    PairKeys pairKeys;
    string pKey = pairKeys.generatePrivateKey();

    BlockChain blockChain;

    //User user1("Arcom", 1000.0);

    //user1.showUserInfo(false);

    Block block1(1, 0, "First block", pKey, blockChain.chain.back().hash, getCurrentDate());
    blockChain.addBlock(block1);

    //Block block2(2, 0, "Second block", pKey, blockChain.chain.back().hash, getCurrentDate());
    //blockChain.addBlock(block2);

    //Block block3(3, 0, "Third block", pKey, blockChain.chain.back().hash, getCurrentDate());
    //blockChain.addBlock(block3);

    //Block block4(4, 0, "Fours block", pKey, blockChain.chain.back().hash, getCurrentDate());
    //blockChain.addBlock(block4);

    blockChain.showBlockChain();


    return 0;
}