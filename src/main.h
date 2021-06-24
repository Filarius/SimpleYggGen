#ifndef MAIN_H
#define MAIN_H

//#include "ed/ed25519.h"
#include <sodium.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <thread>
#include <regex>
#include <mutex>
#ifdef _WIN32            // преобразование в IPv6
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
#endif

#include "parametes.h"
#include "cppcodec/base32_rfc4648.hpp"

const size_t KEYSIZE = 32;
const size_t ADDRIPV6 = 16;
typedef std::array<uint8_t, KEYSIZE> Key;
typedef std::array<uint8_t, ADDRIPV6> Address;

struct KeysBox
{
        Key PublicKey;
        Key PrivateKey;
};

//void randombytes(uint8_t * const buf, const unsigned long long buf_len);
    
//void ed25519_publickey(const ed25519_secret_key sk, ed25519_public_key pk);    
//void ed25519_publickey(const ed25519_secret_key sk, ed25519_public_key pk);    

void displayConfig();
void testOutput();
void logStatistics();
void logKeys(uint8_t * raw, const Key publicKey, const Key privateKey);
std::string getBase32(const Address& rawAddr);
std::string pickupStringForMeshname(std::string str);
std::string pickupMeshnameForOutput(std::string str);
std::string decodeMeshToIP(const std::string str);
bool subnetCheck();
bool convertStrToRaw(const std::string str, Address& array);
KeysBox getKeyPair();
void getRawAddress(int lErase, Key InvertedPublicKey, Address& rawAddr);
Key bitwiseInverse(const Key key);
int getOnes(const Key value);


std::string getAddress(const Address& rawAddr);
std::string hexArrayToString(const uint8_t* bytes, int length);
std::string keyToString(const Key key);
void process_fortune_key(const KeysBox& block);
void startThreads();
template <int T>
void miner_thread();
void error(int code);
void help();
void without();

#endif // MAIN_H
