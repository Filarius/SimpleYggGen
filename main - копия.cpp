/**
 *
 * IRC: irc.ilita.i2p port 6667 || 303:60d4:3d32:a2b9::3 port 16667
 * general channels: #ru and #howtoygg
 *
 * acetone (default) git: notabug.org/acetone/SimpleYggGen-CPP
 * Vort (member) git:     notabug.org/Vort/SimpleYggGen-CPP
 *
 * developers:  acetone, lialh4, orignal, R4SAS, Vort
 * developers team, 2020 (c) GPLv3
 *
 */

#include <x86intrin.h>
#include <string.h>      // memcmp
#include <sodium.h>      // библиотека libsodium
#include <iostream>      // вывод на экран
#include <string>
#include <sstream>
#include <fstream>       // файловые потоки
#include <iomanip>       // форматированный вывод строк
#include <bitset>        // побитовое чтение
#include <vector>
#include <thread>        // многопоточность
#include <mutex>         // блокирование данных при многопоточности
#include <chrono>        // для вычисления скорости
#include <ctime>
#include <regex>         // регулярные выражения
#include <string>
#include "gpu.h"

#ifdef _WIN32            // преобразование в IPv6
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include "x25519.h"
#include "sha512.h"

#define BLOCKSIZE 1024*32*16
//const int crypto_hash_sha512_BYTES = 64;

//#define SELF_CHECK // debug

////////////////////////////////////////////////// Заставка

void Intro()
{
    std::cout <<
              std::endl <<
              " +--------------------------------------------------------------------------+" << std::endl <<
              " |                      SimpleYggGen C++  3.2.1-legend                      |" << std::endl <<
              " |                         X25519 -> SHA512 -> IPv6                         |" << std::endl <<
              " |                   notabug.org/acetone/SimpleYggGen-CPP                   |" << std::endl <<
              " |                                                                          |" << std::endl <<
              " |            developers:  Vort, acetone, R4SAS, lialh4, orignal            |" << std::endl <<
              " |                              GPLv3 (c) 2020                              |" << std::endl <<
              " +--------------------------------------------------------------------------+" << std::endl <<
              std::endl;
}

////////////////////////////////////////////////// Суть вопроса

std::mutex mtx;


std::time_t sygstartedin = std::time(NULL); // для вывода времени работы

int countsize = 0;               // определяет периодичность вывода счетчика
uint64_t block_count = 0;        // количество вычисленных блоков
uint64_t totalcountfortune = 0;  // счетчик нахождений
bool newline = false;            // форматирует вывод после нахождения адреса
std::chrono::steady_clock::duration blocks_duration(0);

#include "basefiles.cpp"

void bookmark(int id) {
        std::cout << "okay " << id << std::endl;

}








int getOnes(const unsigned char HashValue[crypto_hash_sha512_BYTES])
{
    int lOnes = 0; // кол-во лидирующих единиц
    for (int i = 0; i < 32; ++i) // всего 32 байта, т.к. лидирующих единиц больше быть не может (32*8 = 256 бит, а ff = 255)
    {
        std::bitset<8> bits(HashValue[i]);
        for (int j = 7; j >= 0; --j)
        {
            if (bits[j] == 1) // обращение к i-тому элементу битсета
                ++lOnes;
            else
                return lOnes;
        }
    }
    return -421; // это никогда не случится
}



int getOnes2(const unsigned char HashValue[crypto_hash_sha512_BYTES])
{
    const int map[8] = {0x80,0x40,0x20,0x10,0x08,0x04,0x02,0x01};
    int lOnes = 0; // кол-во лидирующих единиц
    for (int i = 0; i < 32; ++i) // всего 32 байта, т.к. лидирующих единиц больше быть не может (32*8 = 256 бит, а ff = 255)
    {
        //std::bitset<8> bits(HashValue[i]);
        //for (int j = 7; j >= 0; --j)
        for (int j = 0; j < 8; ++j)
        {
            if (HashValue[i] & map[j]) // if zero then true then there is bit = 1
                ++lOnes;
            else
                return lOnes;

        }
    }
    return -421; // это никогда не случится
}



int getOnesPartial(const unsigned char HashValue[crypto_hash_sha512_BYTES], int ffbytes) {
    int lOnes = ffbytes*8; // кол-во лидирующих единиц
    for (int i = ffbytes; i < 32; ++i) // всего 32 байта, т.к. лидирующих единиц больше быть не может (32*8 = 256 бит, а ff = 255)
    {
        std::bitset<8> bits(HashValue[i]);
        for (int j = 7; j >= 0; --j)
        {
            if (bits[j] == 1) // обращение к i-тому элементу битсета
                ++lOnes;
            else
                return lOnes;
        }
    }
    return -421; // это никогда не случится
}

void getAddressBytes(unsigned char HashValue[crypto_hash_sha512_BYTES], byte arr[16]){
    int ones = getOnes2(HashValue) ;
    int start =  (ones + 1); // лидирующие единицы и первый ноль
    int bitshift = start % 8;
    start = start/8;
    for (int i = start;i<start+15;i++){
            HashValue[i] <<= bitshift;
            HashValue[i] |= (HashValue[i+1] >> (8-bitshift));
    }

    arr[0] = 0x02;
    arr[1] = ones;
    for (int i = 0; i < 14; ++i)
        arr[i + 2] = HashValue[i+start];
}

void getAddressBytes2(unsigned char HashValue[crypto_hash_sha512_BYTES], byte ipAddr[16]){
    int lErase = getOnes(HashValue) + 1; // лидирующие единицы и первый ноль
    int start = lErase / 8;
    int shift = lErase % 8;
    bool changeit = false;
    int bigbyte = 0;

    for(int j = 0; j < shift; ++j) // побитовое смещение
    {
        for(int i = start+15; i >= start; --i)
        {
            if(bigbyte == i+1) // предыдущий байт требует переноса
                changeit = true;

            if(HashValue[i] & 0x80)
                bigbyte = i;

            HashValue[i] <<= 1;

            if(changeit)
            {
                HashValue[i] |= 0x01;
                changeit = false;
            }
        }
    }
    ipAddr[0] = 0x02;
    ipAddr[1] = lErase - 1;
    for (int i = 0; i < 14; ++i)
    ipAddr[i + 2] = HashValue[i+start];
}

void getAddressBytes3(unsigned char HashValue[crypto_hash_sha512_BYTES], byte ipAddr[16]){
    // функция "портит" массив хэша, т.к. копирование массива не происходит
    int lErase = getOnes(HashValue) + 1; // лидирующие единицы и первый ноль

    bool changeit = false;
    int bigbyte = 0;

    for(int j = 0; j < lErase; ++j) // побитовое смещение
    {
        for(int i = 63; i >= 0; --i)
        {
            if(bigbyte == i+1) // предыдущий байт требует переноса
                changeit = true;

            if(HashValue[i] & 0x80)
                bigbyte = i;

            HashValue[i] <<= 1;

            if(changeit)
            {
                HashValue[i] |= 0x01;
                changeit = false;
            }
        }
    }

    ipAddr[0] = 0x02;
    ipAddr[1] = lErase - 1;
    for (int i = 0; i < 14; ++i)
        ipAddr[i + 2] = HashValue[i];
}

std::string byteToAddres(byte arr[16]) {
    char ipStrBuf[46];
    inet_ntop(AF_INET6, arr, ipStrBuf, 46);
    return std::string(ipStrBuf);
}

std::string getAddress(unsigned char HashValue[crypto_hash_sha512_BYTES])
{
    // функция "портит" массив хэша, т.к. копирование массива не происходит
    int lErase = getOnes(HashValue) + 1; // лидирующие единицы и первый ноль

    bool changeit = false;
    int bigbyte = 0;

    for(int j = 0; j < lErase; ++j) // побитовое смещение
    {
        for(int i = 63; i >= 0; --i)
        {
            if(bigbyte == i+1) // предыдущий байт требует переноса
                changeit = true;

            if(HashValue[i] & 0x80)
                bigbyte = i;

            HashValue[i] <<= 1;

            if(changeit)
            {
                HashValue[i] |= 0x01;
                changeit = false;
            }
        }
    }

    uint8_t ipAddr[16];
    ipAddr[0] = 0x02;
    ipAddr[1] = lErase - 1;
    for (int i = 0; i < 14; ++i)
        ipAddr[i + 2] = HashValue[i];

    char ipStrBuf[46];
    inet_ntop(AF_INET6, ipAddr, ipStrBuf, 46);
    return std::string(ipStrBuf);
}

void logStatistics()
{
    if (++block_count % countsize == 0)
    {
        auto timedays = (std::time(NULL) - sygstartedin) / 86400;
        auto timehours = ((std::time(NULL) - sygstartedin) - (timedays * 86400)) / 3600;
        auto timeminutes = ((std::time(NULL) - sygstartedin) - (timedays * 86400) - (timehours * 3600)) / 60;
        auto timeseconds = (std::time(NULL) - sygstartedin) - (timedays * 86400) - (timehours * 3600) - (timeminutes * 60);

        std::chrono::duration<double, std::milli> df = blocks_duration;
        blocks_duration = std::chrono::steady_clock::duration::zero();
        int khs = conf.proc * countsize * BLOCKSIZE / df.count();
        std::cout <<
                  " kH/s: [" << std::setw(7) << std::setfill('_') << khs <<
                  "] Total: [" << std::setw(19) << block_count * BLOCKSIZE <<
                  "] Found: [" << std::setw(3) << totalcountfortune <<
                  "] Time: [" << timedays << ":" << std::setw(2) << std::setfill('0') <<
                  timehours << ":" << std::setw(2) << timeminutes << ":" << std::setw(2) << timeseconds << "]" << std::endl;
        newline = true;
    }
}

std::string hexArrayToString(const uint8_t* bytes, int length)
{
    std::stringstream ss;
    for (int i = 0; i < length; i++)
        ss << std::setw(2) << std::setfill('0') << std::hex << (int)bytes[i];
    return ss.str();
}

std::string keyToString(const key25519 key)
{
    return hexArrayToString(key, KEYSIZE);
}

std::string hashToString(const uint8_t hash[crypto_hash_sha512_BYTES])
{
    return hexArrayToString(hash, crypto_hash_sha512_BYTES);
}

void logKeys(std::string address, const key25519 publicKey, const key25519 privateKey)
{
    if(newline) // добавляем пустую строку на экране между счетчиком и новым адресом
    {
        std::cout << std::endl;
        newline = false;
    }
    std::cout << " Address:    " << address << std::endl;
    std::cout << " PublicKey:  " << keyToString(publicKey) << std::endl;
    std::cout << " PrivateKey: " << keyToString(privateKey) << std::endl;
    std::cout << std::endl;

    if (conf.log) // запись в файл
    {

        std::ofstream output(conf.outputfile, std::ios::app);
        output << std::endl;
        output << "Address:              " << address << std::endl;
        output << "EncryptionPublicKey:  " << keyToString(publicKey) << std::endl;
        output << "EncryptionPrivateKey: " << keyToString(privateKey) << std::endl;
        output.close();
    }
}

void process_fortune_key(const keys_block& block, int index)
{
    if (index == -1)
        return;

    key25519 public_key;
    key25519 private_key;
    block.get_public_key(public_key, index);
    block.get_private_key(private_key, index);

    uint8_t sha512_hash[crypto_hash_sha512_BYTES];
    crypto_hash_sha512(sha512_hash, public_key);
    std::string address = getAddress(sha512_hash);

    logKeys(address, public_key, private_key);
    ++totalcountfortune;
}

template <int T>
void miner_thread()
{
    bookmark(1);
    std::cout << " 1 ";
    key25519 public_key;
    keys_block block(BLOCKSIZE);
    uint8_t sha_block[BLOCKSIZE*64];
    uint8_t key_block[BLOCKSIZE*32];
    uint8_t random_bytes[KEYSIZE];
    uint8_t sha512_hash[crypto_hash_sha512_BYTES];
    std::regex regx(conf.rgx_search, std::regex_constants::egrep);
    byte iparr[16];
    bookmark(2);
    for (;;)
    {
        auto start_time = std::chrono::steady_clock::now();

        int zeros[4] = { 0 };// test
        int fortune_key_index = -1;
        randombytes(random_bytes, KEYSIZE);
        block.calculate_public_keys(random_bytes);
        bookmark(3);

        for(int j=0;j<BLOCKSIZE;j++){
            block.get_public_key(public_key, j);
            memcpy((void *)(key_block + j * 32), public_key, 32);
        }
        bookmark(4);

        gpuKeyToSHA512(key_block,sha_block,BLOCKSIZE);
        bookmark(5);

        for (int i = 0; i < BLOCKSIZE; i++)
        {
            i = i;
            //block.get_public_key(public_key, i);
            //crypto_hash_sha512(sha512_hash, public_key);
            memcpy( sha_block,(void *)(sha_block + i * 64), 32);
            bookmark(6);


            if (T == 0) // pattern mining
            {
                if (getAddress(sha512_hash).find(
                        conf.str_search.c_str()) != std::string::npos)
                {
                    fortune_key_index = i;
                    break; // можно использовать только один ключ из блока
                }
            }
            if (T == 1) // high mining
            {
                int newones = getOnes2(sha512_hash);
                if (newones > conf.high)
                {
                    conf.high = newones;
                    fortune_key_index = i;
                }
            }
            if (T == 2) // pattern & high mining
            {
                int newones = getOnes(sha512_hash);
                if (getAddress(sha512_hash).find(
                        conf.str_search.c_str()) != std::string::npos &&
                    newones > conf.high)
                {
                    conf.high = newones;
                    fortune_key_index = i;
                    break;
                }
            }
            if (T == 3) // regexp mining
            {
                if (std::regex_search((getAddress(sha512_hash)), regx))
                {
                    fortune_key_index = i;
                    break;
                }
            }
            if (T == 4) // regexp & high mining
            {
                int newones = getOnes(sha512_hash);
                if (std::regex_search((getAddress(sha512_hash)), regx) &&
                    newones > conf.high)
                {
                    conf.high = newones;
                    fortune_key_index = i;
                    break;
                }
            }
            if (T == 5) // search short subnet
            {
                getAddressBytes(sha512_hash,iparr);


                //if ((iparr[6] == 0) && (iparr[7] == 0) && (iparr[5] == 0))
                if ((iparr[4] == 0) && (iparr[5] == 0) && (iparr[6] == 0) && (iparr[7] == 0))
                {
                    //if ((iparr[5] == 0) && (iparr[4] == 0)) {
                    //if (((*(uint32_t*)(iparr + 6))==0)) {  //slower
                    //if (memcmp(iparr + 4, zeros, 4) == 0) {	//same speed

                   fortune_key_index = i;
                }
            }
            /*
            if (T == 6) // any shortis
            {
                getAddressArray(sha512_hash, iparr);
                for (int i = 2; i < 16; i += 2) {
                    if ((iparr[i] == 0) && (iparr[i + 1] == 0)) {
                        fortune_key_index = i;
                    }
                }
            }
            */
        }
        auto stop_time = std::chrono::steady_clock::now();
        mtx.lock();
        blocks_duration += stop_time - start_time;
        process_fortune_key(block, fortune_key_index);
        logStatistics();
        mtx.unlock();
    }
}

#ifdef SELF_CHECK // debug
void selfCheck()
{
	std::cout << "Self-check started." << std::endl;

	for (int i = 0; i < 16; i++)
	{
		int block_size = 1 << i;

		keys_block block(block_size);
		uint8_t random_bytes[KEYSIZE];
		randombytes(random_bytes, KEYSIZE);
		block.calculate_public_keys(random_bytes);

		key25519 public_key1;
		key25519 public_key2;
		key25519 private_key;
		uint8_t sha512_hash1[crypto_hash_sha512_BYTES];
		uint8_t sha512_hash2[crypto_hash_sha512_BYTES];
		for (int j = 0; j < block_size; j++)
		{
			block.get_public_key(public_key1, j);
			block.get_private_key(private_key, j);
			crypto_scalarmult_curve25519_base(public_key2, private_key);
			crypto_hash_sha512(sha512_hash1, public_key2);
			crypto_hash_sha512(sha512_hash2, public_key2, KEYSIZE);
			if (memcmp(public_key1, public_key2, KEYSIZE) != 0 ||
				memcmp(sha512_hash1, sha512_hash2, crypto_hash_sha512_BYTES))
			{
				std::cout << "!!! Self-check failed !!!" << std::endl;
				std::cout << " PrivateKey:  " << keyToString(private_key) << std::endl;
				std::cout << " PublicKey1:  " << keyToString(public_key1) << std::endl;
				std::cout << " PublicKey2:  " << keyToString(public_key2) << std::endl;
				std::cout << " SHA512Hash1: " << hashToString(sha512_hash1) << std::endl;
				std::cout << " SHA512Hash2: " << hashToString(sha512_hash2) << std::endl;
				std::cout << "!!! Self-check failed !!!" << std::endl;
				return;
			}
			else
			{
				//std::cout << "    Self-check ok" << std::endl;
				//std::cout << " PrivateKey: " << keyToString(private_key) << std::endl;
			}
		}
	}
	std::cout << "Self-check finished." << std::endl;
}
#endif // debug

// ------------------------------------------------------

int main()
{
    bookmark(10);
    gpuPrintInfo();
    bookmark(11);
    /*
    int size = 4;
    uint8_t bigkey[32*size];
    for(int j = 0;j<size;j++) {
        uint8_t key1[32];
        uint8_t key2[32];
        uint8_t sha1[64];
        uint8_t sha2[64];
        for (int i = 0; i < 32; i++) {
            bigkey[i+j*32] = j;
            key2[i] = j;
            sha1[i] = 1;
            sha2[i] = 1;
        }
        gpuKeyToSHA512(bigkey+j*32, sha1,1);
        crypto_hash_sha512(sha2, key2);
        for (int i = 0; i < 64; i++) {
            //if (sha1[i]!=sha2[i])
            {
                std::cerr << int(sha1[i]) << "  " << int(sha2[i]) << std::endl;
            }
        }
        std::cerr << "===="<< std::endl;
    }
    return 0;
     */


#ifdef SELF_CHECK
    selfCheck();
	return 0;
#endif

    int configcheck = config(); // функция получения конфигурации
    if(configcheck < 0)
    {
        std::cerr << " Error code: " << configcheck;
        std::this_thread::sleep_for(std::chrono::seconds(15));
        return configcheck;
    }
    bookmark(12);

    DisplayConfig();
    testoutput();
    bookmark(13);

    std::thread* lastThread;
    for (int i = 0; i < conf.proc; i++)
    {
        bookmark(14 + 10*i);
        lastThread = new std::thread(miner_thread<1>);
        /*
        lastThread = new std::thread(
                conf.mode == 0 ? miner_thread<0> :
                conf.mode == 1 ? miner_thread<1> :
                conf.mode == 2 ? miner_thread<2> :
                conf.mode == 3 ? miner_thread<3> :
                conf.mode == 5 ? miner_thread<5> :
                miner_thread<4>
        );
         */
    }
    bookmark(15);
    lastThread->join();

    std::cerr << "SYG has stopped working unexpectedly! Please, report about this.";
    std::this_thread::sleep_for(std::chrono::seconds(15));
    return -420;
}
