#ifndef BFKEYEXP_H
#define BFKEYEXP_H

#include <sstream>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include <iostream>
#include <string>
#include "carray.h"
#include "ecc.h"
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/random_number_generator.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/random/random_device.hpp>
#include <boost/random.hpp>
#include <iomanip>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

using namespace std;
using namespace CryptoPP;

bool log_print = false;
// Function to generate 128-bit random number as 32-digit hexadecimal string
std::string generateRandomHex128() {
    // Seed the random number generator with a non-deterministic seed
    boost::random::random_device rd;
    boost::random::mt19937_64 rng(rd());

    // Generate a 128-bit random number 'ck'
    boost::multiprecision::cpp_int ck = rng();
    // Convert 'ck' to a 32-digit hexadecimal string
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(32) << std::hex << ck;
    std::string ckHex = ss.str();
    return ckHex;
}

std::string AES_ecb_encrypt(const std::string& k, const std::string& x) {
    CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    CryptoPP::StringSource(k, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::ArraySink(key, sizeof(key))
        )
    );

    // Convert x to boost::multiprecision::cpp_int with 128-bit precision to handle 128-bit integers
    boost::multiprecision::cpp_int x_int;
    std::stringstream ss;
    ss << std::hex << x;
    ss >> x_int;

    // Pad x_int with leading zeros to ensure it is 32 bytes long
    std::stringstream x_stream;
    x_stream << std::setw(32) << std::setfill('0') << std::hex << x_int;
    std::string xpi_str = x_stream.str();

    CryptoPP::byte xpi[CryptoPP::AES::BLOCKSIZE];
    for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; ++i) {
        std::stringstream byte_stream;
        byte_stream << std::hex << xpi_str.substr(i * 2, 2);
        int byte_value;
        byte_stream >> byte_value;
        xpi[i] = static_cast<CryptoPP::byte>(byte_value);
    }

    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;
    e.SetKey(key, sizeof(key));

    CryptoPP::byte aes_xpi[CryptoPP::AES::BLOCKSIZE];
    e.ProcessData(aes_xpi, xpi, sizeof(xpi));

    boost::multiprecision::cpp_int aes_xpi_int = 0;
    for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; ++i) {
        aes_xpi_int |= static_cast<boost::multiprecision::cpp_int>(aes_xpi[i]) << (8 * (CryptoPP::AES::BLOCKSIZE - 1 - i));
    }

    boost::multiprecision::cpp_int blki_int = aes_xpi_int;
    std::stringstream blki_stream;
    blki_stream << std::setw(32) << std::setfill('0') << std::hex << blki_int;
    std::string blki_str = blki_stream.str();
    return blki_str;
}

//boost::multiprecision::cpp_int hexStringToCppInt(const std::string& hexString) {
//    boost::multiprecision::cpp_int result;
//    std::stringstream ss;
//    ss << std::hex << hexString;
//    ss >> result;
//    return result;
//}

//boost::multiprecision::cpp_int radix_256 = boost::multiprecision::pow(boost::multiprecision::cpp_int(2), 256);
//boost::multiprecision::cpp_int radix_128 = boost::multiprecision::pow(boost::multiprecision::cpp_int(2), 128);
//boost::multiprecision::cpp_int radix_32 =  boost::multiprecision::pow(boost::multiprecision::cpp_int(2), 32);
//boost::multiprecision::cpp_int radix_16 =  boost::multiprecision::pow(boost::multiprecision::cpp_int(2), 16);
//boost::multiprecision::cpp_int radix_8 =   boost::multiprecision::pow(boost::multiprecision::cpp_int(2), 8);
//ECPoint genP256(secp256r1, secp256r1.gx, secp256r1.gy); 
    
string f_k_int_x(const std::string& k, const boost::multiprecision::cpp_int& x, boost::multiprecision::cpp_int radix_8) {
            
    string s = "";
    
    for (int i = 1; i <= 3; i++) {
        if (log_print)
            cout << "x+" << i << ": Input to AES block " << i << " encryption (128 bits):" << endl;
        
        string xpi = Hex2(x + i, radix_128);
        
        if (log_print) {
            cout << xpi << endl;
            
            cArrayDef("[be]", "xp" + to_string(i), x + i, 128/8, radix_8, false);
            
            cout << endl;
        }
        if (log_print) 
            cout << "AES_k(x+" << i << "): Output of AES block " << i << " encryption (128 bits):" << endl;
         
        string aes_xpi_str = AES_ecb_encrypt(k,xpi);

        boost::multiprecision::cpp_int aes_xpi = hexStringToCppInt(aes_xpi_str);
    
        if (log_print) {
            cout << aes_xpi_str << endl;
            cArrayDef("[be]", "aes_xp" + to_string(i), aes_xpi, 128/8, radix_8, false);
            cout << endl;
        }

        if (log_print) 
            cout << "AES_k(x+" << i << ") XOR (x+" << i << "): block " << i << " (128 bits):" << endl;
        boost::multiprecision::cpp_int blki_int = (x + i) ^ aes_xpi;
        std::stringstream blki_stream;
        blki_stream << std::setw(32) << std::setfill('0') << std::hex << blki_int;
        string blki = blki_stream.str();

        if (log_print) {
            cout << "0x" << blki << endl;
            cArrayDef("[be]", "block_" + to_string(i), blki_int, 128/8, radix_8, false);
            cout << endl;
        }
        s += blki;
         
    }
    return s;
}   
    
std::pair<boost::multiprecision::cpp_int, ECPoint> bfexpandkey(int i, int j, boost::multiprecision::cpp_int exp_val, boost::multiprecision::cpp_int seedprv, std::string type = "cert") {
    boost::multiprecision::cpp_int x;
    if (type == "cert") {
        x = (i * radix_32 + j) * radix_32;
    } else if (type == "enc") {
        x = (((radix_32 - 1) * radix_32 + i) * radix_32 + j) * radix_32;
    }   
    std::stringstream exp_stream;
    exp_stream << std::setw(32) << std::setfill('0') << std::hex << exp_val;
    string exp_str = exp_stream.str();
    
    string f_k = f_k_int_x(exp_str, x, radix_8);
    
    boost::multiprecision::cpp_int f_k_x = hexStringToCppInt(f_k) % genP256.ecc.n;
    boost::multiprecision::cpp_int prv = (seedprv + f_k_x) % genP256.ecc.n;
    
    ECPoint seedpub = genP256 * seedprv;
    ECPoint pub = seedpub + genP256 * f_k_x;
    assert(pub == genP256 * prv);
    
    return std::make_pair(prv, pub);
}

#endif // BFKEYEXP_H


