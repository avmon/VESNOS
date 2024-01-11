#ifndef IMPLICIT_H
#define IMPLICIT_H

#include <iostream>
#include <string>
#include <vector>
#include <openssl/sha.h>
#include "carray.h"
#include "ecc.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <tuple>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/random/mersenne_twister.hpp>

using namespace std;

const int r_len = 256/8;
boost::multiprecision::cpp_int radix_256 = boost::multiprecision::pow(boost::multiprecision::cpp_int(2), 256);
boost::multiprecision::cpp_int radix_128 = boost::multiprecision::pow(boost::multiprecision::cpp_int(2), 128);
boost::multiprecision::cpp_int radix_32 =  boost::multiprecision::pow(boost::multiprecision::cpp_int(2), 32);
boost::multiprecision::cpp_int radix_16 =  boost::multiprecision::pow(boost::multiprecision::cpp_int(2), 16);
boost::multiprecision::cpp_int radix_8 =   boost::multiprecision::pow(boost::multiprecision::cpp_int(2), 8);
ECPoint genP256(secp256r1, secp256r1.gx, secp256r1.gy);

boost::multiprecision::cpp_int hexStringToCppInt(const std::string& hexString) {
    boost::multiprecision::cpp_int result;
    std::stringstream ss;
    ss << std::hex << hexString;
    ss >> result;
    return result;
}

std::string hexStringToBytes(const std::string& hexString) {
    std::string bytes;
    for (size_t i = 0; i < hexString.length(); i += 2) {
        std::string byteString = hexString.substr(i, 2);
        char byte = static_cast<char>(std::strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string sha_256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256Context;
    SHA256_Init(&sha256Context);
    SHA256_Update(&sha256Context, input.c_str(), input.length());
    SHA256_Final(hash, &sha256Context);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

boost::multiprecision::cpp_int generate_random_cpp_int(unsigned int seed = 333, boost::multiprecision::cpp_int minValue = 1, boost::multiprecision::cpp_int maxValue = 10, unsigned int hexDigitsNeeded = 64) {
    
    boost::random::mt19937_64 rng(seed);

    boost::multiprecision::cpp_int randomValue = 0;

    std::string hexValue = "";
    
    do {
        // Generate a random value
        randomValue = rng() % maxValue + minValue;

        // Convert the value to hexadecimal representation
        std::stringstream ss;
        ss << std::hex << std::uppercase << randomValue;
        std::string hexValue = ss.str();

        // Ensure the hexadecimal value is exactly 64 characters by padding with zeros
        if (hexValue.length() < hexDigitsNeeded) {
            hexValue = std::string(hexDigitsNeeded - hexValue.length(), '0') + hexValue;
        }
    } while (randomValue >= maxValue);
    
    return hexStringToCppInt(hexValue);
} 
    
tuple<ECPoint, std::string, std::string, std::string> implicitCertGen(string tbsCert, ECPoint RU, string dCA, string k = "", bool sec4 = false) {
    assert(dCA.length() == r_len*2);
    assert(RU.is_on_curve());
    boost::multiprecision::cpp_int k_long;
    ECPoint kG;
    boost::multiprecision::cpp_int width = bitLen(genP256.ecc.n)*2/8;
         
    if (k == "") {
        k_long = generate_random_cpp_int(333, 1, genP256.ecc.n - 1, 64);
        k = Hex2(k_long, width);
        kG = genP256 * k_long;
    } else {
        k_long = hexStringToCppInt(k);
        kG = genP256 * k_long;
    }

    ECPoint PU = RU + kG;

    string PU_os = PU.output(true);

    string CertU = tbsCert + PU_os;
    
    string e = sha_256(hexStringToBytes(CertU));
            
    boost::multiprecision::cpp_int e_long;
    if (sec4) {
        e_long = hexStringToCppInt(e) / 2;
    } else {
        e_long = hexStringToCppInt(e) ;
    }   
    boost::multiprecision::cpp_int r_long = (e_long * k_long + hexStringToCppInt(dCA)) % genP256.ecc.n;
    string r = Hex2(r_long, width);
    return std::make_tuple(PU, CertU, r, k);
}


string reconstructPrivateKey(string kU, string CertU, string r, bool sec4 = false, bool cert_dgst = false) {
    string e;
    if (cert_dgst) {
        e = CertU;
    } else {
        e = sha_256(hexStringToBytes(CertU));
    }
    
    boost::multiprecision::cpp_int e_long;
    if (sec4) {
        e_long = hexStringToCppInt(e) / 2;
    } else {
        e_long = hexStringToCppInt(e) ;
    }

    boost::multiprecision::cpp_int kU_long = hexStringToCppInt(kU);
    boost::multiprecision::cpp_int r_long = hexStringToCppInt(r);

    boost::multiprecision::cpp_int dU_long = ((e_long * kU_long) + r_long) % genP256.ecc.n;
    boost::multiprecision::cpp_int width = bitLen(genP256.ecc.n)*2/8;   
    string dU = Hex2(dU_long, width);
    return dU;
}

ECPoint reconstructPublicKey(ECPoint PU, string CertU, ECPoint QCA, bool sec4 = false, bool cert_dgst = false) {
    string e;
    if (cert_dgst) {
        e = CertU;
    } else {
        e = sha_256(hexStringToBytes(CertU));
    }
    
    boost::multiprecision::cpp_int e_long;
    if (sec4) {
        e_long = hexStringToCppInt(e) / 2;
    } else {
        e_long = hexStringToCppInt(e) ;
    }

    ECPoint QU =  (PU * e_long) + QCA;
    return QU;
}

#endif // IMPLICIT_H

