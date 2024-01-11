#ifndef BSMSIGN_H
#define BSMSIGN_H

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include "carray.h"
#include "ecc.h"
#include "radix.h"
#include "implicit.h"
#include "bfkeyexp.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <tuple>
#include <random>
#include <iomanip>

using namespace std;

vector<string> splitString(const string& input, char delimiter) {
    vector<string> substrings;
    size_t start = 0;
    size_t end = input.find(delimiter);

    while (end != string::npos) {
        substrings.push_back(input.substr(start, end - start));
        start = end + 1;
        end = input.find(delimiter, start);
    }

    substrings.push_back(input.substr(start));

    return substrings;
}

pair<string, string> create1609Dot2Digest(string tbs, string signer_cert) {
    
    string tbs_dgst = sha_256(hexStringToBytes(tbs));
    
    string signer_cert_dgst = sha_256(hexStringToBytes(signer_cert));
    
    string digest = sha_256(hexStringToBytes(tbs_dgst + signer_cert_dgst));
    
    return make_pair(digest, signer_cert_dgst);
}

tuple<ECPoint, boost::multiprecision::cpp_int, string, string> BSMSigning(string bsm_tbs, string pseudo_prv, string pseudo_cert) {

    pair<string, string> dgst = create1609Dot2Digest(bsm_tbs, pseudo_cert);
    
    string bsm_dgst = dgst.first;
    
    string cert_dgst = dgst.second;

    boost::multiprecision::cpp_int pseudo_prv_long = string_to_cpp_int(pseudo_prv);

    ECPoint pseudo_pub = genP256 * pseudo_prv_long;

    ECDSA to_sign(256, pseudo_pub, pseudo_prv_long);

    std::pair<ECPoint, boost::multiprecision::cpp_int> signature = to_sign.sign(bsm_dgst, false);

    return make_tuple(signature.first, signature.second, bsm_dgst, cert_dgst);
}

string BSM_encode(unsigned long long generationTime, string bsm1_1, string pseudo_prv_7A_0, string pseudo_cert_7A_0) {

    ECPoint R;
    boost::multiprecision::cpp_int s;
    std::string digest;
    std::string cert_dgst;
    string R_out;
    string s_out;
    string signedbsm = "038100";
    string bsm_tbs = "400380";

    bsm_tbs += long2hexstr(bsm1_1.length() / 2, 8);
    bsm_tbs += bsm1_1;
    bsm_tbs += "40";
    bsm_tbs += "0100";

    bsm_tbs += longlong2hexstr(generationTime, 64);

    tie(R, s, digest, cert_dgst) = BSMSigning(bsm_tbs, pseudo_prv_7A_0, pseudo_cert_7A_0);

    //res = BSMVerify(R, s, bsm_tbs, pseudo_cert_7A_0, pseudo_cert_tbs_7A_0, pub_recon_7A_0, pca_cert, pca_pub);
    /*
    if (res == true) {
        cout << "BSM successfully verified!" << endl;
    }
    else{
        cout << "ERROR: Failed to verify BSM" << endl;
    }
    */
    R_out = R.output(true, true);
    s_out = decToHex(s, 32);

    signedbsm += bsm_tbs;
    string pseudo_cert_HashedId8 = cert_dgst.substr(cert_dgst.length() - 16);

    signedbsm += "80" + pseudo_cert_HashedId8;
    signedbsm += "80"; // ecdsaNistP256Signature

    char delimiter = ',';

    vector<string> R_out_substrings = splitString(R_out, delimiter);

    if (R_out_substrings[0] == "compressed-y-0") {
        signedbsm += "82";
    } else if (R_out_substrings[0] == "compressed-y-1") {
        signedbsm += "83";
    }

    R_out_substrings[1].erase(0, 1);
    signedbsm += R_out_substrings[1];
    signedbsm += s_out;
    signedbsm += to_string(R_out_substrings[1].length());
    signedbsm += to_string(s_out.length());
    return signedbsm;
}


ECPoint reconstruct_PublicKey(string implicit_cert, string implicit_cert_tbs, ECPoint pub_recon, string issuer_cert, ECPoint issuer_pub) {
    
    string cert_dgst = create1609Dot2Digest(implicit_cert_tbs, issuer_cert).first;

    ECPoint recon_pub = reconstructPublicKey(pub_recon, cert_dgst, issuer_pub, false, true);

    return recon_pub;
}

    
bool BSMVerify(ECPoint r, boost::multiprecision::cpp_int s, string bsm_tbs, string pseudo_cert, string pseudo_cert_tbs, ECPoint pub_recon, string pca_cert, ECPoint pca_pub) {
   
    ECPoint pseudo_pub = reconstruct_PublicKey(pseudo_cert, pseudo_cert_tbs, pub_recon, pca_cert, pca_pub);

    string bsm_dgst = create1609Dot2Digest(bsm_tbs, pseudo_cert).first;

    ECDSA to_verify = ECDSA(256, pseudo_pub);
   
    bool result = to_verify.verify(bsm_dgst, r.x, s);

    return result;
}   

     
pair<string, ECPoint> BFExpandAndReconstructKey(boost::multiprecision::cpp_int seed_prv, boost::multiprecision::cpp_int exp_val, int i, int j, 
string prv_recon, string pseudo_cert_tbs, string pca_cert,ECPoint* pca_pub = nullptr, ECPoint* pseudo_pub_recon = nullptr) {
    
    bool log_print = false;

    boost::multiprecision::cpp_int bf_prv = bfexpandkey(i, j, exp_val, seed_prv).first;
       
    string cert_dgst = create1609Dot2Digest(pseudo_cert_tbs, pca_cert).first;
    
    string pseudo_prv = reconstructPrivateKey(Hex2(bf_prv, radix_256), cert_dgst, prv_recon, false, true);
    
    if (pseudo_prv.substr(0, 2) == "0x")
        pseudo_prv.erase(0, 2);
       
    ECPoint pseudo_pub = genP256 * string_to_cpp_int(pseudo_prv);
    
    if (pca_pub != nullptr) {
        ECPoint recon_pseudo_pub = reconstructPublicKey(*pseudo_pub_recon, cert_dgst, *pca_pub, false, true);
        if (recon_pseudo_pub != pseudo_pub) {
            throw std::invalid_argument("Reconstructed private key and public key do not form a pair");
        }
    }
    
    return make_pair(pseudo_prv, pseudo_pub);
}

int hexStringToInt(const std::string& hexStr) {
    
    int intValue;
    
    std::stringstream hexStream(hexStr);
    
    hexStream >> std::hex >> intValue;
    
    return intValue;
}

#endif
