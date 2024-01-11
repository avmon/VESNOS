#ifndef BSMVERIFY_H
#define BSMVERIFY_H

#include <iostream>
#include <string>
#include <stdexcept>
#include <sstream>
#include <cmath>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/lexical_cast.hpp>
#include <openssl/sha.h>
#include <cctype>
#include <vector>
#include <tuple>
#include <random>
#include <iomanip>


boost::multiprecision::cpp_int hexStringToBigInt_(std::string hexString) {
    boost::multiprecision::cpp_int value;
    std::size_t numBits = hexString.length() * 4; // 4 bits per hex digit
    value = 0;

    for (char c : hexString) {
        value <<= 4; // Shift previous bits to the left
        if (c >= '0' && c <= '9')
            value += c - '0'; // Add digit value (0-9)
        else if (c >= 'A' && c <= 'F')
            value += c - 'A' + 10; // Add digit value (10-15)
        else if (c >= 'a' && c <= 'f')
            value += c - 'a' + 10; // Add digit value (10-15)
        else
            throw std::runtime_error("Invalid hex string");
    }

    value <<= (sizeof(boost::multiprecision::cpp_int) * 8 - numBits); // Left-align the value
    return value;
}

boost::multiprecision::cpp_int string_to_cpp_int_(const std::string& hex_str) {
    // Validate the input string
    for (char c : hex_str) {
        if (!std::isxdigit(c, std::locale::classic())) {
            throw std::invalid_argument("Invalid character in the input string");
        }
    }

    boost::multiprecision::cpp_int number;
    std::stringstream ss;
    ss << std::hex << hex_str;
    ss >> number;
    return number;
}

int bitLen_(boost::multiprecision::cpp_int int_type) {
    int length = 0;
    while (int_type) {
        int_type >>= 1;
        length += 1;
    }
    return length;
}

int testBit_(const boost::multiprecision::cpp_int& int_type, int offset) {
    return boost::multiprecision::bit_test(int_type, offset);
}

boost::multiprecision::cpp_int egcd_(boost::multiprecision::cpp_int a, boost::multiprecision::cpp_int b, boost::multiprecision::cpp_int& x, boost::multiprecision::cpp_int& y) {
    if (a == 0) {
        x = 0;
        y = 1;
        return b;
    }
    boost::multiprecision::cpp_int x1, y1;
    boost::multiprecision::cpp_int gcd = egcd_(b % a, a, x1, y1);
    x = y1 - (b / a) * x1;
    y = x1;
    return gcd;
}

boost::multiprecision::cpp_int modinv_(boost::multiprecision::cpp_int a, boost::multiprecision::cpp_int m) {
    a = a % m;
    boost::multiprecision::cpp_int x, y;
    if (a < 0)
        a += m;
    boost::multiprecision::cpp_int gcd = egcd_(a, m, x, y);
    if (gcd != 1) {
      throw std::invalid_argument("modular inverse does not exist");
    }
    else {
        return (x % m + m) % m;
    }
}

boost::multiprecision::cpp_int boost_pow_mod_(boost::multiprecision::cpp_int x, boost::multiprecision::cpp_int y, boost::multiprecision::cpp_int z) {
    boost::multiprecision::cpp_int acc = 1;
    while (y) {
        if (y & 1) {
            acc = (acc * x) % z;
        }
        y >>= 1;
        x = (x * x) % z;
    }
    return acc;
}

boost::multiprecision::cpp_int boost_sqrt_(boost::multiprecision::cpp_int a, boost::multiprecision::cpp_int m) {
    return boost_pow_mod_(a, (m + 1) / 4, m);
}

std::string decToHex_(boost::multiprecision::cpp_int decimal, int width = -1) {
    std::stringstream stream;
    stream << std::hex << decimal;
    std::string result(stream.str());

    if (width != -1) {
        while (result.length() < width) {
            result = "0" + result;
        }
    }

    return result;
}

class ECurve2 {
   public:
   std::string name;
   boost::multiprecision::cpp_int p;
   boost::multiprecision::cpp_int a;
   boost::multiprecision::cpp_int b;
   boost::multiprecision::cpp_int gx;
   boost::multiprecision::cpp_int gy;
   boost::multiprecision::cpp_int n;
   boost::multiprecision::cpp_int h;

   ECurve2(std::string name, std::string p, std::string a, std::string b, std::string gx, std::string gy, std::string n, std::string h) {
      this->name = name;
      this->p = hexStringToBigInt_(p);
      this->a = hexStringToBigInt_(a);
      this->b = hexStringToBigInt_(b);
      this->gx = hexStringToBigInt_(gx);
      this->gy = hexStringToBigInt_(gy);
      this->n = hexStringToBigInt_(n);
      this->h = hexStringToBigInt_(h);
   }
              
    //ECurve() = default; // Default constructor
   
    bool operator==(const ECurve2& c) const {
        return (this->p == c.p && this->a == c.a && this->b == c.b && this->gx == c.gx && this->gy == c.gy && this->n == c.n && this->h == c.h);
    }

    bool operator!=(const ECurve2& c) const {
        return !(*this == c); // Reuse the equality comparison
    }
   
   std::string toString() {
      return this->name;
   }
};


ECurve2 secp256r1_(
std::string("secp256r1"),
std::string("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),  // p
std::string("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),  // a
std::string("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),  // b
std::string("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),  // gx
std::string("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),  // gy
std::string("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),  // n
std::string("1")  // h
);

ECurve2 secp384r1_(
std::string("secp384r1"),
std::string("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"),  // p
std::string("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC"),  // a
std::string("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF"),  // b
std::string("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"),  // gx
std::string("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"),  // gy
std::string("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"),  // n
std::string("1")  // h
);

class ECPoint2 {
   public:
      ECurve2 ecc = ECurve2("","","","","","","","");
      boost::multiprecision::cpp_int x;
      boost::multiprecision::cpp_int y;
      ECPoint2() = default; // Default constructor

        ECPoint2(const ECPoint2& ec_point) {
            ecc = ec_point.ecc;
            x = ec_point.x % ecc.p;
            y = ec_point.y % ecc.p;
            // Convert the result to a positive value if negative
            if (this->x < 0)
                this->x += ecc.p;
            if (this->y < 0)
                this->y += ecc.p; 
            if (!is_infinity()) {
                is_on_curve();
            }
        }
    
       ECPoint2(const ECurve2& ecc, const std::string& os)  {
          this->ecc = ecc;
          this->input(os);
       }
       
       
       ECPoint2(const std::string& compress, const std::string& pub_recon)  {
          if(compress == "compressed-y-0" ||  compress == "compressed-y-1" ) {
             this->ecc = secp256r1_;
             int l = bitLen_(this->ecc.p);
             int os_len = 2 * ((l - 1) / 8 + 1); 
             std::string flag = "";
          if(compress == "compressed-y-0") {
                flag = "02";
             }
             else {
                flag = "03";
             }
             std::string os = flag + pub_recon;
             this->input(os);
          }
       }
     

       ECPoint2(const ECurve2& ecc, const boost::multiprecision::cpp_int& x, const boost::multiprecision::cpp_int& y)  {
          this->ecc = ecc;
          this->x = x % ecc.p;
          this->y = y % ecc.p;
        // Convert the result to a positive value if negative
        if (this->x < 0)
            this->x += ecc.p;
        if (this->y < 0)
            this->y += ecc.p;    
          if(!this->is_infinity()) {
             this->is_on_curve();
          }
       }

    bool operator==(const ECPoint2& b) const {
        return (this->x == b.x && this->y == b.y);
    }
        
    bool operator!=(const ECPoint2& b) const {
        return !(*this == b);
    }

    ECPoint2 operator-() const {
        return ECPoint2(this->ecc, this->x, this->ecc.p - this->y);
    }
  
   ECPoint2 operator+(const ECPoint2& right) const{
      if(this->ecc != right.ecc) {
         throw std::invalid_argument("Different curves for input points!");
      }

      if(this->is_infinity()) {
         return right;
      }
      
      if(right.is_infinity()) {
         return *this;
      }
   
      this->is_on_curve();
      right.is_on_curve();
   
      if(*this == right) {
         return this->doublePoint();
      }
      if(*this == -right) {
         return ECPoint2(this->ecc, 0, 0);
      }
       
      boost::multiprecision::cpp_int lmb = ((right.y - this->y) * modinv_(right.x - this->x, this->ecc.p)) % this->ecc.p;
      boost::multiprecision::cpp_int x3 = (lmb * lmb - this->x - right.x) % this->ecc.p;
      boost::multiprecision::cpp_int y3 = (lmb * (right.x - x3) - right.y) % this->ecc.p;
      return ECPoint2(this->ecc, x3, y3);
   }
   
   ECPoint2 operator-(const ECPoint2& right) {
      if(right.ecc != this->ecc) {
         throw std::invalid_argument("Operand on the right is not ECPoint type!");
      }
      
      return *this + (-right);
   }
   
  
    ECPoint2 operator*(const boost::multiprecision::cpp_int& scalar) const {
        boost::multiprecision::cpp_int k = scalar % ecc.n;
        if (k < 0)
            k += ecc.n;
        
        int bl = bitLen_(k);
        
        if (bl == 0) {
            return ECPoint2(ecc, 0, 0);
        }
        if (bl == 1) {
            return *this;
        }
        ECPoint2 acc = *this;
        for (int i = bl - 2; i >= 0; i--) {
            acc = acc.doublePoint();
            if (testBit_(k, i) != 0) {
                acc = acc + *this;
            }
        }
        return acc;
    }

   bool is_on_curve() const{
      //Checking that (x,y) is on the curve: y^2 = x^3 + a*x + b
      if((this->y * this->y - this->x * this->x * this->x - this->ecc.a * this->x - this->ecc.b) % this->ecc.p != 0) {
         throw std::invalid_argument("[" + boost::lexical_cast<std::string>(this->x) + "], [" + boost::lexical_cast<std::string>(this->y) + "] Point is not on the curve!\n");
      }
      
      return true;
   }
   
   bool is_infinity() const{
      if(this->x == 0 && this->y == 0) {
         return true;
      }
      
      return false;
   }
   
   ECPoint2 doublePoint() const{
      if(this->is_infinity()) {
         return *this;
      }
      
      this->is_on_curve();
      
      boost::multiprecision::cpp_int t = ((3 * this->x * this->x + this->ecc.a) * modinv_(2 * this->y, this->ecc.p)) % this->ecc.p;
      boost::multiprecision::cpp_int x3 = t * t - 2 * this->x;
      boost::multiprecision::cpp_int y3 = t * (this->x - x3) - this->y;   
      return ECPoint2(this->ecc, x3, y3);
   }
   
   std::string output(bool compress = true, bool Ieee1609Dot2 = false) {
      this->is_on_curve();
    
      int l = bitLen_(this->ecc.p);
      int os_len = 2 * ((l - 1) / 8 + 1);   
      if(compress) {
         std::string flag;
         std::string y_str;
         
         if(testBit_(this->y, 0) != 0) {
            flag = "03";
            y_str = "compressed-y-1";
         }
         else {
            flag = "02";
            y_str = "compressed-y-1";
         }
         
         if(!Ieee1609Dot2) {
            return flag + decToHex_(this->x, os_len);
         }
         else {
            return y_str + ", " + decToHex_(this->x, os_len);
         }
      }
      else {
         return "04" + decToHex_(this->x, os_len) + decToHex_(this->y, os_len);
      }
   }
  
    void input(const std::string& os) {
        int l = bitLen_(this->ecc.p);
        int os_len = 2 * ((l - 1) / 8 + 1);
        
        if (os_len == os.length() - 2) {
            std::string flag = os.substr(0, 2);
            if (flag != "02" && flag != "03") {
                throw std::runtime_error("Bad octet string flag!");
            }
            std::string hex_x = os.substr(2, os_len);
            std::stringstream ss_x;
            ss_x << std::hex << hex_x;
            ss_x >> this->x;
            this->y = (this->x * this->x * this->x + this->ecc.a * this->x + this->ecc.b) % this->ecc.p;
            this->y = boost_sqrt_(this->y, this->ecc.p);

            if ((testBit_(this->y, 0) != 0 && flag == "02") || (testBit_(this->y, 0) == 0 && flag == "03")) {
                this->y = this->ecc.p - this->y;
            }

            if (!is_on_curve()) {
                throw std::invalid_argument("Point is not on the curve!");
            }
        } else if (2 * os_len == static_cast<int>(os.length() - 2)) {
            std::string flag = os.substr(0, 2);
            if (flag != "04") {
                throw std::runtime_error("Bad octet string flag!");
            }
 
            std::string hex_x = os.substr(2, os_len);
            std::stringstream ss_x;
            ss_x << std::hex << hex_x;
            ss_x >> this->x;
            
            std::string hex_y = os.substr(2 + os_len, os_len);
            std::stringstream ss_y;
            ss_y << std::hex << hex_y;
            ss_y >> this->y;

            if (!is_on_curve()) {
                throw std::invalid_argument("Point is not on the curve!");
            }
        } else {
            throw std::runtime_error("Bad octet string length!");
        }
    }
};


class ECDSA2 {
public:
    int dgst_bitlen;
    ECurve2 ecc = ECurve2("","","","","","","","");
    ECPoint2 pub_key;
    boost::multiprecision::cpp_int prv_key;
    int n_bitlen;
    int shr_dgst;

    ECDSA2(int dgst_bitlen, ECPoint2 pub_key, boost::multiprecision::cpp_int prv_key = 0) {
        this->dgst_bitlen = dgst_bitlen;
        this->ecc = pub_key.ecc;
        this->pub_key = pub_key;
        this->pub_key.is_on_curve();
        this->n_bitlen = bitLen_(this->ecc.n);
        this->shr_dgst = 0;

        if (this->dgst_bitlen > this->n_bitlen) {
            this->shr_dgst = this->dgst_bitlen - this->n_bitlen;
        }

        if (prv_key != 0) {
            this->prv_key = prv_key % this->ecc.p;

            ECPoint2 genP = ECPoint2(this->ecc, this->ecc.gx, this->ecc.gy);
            ECPoint2 res = genP * this->prv_key;

            if (res != this->pub_key) {
                throw std::invalid_argument("Private key and public key don't match!");
            }
        }
    }

    bool verify(std::string digest, boost::multiprecision::cpp_int r, boost::multiprecision::cpp_int s) {
        boost::multiprecision::cpp_int digest_int = hexStringToBigInt_(digest);
        boost::multiprecision::cpp_int w = modinv_(s, this->ecc.n);
        boost::multiprecision::cpp_int u1 = (digest_int * w) % this->ecc.n;
        boost::multiprecision::cpp_int u2 = (r * w) % this->ecc.n;
        ECPoint2 R = ECPoint2(this->ecc, this->ecc.gx, this->ecc.gy) * u1 + this->pub_key * u2;

        if (R.is_infinity()) {
            return false;
        }

        return (r % this->ecc.n) == (R.x % this->ecc.n);
    }

};

boost::multiprecision::cpp_int hexStringToCppInt_(const std::string& hexString) {
    boost::multiprecision::cpp_int result;
    std::stringstream ss;
    ss << std::hex << hexString;
    ss >> result;
    return result;
}

std::string hexStringToBytes_(const std::string& hexString) {
    std::string bytes;
    for (size_t i = 0; i < hexString.length(); i += 2) {
        std::string byteString = hexString.substr(i, 2);
        char byte = static_cast<char>(std::strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

void hexStringToBytes2(const char *hexString, uint8_t *bytes, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        sscanf(hexString + 2 * i, "%2hhX", &bytes[i]);
    }
}

std::string sha_256_(const std::string& input) {
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

ECPoint2 reconstructPublicKey_(ECPoint2 PU, std::string CertU, ECPoint2 QCA, bool sec4 = false, bool cert_dgst = false) {
    std::string e;
    if (cert_dgst) {
        e = CertU;
    } else {
        e = sha_256_(hexStringToBytes_(CertU));
    }

    boost::multiprecision::cpp_int e_long;
    if (sec4) {
        e_long = hexStringToCppInt_(e) / 2;
    } else {
        e_long = hexStringToCppInt_(e) ;
    }

    ECPoint2 QU =  (PU * e_long) + QCA;
    return QU;
}


std::pair<std::string, std::string> create1609Dot2Digest_(std::string tbs, std::string signer_cert) {

    std::string tbs_dgst = sha_256_(hexStringToBytes_(tbs));

    std::string signer_cert_dgst = sha_256_(hexStringToBytes_(signer_cert));

    std::string digest = sha_256_(hexStringToBytes_(tbs_dgst + signer_cert_dgst));

    return std::make_pair(digest, signer_cert_dgst);
}


ECPoint2 reconstruct_PublicKey_(std::string implicit_cert, std::string implicit_cert_tbs, ECPoint2 pub_recon, std::string issuer_cert, ECPoint2 issuer_pub) {

    std::string cert_dgst = create1609Dot2Digest_(implicit_cert_tbs, issuer_cert).first;

    ECPoint2 recon_pub = reconstructPublicKey_(pub_recon, cert_dgst, issuer_pub, false, true);

    return recon_pub;
}


bool BSMVerify_(boost::multiprecision::cpp_int  r, boost::multiprecision::cpp_int s, std::string bsm_tbs, std::string pseudo_cert, std::string pseudo_cert_tbs, ECPoint2 pub_recon, std::string pca_cert, ECPoint2 pca_pub) {

    ECPoint2 pseudo_pub = reconstruct_PublicKey_(pseudo_cert, pseudo_cert_tbs, pub_recon, pca_cert, pca_pub);

    std::string bsm_dgst = create1609Dot2Digest_(bsm_tbs, pseudo_cert).first;

    ECDSA2 to_verify = ECDSA2(256, pseudo_pub);

    bool result = to_verify.verify(bsm_dgst, r, s);

    return result;
}

std::tuple<ECPoint2, boost::multiprecision::cpp_int, boost::multiprecision::cpp_int, std::string, std::string> Payload_decode(std::string pseudo_cert,std::string bsm_setPayload) {

    std::string BSM_signed = bsm_setPayload.substr(0, bsm_setPayload.length() - 4);
    std::string lengths = bsm_setPayload.substr(bsm_setPayload.length() - 4);
    int R_len = std::stoi(lengths.substr(0, 2));
    int s_len = std::stoi(lengths.substr(2));
    std::string s_out = BSM_signed.substr(BSM_signed.length() - s_len);
    std::string new_BSM_signed = BSM_signed.substr(0, BSM_signed.length() - s_len);
    std::string R_out = new_BSM_signed.substr(new_BSM_signed.length() - R_len);

    // Extract received_hex from BSM_signed
    std::string received_hex = BSM_signed.substr(6);
    int skip = 22 + R_len + s_len;
    received_hex = received_hex.substr(0, received_hex.length() - skip);

    // Initialize bsm_tbs
    std::string bsm_tbs = received_hex;

    // Extract pseudo_cert_tbs from pseudo_cert
    std::string pseudo_cert_tbs = pseudo_cert.substr(24);

    // Extract verificationKeyIndicator (reconstructionValue) from pseudo_cert_tbs
    std::string pub_recon_x = pseudo_cert_tbs.substr(pseudo_cert_tbs.length() - 64);

    // Check if the reconstruction point is compressed-y-0 or compressed-y-1
    ECPoint2 pub_recon("compressed-y-0", pub_recon_x);
    if (pseudo_cert_tbs.substr(pseudo_cert_tbs.length() - 66, 2) == "82") {
        pub_recon = ECPoint2("compressed-y-0", pub_recon_x);
    } else {
        pub_recon = ECPoint2("compressed-y-1", pub_recon_x);
    }

    boost::multiprecision::cpp_int R_x = hexStringToBigInt_(R_out);
    boost::multiprecision::cpp_int s   = hexStringToCppInt_(s_out);

    return std::make_tuple(pub_recon, R_x, s, bsm_tbs, pseudo_cert_tbs);
}

uint8_t* decode_BSM_fields(std::string bsm) {

    std::string bsm_tbs = bsm.substr(5);
    int bsm_len = std::stoi(bsm_tbs.substr(0, 3));
    bsm_tbs = bsm_tbs.substr(3, bsm_len * 2);

    // Convert hex string back to bytes
    size_t hexStringLength = strlen(bsm_tbs.c_str());
    uint8_t *decodedBuffer = (uint8_t *)malloc(hexStringLength / 2);
    hexStringToBytes2(bsm_tbs.c_str(), decodedBuffer, hexStringLength / 2);

    return decodedBuffer;
}








#endif // BSMVERIFY_H

