#ifndef ECC_H
#define ECC_H

#include <iostream>
#include <string>
#include <stdexcept>
#include <sstream>
#include <cmath>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/lexical_cast.hpp>
#include <openssl/sha.h>
#include <cctype>
typedef boost::multiprecision::cpp_int bigint_t; 


boost::multiprecision::cpp_int string_to_cpp_int(const std::string& hex_str) {
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

std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.length());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

boost::multiprecision::cpp_int boost_pow_mod(boost::multiprecision::cpp_int x, boost::multiprecision::cpp_int y, boost::multiprecision::cpp_int z) {
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

boost::multiprecision::cpp_int boost_sqrt(boost::multiprecision::cpp_int a, boost::multiprecision::cpp_int m) {
    return boost_pow_mod(a, (m + 1) / 4, m);
}


int bitLen(boost::multiprecision::cpp_int int_type) {
    int length = 0;
    while (int_type) {
        int_type >>= 1;
        length += 1;
    }
    return length;
}

int testBit(const boost::multiprecision::cpp_int& int_type, int offset) {
    return boost::multiprecision::bit_test(int_type, offset);
}

boost::multiprecision::cpp_int egcd(boost::multiprecision::cpp_int a, boost::multiprecision::cpp_int b, boost::multiprecision::cpp_int& x, boost::multiprecision::cpp_int& y) {
    if (a == 0) {
        x = 0;
        y = 1;
        return b;
    }
    boost::multiprecision::cpp_int x1, y1;
    boost::multiprecision::cpp_int gcd = egcd(b % a, a, x1, y1);
    x = y1 - (b / a) * x1;
    y = x1;
    return gcd;
}

boost::multiprecision::cpp_int modinv(boost::multiprecision::cpp_int a, boost::multiprecision::cpp_int m) {
    a = a % m;
    boost::multiprecision::cpp_int x, y;
    if (a < 0)
        a += m;       
    boost::multiprecision::cpp_int gcd = egcd(a, m, x, y);
    if (gcd != 1) {
      throw std::invalid_argument("modular inverse does not exist");
    }
    else {
        return (x % m + m) % m;
    }
}

boost::multiprecision::cpp_int hexStringToBigInt(std::string hexString) {
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

std::string decToHex(boost::multiprecision::cpp_int decimal, int width = -1) {
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

class ECurve {
   public:
   std::string name;
   boost::multiprecision::cpp_int p;
   boost::multiprecision::cpp_int a;
   boost::multiprecision::cpp_int b;
   boost::multiprecision::cpp_int gx;
   boost::multiprecision::cpp_int gy;
   boost::multiprecision::cpp_int n;
   boost::multiprecision::cpp_int h;

   ECurve(std::string name, std::string p, std::string a, std::string b, std::string gx, std::string gy, std::string n, std::string h) {
      this->name = name;
      this->p = hexStringToBigInt(p);
      this->a = hexStringToBigInt(a);
      this->b = hexStringToBigInt(b);
      this->gx = hexStringToBigInt(gx);
      this->gy = hexStringToBigInt(gy);
      this->n = hexStringToBigInt(n);
      this->h = hexStringToBigInt(h);
   }
              
    //ECurve() = default; // Default constructor
   
    bool operator==(const ECurve& c) const {
        return (this->p == c.p && this->a == c.a && this->b == c.b && this->gx == c.gx && this->gy == c.gy && this->n == c.n && this->h == c.h);
    }

    bool operator!=(const ECurve& c) const {
        return !(*this == c); // Reuse the equality comparison
    }
   
   std::string toString() {
      return this->name;
   }
};


ECurve secp256r1(
std::string("secp256r1"),
std::string("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),  // p
std::string("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),  // a
std::string("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),  // b
std::string("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),  // gx
std::string("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),  // gy
std::string("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),  // n
std::string("1")  // h
);

ECurve secp384r1(
std::string("secp384r1"),
std::string("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"),  // p
std::string("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC"),  // a
std::string("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF"),  // b
std::string("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"),  // gx
std::string("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"),  // gy
std::string("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"),  // n
std::string("1")  // h
);
    
class ECPoint {
   public:
      ECurve ecc = ECurve("","","","","","","","");
      boost::multiprecision::cpp_int x;
      boost::multiprecision::cpp_int y;
      ECPoint() = default; // Default constructor

        ECPoint(const ECPoint& ec_point) {
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
    
       ECPoint(const ECurve& ecc, const std::string& os)  {
          this->ecc = ecc;
          this->input(os);
       }
       
       
       ECPoint(const std::string& compress, const std::string& pub_recon)  {
          if(compress == "compressed-y-0" ||  compress == "compressed-y-1" ) {
             this->ecc = secp256r1;
             int l = bitLen(this->ecc.p);
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
     

       ECPoint(const ECurve& ecc, const boost::multiprecision::cpp_int& x, const boost::multiprecision::cpp_int& y)  {
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

    bool operator==(const ECPoint& b) const {
        return (this->x == b.x && this->y == b.y);
    }
        
    bool operator!=(const ECPoint& b) const {
        return !(*this == b);
    }

    ECPoint operator-() const {
        return ECPoint(this->ecc, this->x, this->ecc.p - this->y);
    }
  
   ECPoint operator+(const ECPoint& right) const{
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
         return ECPoint(this->ecc, 0, 0);
      }
       
      boost::multiprecision::cpp_int lmb = ((right.y - this->y) * modinv(right.x - this->x, this->ecc.p)) % this->ecc.p;
      boost::multiprecision::cpp_int x3 = (lmb * lmb - this->x - right.x) % this->ecc.p;
      boost::multiprecision::cpp_int y3 = (lmb * (right.x - x3) - right.y) % this->ecc.p;
      return ECPoint(this->ecc, x3, y3);
   }
   
   ECPoint operator-(const ECPoint& right) {
      if(right.ecc != this->ecc) {
         throw std::invalid_argument("Operand on the right is not ECPoint type!");
      }
      
      return *this + (-right);
   }
   
  
    ECPoint operator*(const boost::multiprecision::cpp_int& scalar) const {
        boost::multiprecision::cpp_int k = scalar % ecc.n;
        if (k < 0)
            k += ecc.n;
        
        int bl = bitLen(k);
        
        if (bl == 0) {
            return ECPoint(ecc, 0, 0);
        }
        if (bl == 1) {
            return *this;
        }
        ECPoint acc = *this;
        for (int i = bl - 2; i >= 0; i--) {
            acc = acc.doublePoint();
            if (testBit(k, i) != 0) {
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
   
   ECPoint doublePoint() const{
      if(this->is_infinity()) {
         return *this;
      }
      
      this->is_on_curve();
      
      boost::multiprecision::cpp_int t = ((3 * this->x * this->x + this->ecc.a) * modinv(2 * this->y, this->ecc.p)) % this->ecc.p;
      boost::multiprecision::cpp_int x3 = t * t - 2 * this->x;
      boost::multiprecision::cpp_int y3 = t * (this->x - x3) - this->y;   
      return ECPoint(this->ecc, x3, y3);
   }
   
   std::string output(bool compress = true, bool Ieee1609Dot2 = false) {
      this->is_on_curve();
    
      int l = bitLen(this->ecc.p);
      int os_len = 2 * ((l - 1) / 8 + 1);   
      if(compress) {
         std::string flag;
         std::string y_str;
         
         if(testBit(this->y, 0) != 0) {
            flag = "03";
            y_str = "compressed-y-1";
         }
         else {
            flag = "02";
            y_str = "compressed-y-1";
         }
         
         if(!Ieee1609Dot2) {
            return flag + decToHex(this->x, os_len);
         }
         else {
            return y_str + ", " + decToHex(this->x, os_len);
         }
      }
      else {
         return "04" + decToHex(this->x, os_len) + decToHex(this->y, os_len);
      }
   }
  
    void input(const std::string& os) {
        int l = bitLen(this->ecc.p);
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
            this->y = boost_sqrt(this->y, this->ecc.p);

            if ((testBit(this->y, 0) != 0 && flag == "02") || (testBit(this->y, 0) == 0 && flag == "03")) {
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

 
class ECPointJ {
public:
    ECurve ecc = ECurve("","","","","","","","");
    boost::multiprecision::cpp_int x;
    boost::multiprecision::cpp_int y;
    boost::multiprecision::cpp_int z;

    ECPointJ() = default; // Default constructor
      
    ECPointJ(const ECPoint& point){
        this->ecc = point.ecc;
        if (point.is_infinity()) {
            this->x = 1;
            this->y = 1;
            this->z = 0; 
        }
        else {
            this->x = point.x % ecc.p;
            this->y = point.y % ecc.p;
            this->z = 1;
            this->is_on_curve();  
        }
    }

    ECPointJ(const ECurve& ecc, const boost::multiprecision::cpp_int& x, const boost::multiprecision::cpp_int& y, const boost::multiprecision::cpp_int& z) {
        this->ecc = ecc;
        this->x = x % ecc.p;
        this->y = y % ecc.p;
        this->z = z % ecc.p;
        // Convert the result to a positive value if negative
        if (this->x < 0)
            this->x += ecc.p;
        if (this->y < 0)
            this->y += ecc.p; 
        if (this->z < 0)
            this->z += ecc.p; 
   
        if (!this->is_infinity()) {
            this->is_on_curve();
        }
    }

    bool operator==(const ECPointJ& b) const {
        return (this->x == b.x && this->y == b.y && this->z == b.z);
    }
    

    ECPointJ operator-() const {
        return ECPointJ(this->ecc, this->x, this->ecc.p - this->y, this->z);
    }

    ECPointJ operator+(const ECPoint& right) const {
        if (this->ecc != right.ecc) {
            throw std::invalid_argument("Different curves for input points!");
        }

        if (this->is_infinity()) {
            return ECPointJ(right.ecc, right.x, right.y, 1);
        }

        if (right.is_infinity()) {
            return ECPointJ(this->ecc, this->x, this->y, this->z);
        }

        this->is_on_curve();
        right.is_on_curve();

        boost::multiprecision::cpp_int z1z1 = this->z * this->z;
        boost::multiprecision::cpp_int u2 = right.x * z1z1;
        boost::multiprecision::cpp_int s2 = right.y * this->z * z1z1;
        boost::multiprecision::cpp_int h = (u2 - this->x) % this->ecc.p;
        boost::multiprecision::cpp_int r = (2 * (s2 - this->y)) % this->ecc.p;

        if (h == 0) {
            if (r == 0) {
                return this->doublePoint();
            } else {
                return ECPointJ(this->ecc, 1, 1, 0);
            }
        }

        boost::multiprecision::cpp_int hh = h * h;
        boost::multiprecision::cpp_int i = 4 * hh;
        boost::multiprecision::cpp_int j = h * i;
        boost::multiprecision::cpp_int v = this->x * i;
        boost::multiprecision::cpp_int x3 = (r * r - j - 2 * v) % this->ecc.p;
        boost::multiprecision::cpp_int y3 = (r * (v - x3) - 2 * this->y * j) % this->ecc.p;
        boost::multiprecision::cpp_int z3 = ((this->z + h) * (this->z + h) - z1z1 - hh) % this->ecc.p;

        return ECPointJ(this->ecc, x3, y3, z3);
    }

    ECPointJ operator+(const ECPointJ& right) const {
        if (this->ecc != right.ecc) {
            throw std::invalid_argument("Different curves for input points!");
        }

        if (this->is_infinity()) {
            return ECPointJ(right.ecc, right.x, right.y, right.z);
        }

        if (right.is_infinity()) {
            return ECPointJ(this->ecc, this->x, this->y, this->z);
        }

        this->is_on_curve();
        right.is_on_curve();

        boost::multiprecision::cpp_int z1z1 = this->z * this->z;
        boost::multiprecision::cpp_int z2z2 = right.z * right.z;
        boost::multiprecision::cpp_int u1 = this->x * z2z2;
        boost::multiprecision::cpp_int u2 = right.x * z1z1;
        boost::multiprecision::cpp_int s1 = this->y * right.z * z2z2;
        boost::multiprecision::cpp_int s2 = right.y * this->z * z1z1;
        boost::multiprecision::cpp_int h = (u2 - u1) % this->ecc.p;
        boost::multiprecision::cpp_int r = (2 * (s2 - s1)) % this->ecc.p;

        if (h == 0) {
            if (r == 0) {
                return this->doublePoint();
            } else {
                return ECPointJ(this->ecc, 1, 1, 0);
            }
        }

        boost::multiprecision::cpp_int i = (2 * h) * (2 * h);
        boost::multiprecision::cpp_int j = h * i;
        boost::multiprecision::cpp_int v = u1 * i;
        boost::multiprecision::cpp_int x3 = (r * r - j - 2 * v) % this->ecc.p;
        boost::multiprecision::cpp_int y3 = (r * (v - x3) - 2 * s1 * j) % this->ecc.p;
        boost::multiprecision::cpp_int z3 = ((this->z + right.z) * (this->z + right.z) - z1z1 - z2z2) * h % this->ecc.p;

        return ECPointJ(this->ecc, x3, y3, z3);
    }
    
    ECPointJ operator& (const ECPoint& right) const {
    // Point addition: Jacobian + Affine
        if (this->ecc != right.ecc) {
            throw std::invalid_argument("Different curves for input points!");
        }

        if (this->is_infinity()) {
            return ECPointJ(right); // Convert from Affine to Jacobian
        }

        if (right.is_infinity()) {
            return *this;
        }
        
        this->is_on_curve();
        right.is_on_curve();

        // Addition formulas
        boost::multiprecision::cpp_int t1 = z * z;
        boost::multiprecision::cpp_int t2 = t1 * z;
        t1 = t1 * right.x;
        t2 = t2 * right.y;
        t1 = (t1 - x) % ecc.p;
        t2 = (t2 - y) % ecc.p;

        // Corner cases
        if (t1 == 0) {
            // Double
            if (t2 == 0) {
                return this->doublePoint();
            } else {
                return ECPointJ(this->ecc, 1, 1, 0);
            }
        }
        boost::multiprecision::cpp_int z3 = z * t1;
        boost::multiprecision::cpp_int t3 = t1 * t1;
        boost::multiprecision::cpp_int t4 = t3 * t1;
        t3 = t3 * x;
        t1 = 2 * t3;
        boost::multiprecision::cpp_int x3 = t2 * t2;
        x3 = x3 - t1;
        x3 = x3 - t4;
        t3 = t3 - x3;
        t3 = t3 * t2;
        t4 = t4 * y;
        boost::multiprecision::cpp_int y3 = t3 - t4;

        return ECPointJ(this->ecc, x3, y3, z3);
    }


    ECPointJ operator-(const ECPointJ& right) const {
        return *this + (-right);
    }

    ECPointJ operator*(const boost::multiprecision::cpp_int& left) const {
        if (left < 0) {
            throw std::invalid_argument("Operand on the left is not a positive integer!");
        }

        boost::multiprecision::cpp_int k = left % this->ecc.n;

        if (k == 0) {
            return ECPointJ(this->ecc, 1, 1, 0);
        }

        if (k == 1) {
            return ECPointJ(this->ecc, this->x, this->y, this->z);
        }

        ECPointJ acc = *this;

        for (int i = bitLen(k) - 2; i >= 0; i--) {
            acc = acc + acc;

            if (testBit(k, i) != 0) {
                acc = acc + *this;
            }
        }

        return acc;
    }

    bool is_on_curve() const {
        //Checking that (x,y,z) is on the curve: y^2 = x^3 + a*x*z^4 + b*z^6
        boost::multiprecision::cpp_int term1 = this->x * this->x * this->x;
        boost::multiprecision::cpp_int term2 = this->ecc.a * this->x * this->z * this->z * this->z * this->z;
        boost::multiprecision::cpp_int term3 = this->ecc.b * this->z * this->z * this->z * this->z * this->z* this->z;      
        boost::multiprecision::cpp_int right_term = term1 + term2 + term3;  
        boost::multiprecision::cpp_int left_term = this->y * this->y; 
        if ((left_term - right_term) % this->ecc.p != 0) {
            throw std::invalid_argument("Point is not on the curve!");
        }
        return true;
    }

    bool is_infinity() const {
        if (this->x == 1 && this->y == 1 && this->z == 0) {
            return true;
        }

        return false;
    }

    ECPointJ doublePoint() const {
        if (this->is_infinity()) {
            return *this;
        }

        this->is_on_curve();

        boost::multiprecision::cpp_int delta = this->z * this->z;
        boost::multiprecision::cpp_int gamma = this->y * this->y;
        boost::multiprecision::cpp_int beta = this->x * gamma;
        boost::multiprecision::cpp_int alpha = 3 * (this->x - delta) * (this->x + delta);
        boost::multiprecision::cpp_int x3 = (alpha * alpha - 8 * beta) % this->ecc.p;
        boost::multiprecision::cpp_int z3 = (2 * this->y * this->z) % this->ecc.p;
        boost::multiprecision::cpp_int y3 = (alpha * (4 * beta - x3) - 8 * gamma * gamma) % this->ecc.p;

        return ECPointJ(this->ecc, x3, y3, z3);
    }
};

ECPoint ECPointJ_to_ECPoint(ECPointJ ec_pointj) {
    ECPoint output(ec_pointj.ecc, 0, 0);
    if (ec_pointj.is_infinity()) {
        output.x = 0;
        output.y = 0;
    } else {
        boost::multiprecision::cpp_int zinv = modinv(ec_pointj.z, output.ecc.p);
        output.x = (ec_pointj.x * zinv * zinv) % output.ecc.p;
        output.y = (ec_pointj.y * zinv * zinv * zinv) % output.ecc.p;
        output.is_on_curve();
    }
    return output;
}     
      
ECPoint multiplyJ(const ECPoint& ec_pointj, const boost::multiprecision::cpp_int& scalar) {
    boost::multiprecision::cpp_int k = scalar % ec_pointj.ecc.n;
    if (k < 0)
        k += ec_pointj.ecc.n;
    int bl = bitLen(k);
    if (bl == 0) {
        return ECPoint(ec_pointj.ecc, 0, 0);
    }
    if (bl == 1) {
        return ec_pointj;
    }
    ECPointJ acc = ECPointJ(ec_pointj);
    for (int i = bl - 2; i >= 0; i--) {
        acc = acc.doublePoint();
        if (testBit(k, i) != 0) {
            acc = acc + ec_pointj;
        }
    }
    return ECPointJ_to_ECPoint(acc);
}


class ECDSA {
public:
    int dgst_bitlen;
    ECurve ecc = ECurve("","","","","","","","");
    ECPoint pub_key;
    boost::multiprecision::cpp_int prv_key;
    int n_bitlen;
    int shr_dgst;

    ECDSA(int dgst_bitlen, ECPoint pub_key, boost::multiprecision::cpp_int prv_key = 0) {
        this->dgst_bitlen = dgst_bitlen;
        this->ecc = pub_key.ecc;
        this->pub_key = pub_key;
        this->pub_key.is_on_curve();
        this->n_bitlen = bitLen(this->ecc.n);
        this->shr_dgst = 0;

        if (this->dgst_bitlen > this->n_bitlen) {
            this->shr_dgst = this->dgst_bitlen - this->n_bitlen;
        }

        if (prv_key != 0) {
            this->prv_key = prv_key % this->ecc.p;

            ECPoint genP = ECPoint(this->ecc, this->ecc.gx, this->ecc.gy);
            ECPoint res = genP * this->prv_key;

            if (res != this->pub_key) {
                throw std::invalid_argument("Private key and public key don't match!");
            }
        }
    }

    std::pair<ECPoint, boost::multiprecision::cpp_int> sign(std::string digest, bool retR_xmodn = true) {
        boost::multiprecision::cpp_int digest_int = hexStringToBigInt(digest);
        boost::multiprecision::cpp_int k = rand() % (this->ecc.n - 1) + 1;
        ECPoint R = ECPoint(this->ecc, this->ecc.gx, this->ecc.gy) * k;
        boost::multiprecision::cpp_int s = modinv(k, this->ecc.n) * (digest_int + this->prv_key * R.x) % this->ecc.n;

        if (retR_xmodn) {
            ECPoint r = ECPoint(R);
            return std::make_pair(r, s);
        }
        else{
            return std::make_pair(R, s);
        }
    }

    bool verify(std::string digest, boost::multiprecision::cpp_int r, boost::multiprecision::cpp_int s) {
        boost::multiprecision::cpp_int digest_int = hexStringToBigInt(digest);
        boost::multiprecision::cpp_int w = modinv(s, this->ecc.n);
        boost::multiprecision::cpp_int u1 = (digest_int * w) % this->ecc.n;
        boost::multiprecision::cpp_int u2 = (r * w) % this->ecc.n;
        ECPoint R = ECPoint(this->ecc, this->ecc.gx, this->ecc.gy) * u1 + this->pub_key * u2;

        if (R.is_infinity()) {
            return false;
        }

        return (r % this->ecc.n) == (R.x % this->ecc.n);
    }
};

#endif // ECC_H

