#ifndef RADIX_H
#define RADIX_H

#include <iostream>
#include <vector>
#include <algorithm>
#include <cmath>
#include <sstream>
#include <boost/multiprecision/cpp_int.hpp>
#include <sstream>

std::string Hex(int n, int radix=0) {
    std::string signum = "";
    if (n < 0) {
        signum = "-";
    }
    std::string nh = std::to_string(abs(n));
    std::transform(nh.begin(), nh.end(), nh.begin(), ::toupper);
    std::string pad = std::string(std::max(std::log2(radix), 0.0), '0');
    if (pad.length() >= nh.length()) {
        pad = pad.substr(0, pad.length() - nh.length());
    } else {
        pad = "";
    }
    return signum + "0x" + pad + nh;
}


boost::multiprecision::cpp_int log2(const boost::multiprecision::cpp_int& num) {
    if (num <= 0)
        throw std::invalid_argument("log2_custom: Invalid input, must be positive.");

    boost::multiprecision::cpp_int result = 0;
    boost::multiprecision::cpp_int n = num;
    
    while (n > 1) {
        n >>= 1;
        ++result;
    }

    return result;
}

// Custom function to create a string of '0's for boost::multiprecision::cpp_int
std::string zeros_string(const boost::multiprecision::cpp_int& num_zeros) {
    if (num_zeros < 0)
        throw std::invalid_argument("zeros_string: Invalid input, must be non-negative.");

    std::string result;
    for (boost::multiprecision::cpp_int i = 0; i < num_zeros; ++i) {
        result += '0';
    }

    return result;
}

std::string Hex2(const boost::multiprecision::cpp_int& n, const boost::multiprecision::cpp_int& radix = 0) {
    std::string signum = (n < 0) ? "-" : "";

    std::stringstream ss;
    ss << std::hex << n;
    std::string nh = ss.str();

    if (nh.find("L") != std::string::npos) {
        nh = nh.substr(0, nh.length() - 1);
    }

    boost::multiprecision::cpp_int pad = (log2(radix) + 1) / 4;

    if (pad >= nh.length()) {
        pad -= nh.length();
    } else {
        pad = 0;
    }

    std::string pad_zeros = zeros_string(pad);

    std::stringstream result;
    result << signum << "0x" << pad_zeros << std::uppercase << nh;

    return result.str();
}

std::vector<boost::multiprecision::cpp_int> int2lelist(boost::multiprecision::cpp_int n, boost::multiprecision::cpp_int radix, int listlen=0) {
    if (n < 0) {
        n = -n;
    } else if (n == 0) {
        return {0};
    }
    std::vector<boost::multiprecision::cpp_int> nlist;
    while (n) {
        nlist.push_back(n % radix);
        n = n / radix;
    }
    while (nlist.size() < listlen) {
        nlist.push_back(0);
    }
    return nlist;
}

int belist2int(std::vector<int> nlist, int radix) {
    int n = 0;
    for (int ndigit : nlist) {
        n *= radix;
        n += ndigit;
    }
    return n;
}

std::vector<boost::multiprecision::cpp_int> int2belist(boost::multiprecision::cpp_int n, boost::multiprecision::cpp_int radix, int listlen=0) {
    std::vector<boost::multiprecision::cpp_int> nlist = int2lelist(n, radix, listlen);
    std::reverse(nlist.begin(), nlist.end());
    return nlist;
}

int lelist2int(std::vector<int> nlist, int radix) {
    std::vector<int> nlist_rev = nlist;
    std::reverse(nlist_rev.begin(), nlist_rev.end());
    return belist2int(nlist_rev, radix);
}

std::string long2hexstr(int n, int bitlen) {
    std::stringstream ss;
    ss << std::hex << n;
    std::string hexstr = ss.str();
    int width = (bitlen * 2 + 7) / 8;
    hexstr = std::string(width - hexstr.length(), '0') + hexstr;
    return hexstr;
}

std::string longlong2hexstr(unsigned long long n, int bitlen) {
    std::stringstream ss;
    ss << std::hex << n;
    std::string hexstr = ss.str();
    int width = (bitlen * 2 + 7) / 8;
    hexstr = std::string(width - hexstr.length(), '0') + hexstr;
    return hexstr;
}

#endif // RADIX_H
