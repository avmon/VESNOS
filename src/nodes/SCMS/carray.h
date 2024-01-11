#ifndef CARRAY_H
#define CARRAY_H

#include <iostream>
#include <vector>
#include "radix.h"
#include <boost/multiprecision/cpp_int.hpp>

void cArrayDefFromList(const std::string& arraytype, const std::string& arrayname, const std::vector<boost::multiprecision::cpp_int>& arraylist, boost::multiprecision::cpp_int arrayradix = 4294967296) {
    if (!arrayname.empty()) {
        std::cout << arraytype << " " << arrayname << "[" << arraylist.size() << "] = ";
    }
    std::cout << "{ ";
    for (int i = 0; i < arraylist.size() - 1; i++) {
        if (i && i % 16 == 0) {
            std::cout << std::endl << "  ";
        }
        std::cout << Hex2(arraylist[i], arrayradix) << ", ";
    }
    int i = arraylist.size() - 1;
    if (i && i % 16 == 0) {
        std::cout << std::endl << "  ";
    }
    std::cout << Hex2(arraylist[i], arrayradix) << " }";
}

void cArrayDef(const std::string& arraytype, const std::string& arrayname, boost::multiprecision::cpp_int arrayvalue, int arraylen = 0, boost::multiprecision::cpp_int arrayradix = 4294967296, bool littleendian = true) {
    std::vector<boost::multiprecision::cpp_int> arraylist;
    if (littleendian) {
        arraylist = int2lelist(arrayvalue, arrayradix, arraylen);
    } else {
        arraylist = int2belist(arrayvalue, arrayradix, arraylen);
    }
    cArrayDefFromList(arraytype, arrayname, arraylist, arrayradix);
}

#endif // CARRAY_H
