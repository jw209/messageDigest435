/***
   prepared for CS435 Project 1 part 2
**/

#include <string.h>
#include <iostream>
#include <fstream>
#include "sha256.h"
#include "BigIntegerLibrary.hh"
 
int main(int argc, char *argv[])
{
   if ((argc != 3 || argv[1][0]!='s') && (argc !=4 || argv[1][0]!='v')) 
      std::cout << "wrong format! should be \"a.exe s filename\" or \"a.exe v filename signature\"" << "\n";
   else {
      // professor Duan's code
      // read the file in and create a memory block to store it in
      std::string filename = argv[2];
      std::string filename_sig;
      if (argv[1][0] == 'v')
           std::string filename_sig = argv[3];
            
      // read the file into memory
      std::streampos begin,end;
      std::ifstream myfile (filename.c_str(), std::ios::binary);
      begin = myfile.tellg();
      myfile.seekg (0, std::ios::end);
      end = myfile.tellg();
      std::streampos size = end-begin;
      
      myfile.seekg (0, std::ios::beg);
      char * memblock = new char[size];
      myfile.read (memblock, size); //read file; it's saved in the char array memblock
      myfile.close();
      
      // SIGN THE FILE
      if (argv[1][0]=='s') {

         // extract d and n values
         std::string d, n;
         std::ifstream istrm("d_n.txt");
         getline(istrm, d);
         getline(istrm, n);
         istrm.close();

         // convert d and n to BigUnsigned values
         BigUnsigned dVal = stringToBigUnsigned(d);
         BigUnsigned nVal = stringToBigUnsigned(n);

         // get hash
         std::string hc = sha256(memblock);
         BigUnsignedInABase hashcode(hc, 16);

         // some type conversion so that we can use modexp and get the signature
         std::string hashforconversion = bigUnsignedToString(hashcode);
         BigInteger hashval = stringToBigInteger(hashforconversion);
         BigUnsigned signature = modexp(hashval, dVal, nVal);
         
         // create and output the signature file
         std::string outputfilename = filename+".signature";
         std::ofstream myfile(outputfilename.c_str(), std::ios::binary);
         if (myfile.is_open()) {
            myfile << signature << "\n";
         }
         else {
            std::cout << "Error occured trying to create file with signature" << std::endl;
            return -1;
         }
         std::cout << "successfuly signed the file" << std::endl;
      }
      // VERIFY THE FILE
      else {

         // extract e and n values
         std::string e, n;
         std::ifstream istrm2("e_n.txt");
         getline(istrm2, e);
         getline(istrm2, n);
         istrm2.close();

         // convert d and n to be BigUnsigned values
         BigUnsigned eVal = stringToBigUnsigned(e);
         BigUnsigned nVal = stringToBigUnsigned(n);

         // read in the signature file.
         std::string inputfilename = filename+".signature";
         std::ifstream istrm3(inputfilename.c_str(), std::ios::binary);
         std::string signature;
         getline(istrm3, signature);
         
         // convert the signature file and get hash code
         BigUnsigned signatureConverted = stringToBigUnsigned(signature);
         BigUnsigned hash = modexp(signatureConverted, eVal, nVal);
         std::string hc = sha256(memblock);
         BigUnsignedInABase sighashcode(hash, 16);
         BigUnsignedInABase hashcode(hc, 16);

         if (hashcode == sighashcode) {
            std::cout << "authentic" << std::endl;
         } else {
            std::cout << "modified" << std::endl;
         }
      }
      delete[] memblock;
    }
    return 0;
}

/*
std::ifstream istrm("p_q.txt");
      getline(istrm, p_string);
*/