#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>
#include "bry_challenge/core.h"


int main(int argc, char* argv[]) {

    int ret = 1;

    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << "<p12file> <passphrase_file> <data_file> <outfile>\n";
        return ret;
    }

    const char* p12File = argv[1];
    const char* passphraseFile = argv[2];
    const char* dataFile = argv[3];
    const char* outFile = argv[4];

    std::filesystem::path outPath(outFile);
    if (outPath.extension() != ".p7s") {
        std::cerr << "Error: output file must have .p7s extension\n";
        return ret;
    }

    std::string passphrase;
    std::ifstream passphraseStream(passphraseFile);
    if (!passphraseStream.is_open()) {
        std::cerr << "Error: Unable to open passphrase file\n";
        return ret;
    }

    std::getline(passphraseStream, passphrase);
    passphraseStream.close();

    if (passphrase.empty()) {
        std::cerr << "Error: Passphrase file is empty\n";
        return ret;
    }

    try {
        bry_challenge::cmsSign(p12File, passphrase.data(), dataFile, outFile);
    } catch (const std::exception& err) {
        std::cerr << "Error: " << err.what() << '\n';
        return 1;
    }
    return 0;
}
