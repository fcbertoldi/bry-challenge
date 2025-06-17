#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>
#include "bry_challenge/core.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << "<signed_file>\n";
        return 1;
    }

    bry_challenge::SignInfo signInfo{};
    bool validSignature = false;
    try {
        validSignature = bry_challenge::cmsVerify(argv[1], signInfo);
    } catch (const std::exception& err) {
        std::cerr << "Error: " << err.what() << '\n';
        return 1;
    }

    if (!validSignature) {
        std::cout << "Inválida\n";
        return 1;
    }

    std::cout << "Válida\n"
        << "\nInformações da assinatura:\n"
        << "\nNome do signatário: " << signInfo.commonName
        << "\nData da assinatura: " << std::asctime(&signInfo.signingTime)
        << "Hash do documento: " << signInfo.encapContentInfoHex
        << "\nNome do algoritmo: " << signInfo.digestAlgorithm
        << "\n\n";

    return 0;
}
