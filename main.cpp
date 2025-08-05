#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>
#include "lexer.h"
#include "parser.h"
#include "ast.h"
#include <unistd.h>
#include <sys/wait.h>


void execBinary(const std::string &binary) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    } else if (pid == 0) {
        execl(binary.c_str(), binary.c_str(), (char *)nullptr);
        perror("execl");
        exit(1);
    } else {
        int status;
        waitpid(pid, &status, 0);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: ./compile <source_files> [-S] [-o output_file] [exec]\n";
        return 1;
    }

    std::vector<std::string> sourceFiles;
    bool assemblyFlag = false;
    int argIndex = 1;

    // Collect source files until we hit a flag
    while (argIndex < argc &&
           std::string(argv[argIndex]) != "-o" &&
           std::string(argv[argIndex]) != "exec" &&
           std::string(argv[argIndex]) != "-S") {
        sourceFiles.push_back(argv[argIndex]);
        argIndex++;
    }

    if (sourceFiles.empty()) {
        std::cerr << "Error: No source files provided.\n";
        return 1;
    }

    // Parse remaining flags
    std::string outputFile = "a.out";
    bool execFlag = false;
    while (argIndex < argc) {
        std::string arg = argv[argIndex];
        if (arg == "-S") {
            assemblyFlag = true;
            argIndex++;
        } else if (arg == "-o") {
            if (argIndex + 1 < argc) {
                outputFile = argv[argIndex + 1];
                argIndex += 2;
            } else {
                std::cerr << "Error: -o flag provided but no output file name given\n";
                return 1;
            }
        } else if (arg == "exec") {
            execFlag = true;
            argIndex++;
        } else {
            argIndex++;
        }
    }

    // Read and combine sources
    std::string combinedSource;
    for (const auto &file : sourceFiles) {
        if (file == "-") {
            std::stringstream buffer;
            buffer << std::cin.rdbuf();
            combinedSource += buffer.str() + "\n";
        } else {
            std::ifstream ifs(file);
            if (!ifs) {
                std::cerr << "Failed to open source file: " << file << "\n";
                return 1;
            }
            std::stringstream buffer;
            buffer << ifs.rdbuf();
            combinedSource += buffer.str() + "\n";
        }
    }

    try {
        Lexer lexer(combinedSource, sourceFiles.front());
        auto tokens = lexer.tokenize();
        Parser parser(tokens);
        ASTNode root = parser.parse();
        CodeGenerator codeGen(root);
        codeGen.generateBinary(outputFile, assemblyFlag);

        if (execFlag && !assemblyFlag) {
            std::cout << "[Executor] Running generated binary: " << outputFile << "\n";
            execBinary(outputFile);
        }
    } catch (const std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    return 0;
}
