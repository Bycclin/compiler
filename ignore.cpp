#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <cmath>
#include <cctype>
#include <stdexcept>
#include <iomanip>
#include <vector>
#include <set>
#include <algorithm>
#include <string>
#include <map>
#include "lexer.h"
#include "parser.h"
#include <exception>
#include <chrono>   // For debug timing

#ifdef __APPLE__
#include <unistd.h>  // for read on macOS and exec functions
#else
#include <unistd.h>
#include <sys/wait.h>
#endif

// The CodeGenerator produces ARM64 assembly code for our Python‑like language.
class CodeGenerator {
public:
    explicit CodeGenerator(const ASTNode &ast)
        : astRoot(ast), dataSection(""), functionSection(""), labelCounter(0),
          sysPathListGenerated(false)
    {
        // Add built-in names.
        definedNames.insert("print");
        definedNames.insert("input");
        definedNames.insert("int");
        definedNames.insert("ascii");
        definedNames.insert("exec");
    }

    // Generates the binary executable (or prints assembly if requested)
    void generateBinary(const std::string &outputFile, bool printAssembly);
    // Returns the complete assembly code as a string.
    std::string generateAssembly(const ASTNode &node, int indentLevel = 1, bool inFunction = false, const std::string &brkLabel = "");

private:
    ASTNode astRoot;
    std::string dataSection;
    std::string functionSection;
    int labelCounter;
    std::set<std::string> compiledModules;
    std::map<std::string, std::string> variableLabels; // Used for assignment storage.
    bool sysPathListGenerated;
    std::string sysPathListLabel;
    std::set<std::string> definedNames;  // Track defined variables and functions.

    std::string generateLabel(const std::string &prefix);
    std::string escapeString(const std::string &str);
    bool tryEvaluateArithmetic(const std::string &expr, std::string &result);
    bool evaluateArithmetic(const std::string &expr, std::string &result);
    double parseExpression(const char *&s);
    double parseTerm(const char *&s);
    double parseFactor(const char *&s);
    void skipWhitespace(const char *&s);
    std::string computeAscii(const std::string &input);
    bool tryEvaluateList(const std::string &expr, std::vector<long long> &result);
    std::string processFString(const std::string &fstr);
    std::string findPythonFolder();
    void compileModule(const std::string &moduleName);
    std::vector<std::string> getSysPaths();
    void generateSysPathList();
    std::string processLiteral(const std::string &token, bool inPrintContext) {
        if (token.empty())
            return token;
        if (std::isalpha(token.front())) {
            if (token.size() >= 2 && (token[1] == '\"' || token[1] == '\'')) {
                std::string content = token.substr(2, token.size() - 3);
                return inPrintContext ? content : ("\"" + content + "\"");
            }
        }
        if (token.front()=='\"' || token.front()=='\'') {
            std::string content = token.substr(1, token.size()-2);
            return inPrintContext ? content : ("\"" + content + "\"");
        }
        return token;
    }
    // Helper to load the absolute address of a symbol.
    std::string getAddress(const std::string &reg, const std::string &label) {
#ifdef __APPLE__
        std::ostringstream oss;
        oss << "    adrp " << reg << ", " << label << "@PAGE\n";
        oss << "    add  " << reg << ", " << reg << ", " << label << "@PAGEOFF\n";
        return oss.str();
#else
        std::ostringstream oss;
        oss << "    adrp " << reg << ", " << label << "@PAGE\n";
        oss << "    add  " << reg << ", " << reg << ", " << label << "@PAGEOFF\n";
        return oss.str();
#endif
    }

    std::string gotSection;          // (Unused now for our internal symbols)
    std::set<std::string> gotLabels;   // (Unused here)
};

std::string CodeGenerator::generateLabel(const std::string &prefix) {
    return prefix + "_" + std::to_string(labelCounter++);
}

std::string CodeGenerator::escapeString(const std::string &str) {
    std::string escaped;
    for (char c : str) {
        switch(c) {
            case '\"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\n': escaped += "\\n"; break;
            case '\t': escaped += "\\t"; break;
            default: escaped.push_back(c); break;
        }
    }
    return escaped;
}

bool CodeGenerator::tryEvaluateArithmetic(const std::string &expr, std::string &result) {
    return evaluateArithmetic(expr, result);
}

bool CodeGenerator::evaluateArithmetic(const std::string &expr, std::string &result) {
    const char *s = expr.c_str();
    try {
        skipWhitespace(s);
        double val = parseExpression(s);
        skipWhitespace(s);
        if (*s != '\0')
            return false;
        std::ostringstream oss;
        oss << val;
        result = oss.str();
        return true;
    } catch (...) {
        return false;
    }
}

double CodeGenerator::parseExpression(const char *&s) {
    double term = parseTerm(s);
    skipWhitespace(s);
    while (*s=='+' || *s=='-') {
        char op = *s; s++;
        double nextTerm = parseTerm(s);
        term = (op=='+' ? term + nextTerm : term - nextTerm);
        skipWhitespace(s);
    }
    return term;
}

double CodeGenerator::parseTerm(const char *&s) {
    double factor = parseFactor(s);
    skipWhitespace(s);
    while (*s=='*' || *s=='/') {
        char op = *s; s++;
        double nextFactor = parseFactor(s);
        if (op=='*')
            factor *= nextFactor;
        else {
            if (fabs(nextFactor)<1e-9)
                throw std::runtime_error("Division by zero");
            factor /= nextFactor;
        }
        skipWhitespace(s);
    }
    return factor;
}

double CodeGenerator::parseFactor(const char *&s) {
    skipWhitespace(s);
    if (*s == '(') {
        s++;
        double val = parseExpression(s);
        skipWhitespace(s);
        if (*s != ')')
            throw std::runtime_error("Missing closing parenthesis");
        s++;
        return val;
    } else {
        char *end;
        double val = strtod(s, &end);
        if (s == end)
            throw std::runtime_error("Invalid number");
        s = end;
        return val;
    }
}

void CodeGenerator::skipWhitespace(const char *&s) {
    while (*s && std::isspace(*s))
        s++;
}

std::string CodeGenerator::computeAscii(const std::string &input) {
    std::string output;
    size_t i = 0;
    while (i < input.size()) {
        unsigned char c = input[i];
        if (c < 128) {
            output.push_back(c);
            i++;
        } else {
            uint32_t codepoint = 0;
            int numBytes = 0;
            if ((c & 0xE0) == 0xC0) { codepoint = c & 0x1F; numBytes = 2; }
            else if ((c & 0xF0) == 0xE0) { codepoint = c & 0x0F; numBytes = 3; }
            else if ((c & 0xF8) == 0xF0) { codepoint = c & 0x07; numBytes = 4; }
            else { output += "?"; i++; continue; }
            if (i + numBytes > input.size()) break;
            for (int j = 1; j < numBytes; j++) {
                unsigned char nc = input[i+j];
                if ((nc & 0xC0) != 0x80) { codepoint = '?'; break; }
                codepoint = (codepoint << 6) | (nc & 0x3F);
            }
            i += numBytes;
            std::ostringstream oss;
            if (codepoint <= 0xFFFF)
                oss << "\\u" << std::setw(4) << std::setfill('0') << std::hex << codepoint;
            else
                oss << "\\U" << std::setw(8) << std::setfill('0') << std::hex << codepoint;
            output += oss.str();
        }
    }
    return output;
}

bool CodeGenerator::tryEvaluateList(const std::string &expr, std::vector<long long> &result) {
    result.clear();
    std::string s = expr;
    if (s.empty() || s.front() != '[' || s.back() != ']')
        return false;
    s = s.substr(1, s.size() - 2);
    std::istringstream iss(s);
    std::string token;
    while (std::getline(iss, token, ',')) {
        token.erase(token.begin(), std::find_if(token.begin(), token.end(), [](int ch) { return !std::isspace(ch); }));
        token.erase(std::find_if(token.rbegin(), token.rend(), [](int ch) { return !std::isspace(ch); }).base(), token.end());
        try {
            long long num = std::stoll(token);
            result.push_back(num);
        } catch (...) {
            return false;
        }
    }
    return true;
}

std::string CodeGenerator::processFString(const std::string &fstr) {
    if (fstr.size() < 3)
        return fstr;
    char quote = fstr[1];
    if (quote != '"' && quote != '\'')
        return fstr;
    std::string inner = fstr.substr(2, fstr.size() - 3);
    std::string output;
    size_t pos = 0;
    while (pos < inner.size()) {
        if (inner[pos] == '{') {
            size_t endPos = inner.find('}', pos);
            if (endPos == std::string::npos) {
                output += inner.substr(pos);
                break;
            }
            std::string expr = inner.substr(pos + 1, endPos - pos - 1);
            std::string evaluated;
            if (tryEvaluateArithmetic(expr, evaluated))
                output += evaluated;
            else
                output += "{" + expr + "}";
            pos = endPos + 1;
        } else {
            output.push_back(inner[pos]);
            pos++;
        }
    }
    return output;
}

std::string CodeGenerator::findPythonFolder() {
    return "/Library/Frameworks/Python.framework/Versions/3.13/lib/python3.13";
}

void CodeGenerator::compileModule(const std::string &moduleName) {
    if (moduleName == "sys")
        return;
    if (compiledModules.find(moduleName) != compiledModules.end())
        return;
    compiledModules.insert(moduleName);
    std::vector<std::string> sysPaths = getSysPaths();
    std::string moduleFilePath;
    for (const std::string &dir : sysPaths) {
        std::string path = dir + "/" + moduleName + ".py";
        std::ifstream moduleFile(path);
        if (moduleFile.good()) {
            moduleFilePath = path;
            break;
        }
    }
    if (moduleFilePath.empty()) {
        std::cerr << "[Warning] Module " << moduleName << " not found in sys.path.\n";
        return;
    }
    std::ifstream ifs(moduleFilePath);
    if (!ifs)
        throw std::runtime_error("Failed to open module file: " + moduleFilePath);
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    std::string source = buffer.str();
    Lexer moduleLexer(source, moduleFilePath);
    std::vector<Token> moduleTokens = moduleLexer.tokenize();
    Parser moduleParser(moduleTokens);
    ASTNode moduleAST = moduleParser.parse();
    std::string moduleAssembly = generateAssembly(moduleAST);
    functionSection += "\n// Module " + moduleName + "\n" + moduleAssembly;
}

std::vector<std::string> CodeGenerator::getSysPaths() {
    std::vector<std::string> sysPaths;
    std::string pythonFolder = findPythonFolder();
    sysPaths.push_back(pythonFolder);
    sysPaths.push_back(pythonFolder + "/lib-dynload");
    sysPaths.push_back(pythonFolder + "/site-packages");
    return sysPaths;
}

void CodeGenerator::generateSysPathList() {
    if (sysPathListGenerated)
        return;
    std::vector<std::string> paths = getSysPaths();
    std::vector<std::string> itemLabels;
    for (size_t i = 0; i < paths.size(); i++) {
        std::string label = generateLabel("sys_path_item");
        dataSection += label + ": .asciz \"" + escapeString(paths[i]) + "\"\n";
        itemLabels.push_back(label);
    }
    sysPathListLabel = "sys_path_list";
    std::string listDef = sysPathListLabel + ":\n";
    for (const auto &lbl : itemLabels) {
        listDef += "    .quad " + lbl + "\n";
    }
    listDef += "    .quad 0\n";
    dataSection += listDef;
    sysPathListGenerated = true;
}

// ARM64 assembly generation for AST nodes (converted from x86_64 code)
std::string CodeGenerator::generateAssembly(const ASTNode &node, int indentLevel, bool inFunction, const std::string &brkLabel) {
    std::stringstream ss;
    std::string indent(indentLevel * 4, ' ');
    if (node.type == "Program") {
        for (const auto &child : node.children)
            ss << generateAssembly(child, indentLevel, false, brkLabel);
    }
    else if (node.type == "Assignment") {
        std::string rhsCode = generateAssembly(node.children[0], indentLevel, inFunction, brkLabel);
        if (variableLabels.find(node.value) == variableLabels.end()) {
            std::string varLabel = generateLabel("var_" + node.value);
            variableLabels[node.value] = varLabel;
            dataSection += varLabel + ": .quad 0\n";
        }
        ss << rhsCode;
        ss << getAddress("x1", variableLabels[node.value]);
        ss << indent << "str x0, [x1]\n";
        ss << getAddress("x0", variableLabels[node.value]);
        ss << indent << "ldr x0, [x0]\n";
    }
    else if (node.type == "Identifier") {
        if (variableLabels.find(node.value) == variableLabels.end())
            throw std::runtime_error("Name \"" + node.value + "\" is not defined.");
        ss << getAddress("x0", variableLabels[node.value]);
        ss << indent << "ldr x0, [x0]\n";
    }
    else if (node.type == "Boolean") {
        if (node.value == "True")
            ss << indent << "mov x0, #1\n";
        else
            ss << indent << "mov x0, #0\n";
    }
    else if (node.type == "While" || node.type == "while") {
        if (node.children.size() < 2)
            return indent + "mov x0, #0\n";
        std::string condLabel = generateLabel("while_cond");
        std::string endLabel = generateLabel("while_end");
        ss << condLabel << ":\n";
        ss << generateAssembly(node.children[0], indentLevel + 1, inFunction, brkLabel);
        ss << indent << "cmp x0, #0\n";
        ss << indent << "beq " << endLabel << "\n";
        ss << generateAssembly(node.children[1], indentLevel + 1, inFunction, endLabel);
        ss << indent << "b " << condLabel << "\n";
        ss << endLabel << ":\n";
        ss << indent << "mov x0, #0\n";
    }
    else if (node.type == "If") {
        if (node.children.size() == 2) {
            std::string falseLabel = generateLabel("if_false");
            std::string endLabel = generateLabel("if_end");
            ss << generateAssembly(node.children[0], indentLevel + 1, inFunction, brkLabel);
            ss << indent << "cmp x0, #0\n";
            ss << indent << "beq " << falseLabel << "\n";
            ss << generateAssembly(node.children[1], indentLevel + 1, inFunction, brkLabel);
            ss << indent << "b " << endLabel << "\n";
            ss << falseLabel << ":\n";
            ss << endLabel << ":\n";
            ss << indent << "mov x0, #0\n";
        }
        else if (node.children.size() == 3) {
            std::string falseLabel = generateLabel("if_false");
            std::string endLabel = generateLabel("if_end");
            ss << generateAssembly(node.children[0], indentLevel + 1, inFunction, brkLabel);
            ss << indent << "cmp x0, #0\n";
            ss << indent << "beq " << falseLabel << "\n";
            ss << generateAssembly(node.children[1], indentLevel + 1, inFunction, brkLabel);
            ss << indent << "b " << endLabel << "\n";
            ss << falseLabel << ":\n";
            ss << generateAssembly(node.children[2], indentLevel + 1, inFunction, brkLabel);
            ss << endLabel << ":\n";
            ss << indent << "mov x0, #0\n";
        } else {
            ss << indent << "mov x0, #0\n";
        }
    }
    else if (node.type == "Unsupported" && node.value == "break") {
        if (!brkLabel.empty())
            ss << indent << "b " << brkLabel << "\n";
        else
            ss << indent << "mov x0, #0\n";
    }
    else if (node.type == "FunctionCall" && node.value == "input") {
        if (!node.children.empty()) {
            std::string prompt = processLiteral(node.children[0].value, true);
            std::string label = generateLabel("prompt");
            dataSection += label + ": .asciz \"" + escapeString(prompt) + "\"\n";
            ss << getAddress("x0", label);
            ss << indent << "bl _print_string\n";
        }
        ss << indent << "bl _input\n";
    }
    else if (node.type == "FunctionCall" && node.value == "print") {
        std::vector<ASTNode> positionalArgs;
        std::string endValue = "\n";
        for (const auto &child : node.children) {
            if (child.type == "KeywordArgument" && child.value == "end")
                endValue = processLiteral(child.children[0].value, true);
            else
                positionalArgs.push_back(child);
        }
        for (const auto &arg : positionalArgs) {
            if (!arg.value.empty() && (arg.value.front() == '"' || arg.value.front() == '\'')) {
                std::string text = processLiteral(arg.value, true);
                std::string label = generateLabel("print_arg");
                dataSection += label + ": .asciz \"" + escapeString(text) + "\"\n";
                ss << getAddress("x0", label);
                ss << indent << "bl _print_string\n";
            } else {
                ss << generateAssembly(arg, indentLevel, inFunction, brkLabel);
                ss << indent << "bl _print_string\n";
            }
        }
        std::string endLabel = generateLabel("print_end");
        dataSection += endLabel + ": .asciz \"" + escapeString(endValue) + "\"\n";
        ss << getAddress("x0", endLabel);
        ss << indent << "bl _print_string\n";
        ss << indent << "mov x0, #0\n";
    }
    else if (node.type == "FunctionCall" && node.value == "int") {
        if (node.children.empty())
            throw std::runtime_error("int() requires an argument.");
        ss << generateAssembly(node.children[0], indentLevel, inFunction, brkLabel);
        ss << indent << "bl _atoi\n";
    }
    else if (node.type == "FunctionCall") {
        throw std::runtime_error("Function \"" + node.value + "\" is not defined.");
    }
    else {
        ss << indent << "mov x0, #0\n";
    }
    return ss.str();
}

void CodeGenerator::generateBinary(const std::string &outputFile, bool printAssembly) {
    std::cout << "[CodeGenerator] Generating binary to: " << outputFile << "\n";
    auto t0 = std::chrono::steady_clock::now();
    std::string mainCode = generateAssembly(astRoot);
    auto t1 = std::chrono::steady_clock::now();
    std::chrono::duration<double> genAsmTime = t1 - t0;
    std::cout << "[DEBUG] Assembly generation took: " << genAsmTime.count() << " seconds.\n";
    
    // Build final assembly string using a large preallocated buffer
    std::string finalAsm;
    finalAsm.reserve(1000000);
    finalAsm.append(".section __DATA,__const\n");
    finalAsm.append(gotSection);
    finalAsm.append(".section __DATA,__data\n");
    finalAsm.append("_input_buffer: .space 256\n");
    finalAsm.append(dataSection);
    finalAsm.append("\n.section __TEXT,__text,regular,pure_instructions\n");
    finalAsm.append(".globl _start\n");
    finalAsm.append("_start:\n");
    finalAsm.append("    // Debug stub (if needed)\n");
    finalAsm.append(mainCode);
    finalAsm.append("\n");
    finalAsm.append(functionSection);
    finalAsm.append("\n    mov x0, #0\n    bl _exit\n");
    
    finalAsm.append("\n.globl _print_string\n");
    finalAsm.append("_print_string:\n"
                     "    stp x29, x30, [sp, #-16]!\n"
                     "    mov x29, sp\n"
                     "    mov x4, x0\n"
                     "    mov x1, x0\n"
                     "    mov x2, #0\n"
                     ".find_length_arm:\n"
                     "    ldrb w3, [x1], #1\n"
                     "    cbz w3, .length_found\n"
                     "    add x2, x2, #1\n"
                     "    b .find_length_arm\n"
                     ".length_found:\n"
                     "    mov x1, x4\n"
                     "    mov x0, #1\n"
                     "    bl _write\n"
                     "    ldp x29, x30, [sp], #16\n"
                     "    ret\n");
    
    finalAsm.append("\n.globl _input\n");
    finalAsm.append("_input:\n"
                     "    stp x29, x30, [sp, #-16]!\n"
                     "    mov x29, sp\n");
    finalAsm.append(getAddress("x1", "_input_buffer"));
    finalAsm.append("    mov x2, #256\n"
                     "    mov x0, #0\n"
                     "    bl _read\n"
                     "    ldp x29, x30, [sp], #16\n"
                     "    ret\n");
    
    finalAsm.append("\n.globl _atoi\n");
    finalAsm.append("_atoi:\n"
                     "    stp x29, x30, [sp, #-16]!\n"
                     "    mov x29, sp\n"
                     "    mov x1, x0\n"
                     "    mov x0, #0\n"
                     "    mov x2, #10\n"
                     "atoi_loop:\n"
                     "    ldrb w3, [x1], #1\n"
                     "    cmp w3, #0\n"
                     "    beq atoi_done\n"
                     "    sub w3, w3, #48\n"
                     "    mul x0, x0, x2\n"
                     "    add x0, x0, w3, uxtw\n"
                     "    b atoi_loop\n"
                     "atoi_done:\n"
                     "    ldp x29, x30, [sp], #16\n"
                     "    ret\n");
    
    finalAsm.append("\n.globl _exit\n");
    finalAsm.append("_exit:\n"
#ifdef __APPLE__
                     "    mov x0, #0\n    mov x16, #1\n    svc #0\n");
#else
                     "    mov x0, #0\n    svc #0\n");
#endif

    // If the flag is set, print the final assembly and exit.
    if (printAssembly) {
        std::cout << finalAsm;
        std::cout << "[DEBUG] Assembly output printed. Exiting without linking.\n";
        return;
    }

    std::string assemblyFile = outputFile + ".s";
    std::ofstream asm_ofs(assemblyFile);
    if (!asm_ofs)
        throw std::runtime_error("Failed to open assembly file for writing.");
    asm_ofs << finalAsm;
    asm_ofs.close();
#ifdef __APPLE__
    std::string compileCommand = "clang " + assemblyFile + " -o " + outputFile + " -e _start -no-integrated-as -lc -fPIE";
#else
    std::string compileCommand = "clang " + assemblyFile + " -o " + outputFile + " -e _start -no-integrated-as -lc";
#endif
    std::cout << "[Compiler] Running: " << compileCommand << "\n";
    auto t2 = std::chrono::steady_clock::now();
    if (std::system(compileCommand.c_str()) != 0)
        throw std::runtime_error("Compilation (clang linking) failed.");
    auto t3 = std::chrono::steady_clock::now();
    std::chrono::duration<double> compileTime = t3 - t2;
    std::cout << "[DEBUG] Linking took: " << compileTime.count() << " seconds.\n";
    
    std::remove(assemblyFile.c_str());
    std::cout << "[CodeGenerator] Binary executable generated: " << outputFile << "\n";
}

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
    using clock = std::chrono::steady_clock;
    auto overall_start = clock::now();

    if (argc < 2) {
        std::cerr << "Usage: ./compile <source_files> [-o output_file] [exec] [--print-asm]\n";
        return 1;
    }
    
    bool printAssembly = false; // New flag: if true, print assembly instead of linking.

    // Gather source files until we encounter "-o", "exec", or "--print-asm"
    std::vector<std::string> sourceFiles;
    int argIndex = 1;
    while (argIndex < argc &&
           std::string(argv[argIndex]) != "-o" &&
           std::string(argv[argIndex]) != "exec" &&
           std::string(argv[argIndex]) != "--print-asm") {
        sourceFiles.push_back(argv[argIndex]);
        argIndex++;
    }
    
    if (sourceFiles.empty()) {
        std::cerr << "Error: No source files provided.\n";
        return 1;
    }
    
    // Combine all source files into one source string.
    auto t0 = clock::now();
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
    auto t1 = clock::now();
    std::chrono::duration<double> readTime = t1 - t0;
    std::cout << "[DEBUG] Reading source files took: " << readTime.count() << " seconds.\n";
    
    // Process remaining command-line arguments.
    std::string outputFile = "a.out";
    bool execFlag = false;
    while (argIndex < argc) {
        std::string arg = argv[argIndex];
        if (arg == "-o") {
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
        } else if (arg == "--print-asm") {
            printAssembly = true;
            argIndex++;
        } else {
            argIndex++;
        }
    }
    
    // Use the first source file's name for error messages.
    std::string sourceFilename = sourceFiles.empty() ? "stdin" : sourceFiles[0];

    auto t2 = clock::now();
    Lexer lexer(combinedSource, sourceFilename);
    std::vector<Token> tokens = lexer.tokenize();
    auto t3 = clock::now();
    std::chrono::duration<double> tokenizeTime = t3 - t2;
    std::cout << "[DEBUG] Tokenization took: " << tokenizeTime.count() << " seconds.\n";
    
    auto t4 = clock::now();
    Parser parser(tokens);
    ASTNode root = parser.parse();
    auto t5 = clock::now();
    std::chrono::duration<double> parseTime = t5 - t4;
    std::cout << "[DEBUG] Parsing took: " << parseTime.count() << " seconds.\n";
    
    CodeGenerator codeGen(root);
    codeGen.generateBinary(outputFile, printAssembly);
    
    auto overall_end = clock::now();
    std::chrono::duration<double> overallTime = overall_end - overall_start;
    std::cout << "[DEBUG] Total compilation time: " << overallTime.count() << " seconds.\n";
    
    if (execFlag && !printAssembly) {
        std::cout << "[Executor] Running generated binary: " << outputFile << "\n";
        execBinary(outputFile);
    }
    return 0;
}
