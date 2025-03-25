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
#ifdef __APPLE__
#include <unistd.h>  // for read on macOS and exec functions
#else
#include <unistd.h>
#include <sys/wait.h>
#endif

// The CodeGenerator produces assembly code for our Python‑like language.
// An extra parameter (brkLabel) propagates the current loop break label.
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

    void generateBinary(const std::string &outputFile);
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
                std::string content = token.substr(2, token.size()-3);
                return inPrintContext ? content : ("\"" + content + "\"");
            }
        }
        if (token.front() == '\"' || token.front() == '\'') {
            std::string content = token.substr(1, token.size()-2);
            return inPrintContext ? content : ("\"" + content + "\"");
        }
        return token;
    }
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
        if (*s != '\0') return false;
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
    while (*s == '+' || *s == '-') {
        char op = *s; s++;
        double nextTerm = parseTerm(s);
        term = (op == '+') ? term + nextTerm : term - nextTerm;
        skipWhitespace(s);
    }
    return term;
}

double CodeGenerator::parseTerm(const char *&s) {
    double factor = parseFactor(s);
    skipWhitespace(s);
    while (*s == '*' || *s == '/') {
        char op = *s; s++;
        double nextFactor = parseFactor(s);
        if (op == '*') factor *= nextFactor;
        else {
            if (fabs(nextFactor) < 1e-9)
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
    s = s.substr(1, s.size()-2);
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
    if (fstr.size() < 3) return fstr;
    char quote = fstr[1];
    if (quote != '"' && quote != '\'') return fstr;
    std::string inner = fstr.substr(2, fstr.size()-3);
    std::string output;
    size_t pos = 0;
    while (pos < inner.size()) {
        if (inner[pos] == '{') {
            size_t endPos = inner.find('}', pos);
            if (endPos == std::string::npos) {
                output += inner.substr(pos);
                break;
            }
            std::string expr = inner.substr(pos+1, endPos-pos-1);
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

// Updated generateAssembly:
// - For "Assignment": Evaluates the RHS expression, stores the result into the variable’s memory slot,
//   and then reloads the value into %rax so that the assignment expression returns the assigned value.
// - For "Identifier": Loads the variable's value from its memory slot.
std::string CodeGenerator::generateAssembly(const ASTNode &node, int indentLevel, bool inFunction, const std::string &brkLabel) {
    std::stringstream ss;
    std::string indent(indentLevel * 4, ' ');
    
    if (node.type == "Program") {
        for (const auto &child : node.children)
            ss << generateAssembly(child, indentLevel, false, brkLabel);
    }
    // Handle assignments: evaluate RHS and store the result in a variable.
    else if (node.type == "Assignment") {
        std::string rhsCode = generateAssembly(node.children[0], indentLevel, inFunction, brkLabel);
        // If this variable hasn't been assigned before, allocate storage.
        if (variableLabels.find(node.value) == variableLabels.end()) {
            std::string varLabel = generateLabel("var_" + node.value);
            variableLabels[node.value] = varLabel;
            dataSection += varLabel + ": .quad 0\n";
        }
        ss << rhsCode;
        ss << indent << "movq %rax, " << variableLabels[node.value] << "(%rip)\n";
        // Reload the value into %rax so that the assignment expression returns the assigned value.
        ss << indent << "movq " << variableLabels[node.value] << "(%rip), %rax\n";
        return ss.str();
    }
    // When an identifier is encountered, load its value from memory.
    else if (node.type == "Identifier") {
        if (variableLabels.find(node.value) == variableLabels.end())
            throw std::runtime_error("Name \"" + node.value + "\" is not defined.");
        ss << indent << "movq " << variableLabels[node.value] << "(%rip), %rax\n";
        return ss.str();
    }
    // Handle Boolean literals.
    else if (node.type == "Boolean") {
        if (node.value == "True")
            ss << indent << "movq $1, %rax\n";
        else
            ss << indent << "movq $0, %rax\n";
        return ss.str();
    }
    // Handle while loops.
    else if (node.type == "While") {
        std::string condLabel = generateLabel("while_cond");
        std::string endLabel = generateLabel("while_end");
        ss << condLabel << ":\n";
        ss << generateAssembly(node.children[0], indentLevel + 1, inFunction, brkLabel); // Condition
        ss << indent << "cmpq $0, %rax\n";
        ss << indent << "je " << endLabel << "\n";
        ss << generateAssembly(node.children[1], indentLevel + 1, inFunction, brkLabel); // Loop body
        ss << indent << "jmp " << condLabel << "\n";
        ss << endLabel << ":\n";
        return ss.str();
    }
    // Handle built-in input function.
    else if (node.type == "FunctionCall" && node.value == "input") {
        if (!node.children.empty()) {
            std::string prompt = processLiteral(node.children[0].value, true);
            std::string label = generateLabel("prompt");
            dataSection += label + ": .asciz \"" + escapeString(prompt) + "\"\n";
            ss << indent << "leaq " << label << "(%rip), %rdi\n"
               << indent << "call _print_string\n";
        }
        ss << indent << "call _input\n";
        return ss.str();
    }
    // Handle built-in print function with default end parameter.
    else if (node.type == "FunctionCall" && node.value == "print") {
        std::vector<ASTNode> positionalArgs;
        std::string endValue = "\n"; // default end is newline
        for (const auto &child : node.children) {
            if (child.type == "KeywordArgument" && child.value == "end") {
                endValue = processLiteral(child.children[0].value, true);
            } else {
                positionalArgs.push_back(child);
            }
        }
        // Process each positional argument.
        for (const auto &arg : positionalArgs) {
            if (arg.value == "input()") {
                ASTNode inputCall("FunctionCall", "input", {});
                ss << generateAssembly(inputCall, indentLevel, inFunction, brkLabel);
            } else if (arg.type == "FunctionCall") {
                ss << generateAssembly(arg, indentLevel, inFunction, brkLabel);
            }
            else {
                std::string text;
                if (!arg.value.empty() && (arg.value[0] == '"' || arg.value[0] == '\'')) {
                    text = processLiteral(arg.value, true);
                } else {
                    if (definedNames.find(arg.value) == definedNames.end())
                        throw std::runtime_error("Name \"" + arg.value + "\" is not defined.");
                    text = arg.value;
                }
                std::string label = generateLabel("print_arg");
                dataSection += label + ": .asciz \"" + escapeString(text) + "\"\n";
                ss << indent << "leaq " << label << "(%rip), %rdi\n"
                   << indent << "call _print_string\n";
            }
        }
        std::string endLabel = generateLabel("print_end");
        dataSection += endLabel + ": .asciz \"" + escapeString(endValue) + "\"\n";
        ss << indent << "leaq " << endLabel << "(%rip), %rdi\n"
           << indent << "call _print_string\n";
        return ss.str();
    }
    // Handle built-in int function.
    else if (node.type == "FunctionCall" && node.value == "int") {
        if (node.children.empty())
            throw std::runtime_error("int() requires an argument.");
        ss << generateAssembly(node.children[0], indentLevel, inFunction, brkLabel);
        ss << indent << "movq %rax, %rdi\n";
        ss << indent << "call _atoi\n";
        return ss.str();
    }
    // For any FunctionCall not handled above, raise an error.
    else if (node.type == "FunctionCall") {
        throw std::runtime_error("Function \"" + node.value + "\" is not defined.");
    }
    else {
        // For other nodes, no assembly is generated.
        return "";
    }
    return ss.str();
}

void CodeGenerator::generateBinary(const std::string &outputFile) {
    std::cout << "[CodeGenerator] Generating binary to: " << outputFile << "\n";
    std::string mainCode = generateAssembly(astRoot);
    std::string textCode = mainCode;
    std::string preText = "    leaq _debug(%rip), %rdi\n"
                          "    call _print_string\n";
    textCode = preText + textCode;
    
    std::stringstream finalAsm;
#if defined(__APPLE__) || defined(__MACH__)
    finalAsm << ".section __DATA,__data\n";
#else
    finalAsm << ".data\n";
#endif
    finalAsm << "_debug: .asciz \"DEBUG: _start entered\\n\"\n";
    // Reserve 1025 bytes: 1024 for data plus one for the null terminator.
    finalAsm << "_input_buffer: .space 1025\n";
    finalAsm << dataSection << "\n";
#if defined(__APPLE__) || defined(__MACH__)
    finalAsm << ".section __TEXT,__text,regular,pure_instructions\n";
#else
    finalAsm << ".text\n";
#endif
    finalAsm << ".globl _start\n";
    finalAsm << "_start:\n";
    // Adjust stack pointer for proper alignment.
    finalAsm << "    subq $8, %rsp\n";
    finalAsm << textCode << "\n";
    finalAsm << functionSection << "\n";
    // Added call to _exit to ensure the program terminates properly.
    finalAsm << "    call _exit\n";
    
    // _print_string definition.
    finalAsm << "\n.globl _print_string\n";
    finalAsm << "_print_string:\n"
             "    pushq %rbp\n"
             "    movq %rsp, %rbp\n"
             "    movq %rdi, %r8\n"
             "    xorq %rcx, %rcx\n"
             ".print_string_loop:\n"
             "    cmpb $0, (%rdi)\n"
             "    je .print_string_done\n"
             "    incq %rcx\n"
             "    incq %rdi\n"
             "    jmp .print_string_loop\n"
             ".print_string_done:\n";
#if defined(__APPLE__) || defined(__MACH__)
    finalAsm << "    movq $0x2000004, %rax\n";
#else
    finalAsm << "    movq $1, %rax\n";
#endif
    finalAsm << "    movq $1, %rdi\n"
             "    movq %r8, %rsi\n"
             "    movq %rcx, %rdx\n"
             "    syscall\n"
             "    popq %rbp\n"
             "    ret\n";
    
    // _input definition.
    finalAsm << "\n.globl _input\n";
    finalAsm << "_input:\n"
             "    pushq %rbp\n"
             "    movq %rsp, %rbp\n";
#if defined(__APPLE__) || defined(__MACH__)
    finalAsm << "    movq $0, %rdi\n"
             "    leaq _input_buffer(%rip), %rsi\n"
             "    movq $1024, %rdx\n"
             "    movq $0x2000003, %rax\n"
             "    syscall\n";
#else
    finalAsm << "    movq $0, %rdi\n"
             "    leaq _input_buffer(%rip), %rsi\n"
             "    movq $1024, %rdx\n"
             "    movq $0, %rax\n"
             "    syscall\n";
#endif
    finalAsm << "    testq %rax, %rax\n"
             "    js .read_error\n"
             "    movq %rax, %rcx\n"
             "    leaq _input_buffer(%rip), %rdx\n"
             "    addq %rcx, %rdx\n"
             "    movb $0, (%rdx)\n"
             "    leaq _input_buffer(%rip), %rax\n"
             "    popq %rbp\n"
             "    ret\n"
             ".read_error:\n"
             "    leaq _input_buffer(%rip), %rax\n"
             "    movb $0, (%rax)\n"
             "    popq %rbp\n"
             "    ret\n";
    
    // _atoi definition.
    finalAsm << "\n.globl _atoi\n";
    finalAsm << "_atoi:\n"
             "    pushq %rbp\n"
             "    movq %rsp, %rbp\n"
             "    movq $0, %rax\n"
             "    movq %rdi, %rcx\n"
             "atoi_loop:\n"
             "    movzbq (%rcx), %rdx\n"
             "    cmpb $0, %dl\n"
             "    je atoi_done\n"
             "    cmpb $'0', %dl\n"
             "    jb atoi_done\n"
             "    cmpb $'9', %dl\n"
             "    ja atoi_done\n"
             "    subb $'0', %dl\n"
             "    imulq $10, %rax, %rax\n"
             "    addq %rdx, %rax\n"
             "    incq %rcx\n"
             "    jmp atoi_loop\n"
             "atoi_done:\n"
             "    popq %rbp\n"
             "    ret\n";
    
    // _exec definition.
    finalAsm << "\n.globl _exec\n";
    finalAsm << "_exec:\n";
#if defined(__APPLE__) || defined(__MACH__)
    finalAsm << "    pushq %rbp\n"
             "    movq %rsp, %rbp\n"
             "    call _system\n"
             "    popq %rbp\n"
             "    ret\n";
#else
    finalAsm << "    pushq %rbp\n"
             "    movq %rsp, %rbp\n"
             "    call system\n"
             "    popq %rbp\n"
             "    ret\n";
#endif
    
    // _exit definition.
#if defined(__APPLE__) || defined(__MACH__)
    finalAsm << "\n.globl _exit\n";
    finalAsm << "_exit:\n"
             "    movq $0x2000001, %rax\n"
             "    movq $0, %rdi\n"
             "    syscall\n";
#else
    finalAsm << "\n.globl _exit\n";
    finalAsm << "_exit:\n"
             "    movq $60, %rax\n"
             "    movq $0, %rdi\n"
             "    syscall\n";
#endif

    std::string assemblyCode = finalAsm.str();
    std::string assemblyFile = outputFile + ".s";
    std::ofstream asm_ofs(assemblyFile);
    if (!asm_ofs)
        throw std::runtime_error("Failed to open assembly file for writing.");
    asm_ofs << assemblyCode;
    asm_ofs.close();
    std::string compileCommand = "clang " + assemblyFile + " -o " + outputFile + " -no-pie -e _start";
#ifdef __APPLE__
    compileCommand += " -lc";
#endif
    std::cout << "[Compiler] Running: " << compileCommand << "\n";
    if (std::system(compileCommand.c_str()) != 0)
        throw std::runtime_error("Compilation (clang linking) failed.");
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
    if (argc < 2) {
        std::cerr << "Usage: ./compile <source_file> [-o output_file] [exec]\n";
        return 1;
    }

    std::string source;
    std::string sourceFile = argv[1];

    // Read from standard input if source file is "-"
    if (sourceFile == "-") {
        std::stringstream buffer;
        buffer << std::cin.rdbuf();
        source = buffer.str();
    } else {
        std::ifstream ifs(sourceFile);
        if (!ifs) {
            std::cerr << "Failed to open source file: " << sourceFile << "\n";
            return 1;
        }
        std::stringstream buffer;
        buffer << ifs.rdbuf();
        source = buffer.str();
    }

    // Parse command-line arguments for output file and exec flag.
    std::string outputFile = "a.out";
    bool execFlag = false;
    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-o") {
            if (i + 1 < argc) {
                outputFile = argv[i + 1];
                i++; // Skip next argument as it is the output file name.
            } else {
                std::cerr << "Error: -o flag provided but no output file name given\n";
                return 1;
            }
        } else if (arg == "exec") {
            execFlag = true;
        } else {
            // Unknown flags are ignored.
        }
    }

    Lexer lexer(source, sourceFile);
    std::vector<Token> tokens = lexer.tokenize();
    Parser parser(tokens);
    ASTNode root = parser.parse();
    CodeGenerator codeGen(root);
    try {
        codeGen.generateBinary(outputFile);
    } catch (const std::exception &ex) {
        std::cerr << "compile: \033[1;31merror:\033[0;1m " << ex.what() << "\033[0m\n";
        return 1;
    }
    if (execFlag) {
        std::cout << "[Executor] Running generated binary: " << outputFile << "\n";
        execBinary(outputFile);
    }
    return 0;
}
