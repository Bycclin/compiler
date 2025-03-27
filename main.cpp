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

// Updated generateAssembly with added support for if statements and break,
// and crucially, we now check for both "While" and "while" for while loops.
std::string CodeGenerator::generateAssembly(const ASTNode &node, int indentLevel, bool inFunction, const std::string &brkLabel) {
    std::cerr << "[DEBUG] generateAssembly called for node type: " << node.type << ", value: " << node.value << std::endl;
    std::stringstream ss;
    std::string indent(indentLevel * 4, ' ');
    
    if (node.type == "Program") {
        for (const auto &child : node.children)
            ss << generateAssembly(child, indentLevel, false, brkLabel);
    }
    // Handle assignments.
    else if (node.type == "Assignment") {
        std::string rhsCode = generateAssembly(node.children[0], indentLevel, inFunction, brkLabel);
        if (variableLabels.find(node.value) == variableLabels.end()) {
            std::string varLabel = generateLabel("var_" + node.value);
            variableLabels[node.value] = varLabel;
            dataSection += varLabel + ": .quad 0\n";
        }
        ss << rhsCode;
        ss << indent << "movq %rax, " << variableLabels[node.value] << "(%rip)\n";
        ss << indent << "movq " << variableLabels[node.value] << "(%rip), %rax\n";
        std::cerr << "[DEBUG] Assignment node generated assembly: " << ss.str() << std::endl;
        return ss.str();
    }
    // Handle identifiers.
    else if (node.type == "Identifier") {
        if (variableLabels.find(node.value) == variableLabels.end())
            throw std::runtime_error("Name \"" + node.value + "\" is not defined.");
        ss << indent << "movq " << variableLabels[node.value] << "(%rip), %rax\n";
        std::cerr << "[DEBUG] Identifier node generated assembly: " << ss.str() << std::endl;
        return ss.str();
    }
    // Handle boolean literals.
    else if (node.type == "Boolean") {
        if (node.value == "True")
            ss << indent << "movq $1, %rax\n";
        else
            ss << indent << "movq $0, %rax\n";
        std::cerr << "[DEBUG] Boolean node generated assembly: " << ss.str() << std::endl;
        return ss.str();
    }
    // Handle while loops (check for both "While" and "while").
    else if (node.type == "While" || node.type == "while") {
        if (node.children.size() < 2) {
            std::cerr << "[DEBUG] While node missing children; generating empty loop.\n";
            return indent + "movq $0, %rax\n";
        }
        std::string condLabel = generateLabel("while_cond");
        std::string endLabel = generateLabel("while_end");
        ss << condLabel << ":\n";
        ss << generateAssembly(node.children[0], indentLevel + 1, inFunction, brkLabel); // Condition
        ss << indent << "cmpq $0, %rax\n";
        ss << indent << "je " << endLabel << "\n";
        // Pass the end label as the break label to the loop body.
        ss << generateAssembly(node.children[1], indentLevel + 1, inFunction, endLabel);
        ss << indent << "jmp " << condLabel << "\n";
        ss << endLabel << ":\n";
        ss << indent << "movq $0, %rax\n"; // Return None
        std::cerr << "[DEBUG] While node generated assembly: " << ss.str() << std::endl;
        return ss.str();
    }
    // Handle if statements.
    else if (node.type == "If") {
        if (node.children.size() == 2) {
            std::string falseLabel = generateLabel("if_false");
            std::string endLabel = generateLabel("if_end");
            ss << generateAssembly(node.children[0], indentLevel + 1, inFunction, brkLabel);
            ss << indent << "cmpq $0, %rax\n";
            ss << indent << "je " << falseLabel << "\n";
            ss << generateAssembly(node.children[1], indentLevel + 1, inFunction, brkLabel);
            ss << indent << "jmp " << endLabel << "\n";
            ss << falseLabel << ":\n";
            ss << endLabel << ":\n";
            ss << indent << "movq $0, %rax\n";
            std::cerr << "[DEBUG] If node (2 children) generated assembly: " << ss.str() << std::endl;
            return ss.str();
        }
        else if (node.children.size() == 3) {
            std::string falseLabel = generateLabel("if_false");
            std::string endLabel = generateLabel("if_end");
            ss << generateAssembly(node.children[0], indentLevel + 1, inFunction, brkLabel);
            ss << indent << "cmpq $0, %rax\n";
            ss << indent << "je " << falseLabel << "\n";
            ss << generateAssembly(node.children[1], indentLevel + 1, inFunction, brkLabel);
            ss << indent << "jmp " << endLabel << "\n";
            ss << falseLabel << ":\n";
            ss << generateAssembly(node.children[2], indentLevel + 1, inFunction, brkLabel);
            ss << endLabel << ":\n";
            ss << indent << "movq $0, %rax\n";
            std::cerr << "[DEBUG] If node (3 children) generated assembly: " << ss.str() << std::endl;
            return ss.str();
        }
        else {
            ss << indent << "movq $0, %rax\n";
            return ss.str();
        }
    }
    // Support break statements.
    else if (node.type == "Unsupported" && node.value == "break") {
        if (!brkLabel.empty())
            return indent + "jmp " + brkLabel + "\n";
        else
            return indent + "movq $0, %rax\n";
    }
    // Built-in input.
    else if (node.type == "FunctionCall" && node.value == "input") {
        if (!node.children.empty()) {
            std::string prompt = processLiteral(node.children[0].value, true);
            std::string label = generateLabel("prompt");
            dataSection += label + ": .asciz \"" + escapeString(prompt) + "\"\n";
            ss << indent << "leaq " << label << "(%rip), %rdi\n"
               << indent << "call _print_string\n";
        }
        ss << indent << "call _input\n";
        std::cerr << "[DEBUG] input() function call generated assembly: " << ss.str() << std::endl;
        return ss.str();
    }
    // Built-in print.
    else if (node.type == "FunctionCall" && node.value == "print") {
        std::vector<ASTNode> positionalArgs;
        std::string endValue = "\n"; // Default end is newline.
        for (const auto &child : node.children) {
            if (child.type == "KeywordArgument" && child.value == "end") {
                endValue = processLiteral(child.children[0].value, true);
            } else {
                positionalArgs.push_back(child);
            }
        }
        // Process each positional argument.
        for (const auto &arg : positionalArgs) {
            if (!arg.value.empty() && (arg.value.front() == '"' || arg.value.front() == '\'')) {
                std::string text = processLiteral(arg.value, true);
                std::string label = generateLabel("print_arg");
                dataSection += label + ": .asciz \"" + escapeString(text) + "\"\n";
                ss << indent << "leaq " << label << "(%rip), %rdi\n"
                   << indent << "call _print_string\n";
            } else {
                ss << generateAssembly(arg, indentLevel, inFunction, brkLabel);
                ss << indent << "movq %rax, %rdi\n"
                   << indent << "call _print_string\n";
            }
        }
        std::string endLabel = generateLabel("print_end");
        dataSection += endLabel + ": .asciz \"" + escapeString(endValue) + "\"\n";
        ss << indent << "leaq " << endLabel << "(%rip), %rdi\n"
           << indent << "call _print_string\n";
        ss << indent << "movq $0, %rax\n"; // Return None after print.
        std::cerr << "[DEBUG] print() function call generated assembly: " << ss.str() << std::endl;
        return ss.str();
    }
    // Built-in int.
    else if (node.type == "FunctionCall" && node.value == "int") {
        if (node.children.empty())
            throw std::runtime_error("int() requires an argument.");
        ss << generateAssembly(node.children[0], indentLevel, inFunction, brkLabel);
        ss << indent << "movq %rax, %rdi\n";
        ss << indent << "call _atoi\n";
        std::cerr << "[DEBUG] int() function call generated assembly: " << ss.str() << std::endl;
        return ss.str();
    }
    else if (node.type == "FunctionCall") {
        throw std::runtime_error("Function \"" + node.value + "\" is not defined.");
    }
    else {
        ss << indent << "movq $0, %rax\n";
        std::cerr << "[DEBUG] Default node generated assembly: " << ss.str() << std::endl;
        return ss.str();
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
    finalAsm << "_input_buffer: .space 1025\n";
    finalAsm << dataSection << "\n";
#if defined(__APPLE__) || defined(__MACH__)
    finalAsm << ".section __TEXT,__text,regular,pure_instructions\n";
#else
    finalAsm << ".text\n";
#endif
    finalAsm << ".globl _start\n";
    finalAsm << "_start:\n";
    finalAsm << "    subq $8, %rsp\n";
    finalAsm << textCode << "\n";
    finalAsm << functionSection << "\n";
    finalAsm << "    call _exit\n";
    
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
             "    movq $0, %rax\n"
             "    ret\n";
    
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
    
    finalAsm << "\n.globl _exec\n";
    finalAsm << "_exec:\n";
#if defined(__APPLE__) || defined(__MACH__)
    finalAsm << "    pushq %rbp\n"
             "    movq %rsp, %rbp\n"
             "    call _system\n"
             "    popq %rbp\n"
             "    movq $0, %rax\n"
             "    ret\n";
#else
    finalAsm << "    pushq %rbp\n"
             "    movq %rsp, %rbp\n"
             "    call system\n"
             "    popq %rbp\n"
             "    movq $0, %rax\n"
             "    ret\n";
#endif
    
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
        std::cerr << "Usage: ./compile <source_files> [-o output_file] [exec]\n";
        return 1;
    }

    // Gather source files until we encounter "-o" or "exec"
    std::vector<std::string> sourceFiles;
    int argIndex = 1;
    while (argIndex < argc && std::string(argv[argIndex]) != "-o" && std::string(argv[argIndex]) != "exec") {
        sourceFiles.push_back(argv[argIndex]);
        argIndex++;
    }

    if (sourceFiles.empty()) {
        std::cerr << "Error: No source files provided.\n";
        return 1;
    }

    // Combine all source files into one source string.
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
        } else {
            argIndex++;
        }
    }

    // Use the first source file's name as the filename for error messages.
    std::string sourceFilename = sourceFiles.empty() ? "stdin" : sourceFiles[0];

    Lexer lexer(combinedSource, sourceFilename);
    std::vector<Token> tokens = lexer.tokenize();
    Parser parser(tokens);
    ASTNode root = parser.parse();
    CodeGenerator codeGen(root);

    // Generate binary.
    codeGen.generateBinary(outputFile);

    if (execFlag) {
        std::cout << "[Executor] Running generated binary: " << outputFile << "\n";
        execBinary(outputFile);
    }
    return 0;
}
