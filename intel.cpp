// ast.cpp
#include "ast.h"
#include "lexer.h"
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
#include <algorithm>
#include <memory>
#include <array>

static std::string executeCommand(const char* cmd) {
    std::array<char, 256> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }
    return result;
}

CodeGenerator::CodeGenerator(const ASTNode &ast)
    : astRoot(ast),
      dataSection(""),
      functionSection(""),
      labelCounter(0),
      sysPathListGenerated(false)
{
    definedNames.insert("print");
    definedNames.insert("input");
    definedNames.insert("int");
    definedNames.insert("ascii");
    definedNames.insert("exec");
}

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
    if (moduleName == "sys") return;
    if (compiledModules.count(moduleName)) return;
    compiledModules.insert(moduleName);

    std::vector<std::string> sysPaths = getSysPaths();
    std::string moduleFilePath;
    for (const auto &dir : sysPaths) {
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
    if (!ifs) throw std::runtime_error("Failed to open module file: " + moduleFilePath);
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    std::string source = buffer.str();

    Lexer moduleLexer(source, moduleFilePath);
    auto moduleTokens = moduleLexer.tokenize();
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
    if (sysPathListGenerated) return;
    auto paths = getSysPaths();
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

std::string CodeGenerator::processLiteral(const std::string &token, bool inPrintContext) {
    if (token.empty()) return token;
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

std::string CodeGenerator::generateAssembly(
    const ASTNode &node,
    int indentLevel,
    bool inFunction,
    const std::string &brkLabel
) {
    std::stringstream ss;
    std::string indent(indentLevel * 4, ' ');

    // ExpressionStatement
    if (node.type == "ExpressionStatement") {
        return generateAssembly(node.children[0], indentLevel, inFunction, brkLabel);
    }
    // SimpleStmtList
    if (node.type == "SimpleStmtList") {
        for (const auto &child : node.children) {
            ss << generateAssembly(child, indentLevel, inFunction, brkLabel);
        }
        return ss.str();
    }
    // BinaryOp (comparisons)
    if (node.type == "BinaryOp") {
        const std::string &op = node.value;
        ss << generateAssembly(node.children[0], indentLevel, inFunction, brkLabel);
        ss << indent << "pushq %rax\n";
        ss << generateAssembly(node.children[1], indentLevel, inFunction, brkLabel);
        ss << indent << "popq %rdi\n";
        ss << indent << "cmpq %rax, %rdi\n";
        if (op == "==")      ss << indent << "sete %al\n";
        else if (op == "!=") ss << indent << "setne %al\n";
        else if (op == "<")  ss << indent << "setl %al\n";
        else if (op == "<=") ss << indent << "setle %al\n";
        else if (op == ">")  ss << indent << "setg %al\n";
        else if (op == ">=") ss << indent << "setge %al\n";
        else                 ss << indent << "movq $0, %rax\n";
        ss << indent << "movzbq %al, %rax\n";
        return ss.str();
    }
    // NumberLiteral
    if (node.type == "NumberLiteral") {
        ss << indent << "movq $" << node.value << ", %rax\n";
        return ss.str();
    }
    // StringLiteral
    else if (node.type == "StringLiteral") {
        std::string raw = node.value.substr(1, node.value.size() - 2);
        std::string label = generateLabel("str");
        dataSection += label + ": .asciz \"" + escapeString(raw) + "\"\n";
        ss << indent << "leaq " << label << "(%rip), %rax\n";
        return ss.str();
    }
    // KeywordLiteral
    else if (node.type == "KeywordLiteral") {
        if (node.value == "True")
            ss << indent << "movq $1, %rax\n";
        else
            ss << indent << "movq $0, %rax\n";
        return ss.str();
    }
    // Suite
    else if (node.type == "Suite") {
        for (const auto &child : node.children) {
            ss << generateAssembly(child, indentLevel, inFunction, brkLabel);
        }
        return ss.str();
    }
    // Program
    else if (node.type == "Program") {
        for (const auto &child : node.children) {
            ss << generateAssembly(child, indentLevel, false, brkLabel);
        }
        return ss.str();
    }
    // Assignment
    else if (node.type == "Assignment") {
        std::string rhs = generateAssembly(node.children[0], indentLevel, inFunction, brkLabel);
        if (!variableLabels.count(node.value)) {
            std::string varLbl = generateLabel("var_" + node.value);
            variableLabels[node.value] = varLbl;
            dataSection += varLbl + ": .quad 0\n";
        }
        ss << rhs;
        ss << indent << "movq %rax, " << variableLabels[node.value] << "(%rip)\n";
        ss << indent << "movq " << variableLabels[node.value] << "(%rip), %rax\n";
        return ss.str();
    }
    // Identifier
    else if (node.type == "Identifier") {
        if (!variableLabels.count(node.value))
            throw std::runtime_error("Name \"" + node.value + "\" is not defined.");
        ss << indent << "movq " << variableLabels[node.value] << "(%rip), %rax\n";
        return ss.str();
    }
    // While
    else if (node.type == "While" || node.type == "while") {
        if (node.children.size() < 2) {
            return indent + "movq $0, %rax\n";
        }
        std::string condLabel = generateLabel("while_cond");
        std::string endLabel  = generateLabel("while_end");
        ss << condLabel << ":\n";
        ss << generateAssembly(node.children[0], indentLevel + 1, inFunction, endLabel);
        ss << indent << "cmpq $0, %rax\n";
        ss << indent << "je " << endLabel << "\n";
        ss << generateAssembly(node.children[1], indentLevel + 1, inFunction, endLabel);
        ss << indent << "jmp " << condLabel << "\n";
        ss << endLabel << ":\n";
        ss << indent << "movq $0, %rax\n";
        return ss.str();
    }
    // If
    else if (node.type == "If") {
        if (node.children.size() == 2) {
            std::string falseLabel = generateLabel("if_false");
            std::string endLabel   = generateLabel("if_end");
            ss << generateAssembly(node.children[0], indentLevel + 1, inFunction, brkLabel);
            ss << indent << "cmpq $0, %rax\n";
            ss << indent << "je " << falseLabel << "\n";
            ss << generateAssembly(node.children[1], indentLevel + 1, inFunction, brkLabel);
            ss << indent << "jmp " << endLabel << "\n";
            ss << falseLabel << ":\n";
            ss << endLabel << ":\n";
            ss << indent << "movq $0, %rax\n";
        }
        else if (node.children.size() == 3) {
            std::string falseLabel = generateLabel("if_false");
            std::string endLabel   = generateLabel("if_end");
            ss << generateAssembly(node.children[0], indentLevel + 1, inFunction, brkLabel);
            ss << indent << "cmpq $0, %rax\n";
            ss << indent << "je " << falseLabel << "\n";
            ss << generateAssembly(node.children[1], indentLevel + 1, inFunction, brkLabel);
            ss << indent << "jmp " << endLabel << "\n";
            ss << falseLabel << ":\n";
            ss << generateAssembly(node.children[2], indentLevel + 1, inFunction, brkLabel);
            ss << endLabel << ":\n";
            ss << indent << "movq $0, %rax\n";
        }
        return ss.str();
    }
    // BreakStatement
    else if (node.type == "BreakStatement") {
        if (!brkLabel.empty())
            return indent + "jmp " + brkLabel + "\n";
        else
            return indent + "movq $0, %rax\n";
    }
    // FunctionCall input
    else if (node.type == "FunctionCall" && node.value == "input") {
        if (!node.children.empty()) {
            std::string prompt = processLiteral(node.children[0].value, true);
            std::string label  = generateLabel("prompt");
            dataSection += label + ": .asciz \"" + escapeString(prompt) + "\"\n";
            ss << indent << "leaq " << label << "(%rip), %rdi\n"
               << indent << "call _print_string\n";
        }
        ss << indent << "call _input\n";
        return ss.str();
    }
    // FunctionCall print
    else if (node.type == "FunctionCall" && node.value == "print") {
        std::vector<ASTNode> positionalArgs;
        std::string endValue = "\n";
        for (const auto &child : node.children) {
            if (child.type == "KeywordArgument" && child.value == "end") {
                endValue = processLiteral(child.children[0].value, true);
            } else {
                positionalArgs.push_back(child);
            }
        }
        for (const auto &arg : positionalArgs) {
            if (!arg.value.empty() && (arg.value.front() == '"' || arg.value.front() == '\'')) {
                std::string text = processLiteral(arg.value, true);
                std::string lbl  = generateLabel("print_arg");
                dataSection += lbl + ": .asciz \"" + escapeString(text) + "\"\n";
                ss << indent << "leaq " << lbl << "(%rip), %rdi\n"
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
        ss << indent << "movq $0, %rax\n";
        return ss.str();
    }
    // FunctionCall int (compile-time for literals, fallback to runtime)
    else if (node.type == "FunctionCall" && node.value == "int") {
        if (node.children.empty())
            throw std::runtime_error("int() requires an argument.");
        const ASTNode &arg = node.children[0];
        if (arg.type == "StringLiteral") {
            std::string raw = arg.value.substr(1, arg.value.size() - 2);
            try {
                long long val = std::stoll(raw);
                ss << indent << "movq $" << val << ", %rax\n";
                return ss.str();
            } catch (...) {
                // fall through to runtime
            }
        }
        ss << generateAssembly(arg, indentLevel, inFunction, brkLabel);
        ss << indent << "movq %rax, %rdi\n";
        ss << indent << "call _atoi\n";
        return ss.str();
    }

    // Default
    ss << indent << "movq $0, %rax\n";
    return ss.str();
}

void CodeGenerator::generateBinary(const std::string &outputFile, bool assemblyOnly) {
    std::cout << "[CodeGenerator] Generating binary to: " << outputFile << "\n";
    std::string mainCode = generateAssembly(astRoot);
    std::string textCode =
        "    leaq _debug(%rip), %rdi\n"
        "    call _print_string\n"
        + mainCode;

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
    finalAsm << "    call _exit\n\n";

    // print_string
    finalAsm << ".globl _print_string\n";
    finalAsm << "_print_string:\n"
                ".print_string_done:\n";
#if defined(__APPLE__) || defined(__MACH__)
    finalAsm << "    movq $0x2000004, %rax\n";
#else
    finalAsm << "    movq $1, %rax\n";
#endif
    finalAsm << "    movq $1, %rdi\n"
                "    ret\n\n";

    // input
    finalAsm << ".globl _input\n";
    finalAsm << "_input:\n"
                "    movq %rsp, %rbp\n";
#if defined(__APPLE__) || defined(__MACH__)
    finalAsm << "    movq $0, %rdi\n"
                "    syscall\n";
#else
    finalAsm << "    movq $0, %rdi\n"
                "    syscall\n";
#endif
    finalAsm << "    testq %rax, %rax\n"
                "    ret\n\n";

    // atoi (runtime)
    finalAsm << ".globl _atoi\n";
    finalAsm << "_atoi:\n"
                "    movq $0, %rax\n"
                "atoi_loop:\n"
                "    movzbq (%rdi), %rcx\n"
                "    cmpb $0, %cl\n"
                "    je atoi_done\n"
                "    subb $'0', %cl\n"
                "    imulq $10, %rax\n"
                "    addq %rcx, %rax\n"
                "    incq %rdi\n"
                "    jmp atoi_loop\n"
                "atoi_done:\n"
                "    ret\n\n";

    // exec stub
    finalAsm << ".globl _exec\n";
    finalAsm << "_exec:\n";
#if defined(__APPLE__) || defined(__MACH__)
    finalAsm << "    pushq %rbp\n"
                "    ret\n\n";
#else
    finalAsm << "    pushq %rbp\n"
                "    ret\n\n";
#endif

    // exit
    finalAsm << ".globl _exit\n";
    finalAsm << "_exit:\n";
#if defined(__APPLE__) || defined(__MACH__)
    finalAsm << "    movq $0x2000001, %rax\n"
                "    syscall\n";
#else
    finalAsm << "    movq $60, %rax\n"
                "    syscall\n";
#endif

    std::string assemblyCode = finalAsm.str();
    std::string asmFile = outputFile + ".s";
    std::string objFile = outputFile + ".o";

    // write .s
    std::ofstream asm_ofs(asmFile);
    if (!asm_ofs) throw std::runtime_error("Failed to write assembly file.");
    asm_ofs << assemblyCode;
    asm_ofs.close();

    if (assemblyOnly) {
        std::cout << "[Compiler] Assembly file generated: " << asmFile << "\n";
        return;
    }

    // assemble
    std::string assemble_cmd = "as " + asmFile + " -o " + objFile;
    std::cout << "[Compiler] Running: " << assemble_cmd << "\n";
    if (std::system(assemble_cmd.c_str()) != 0) {
        throw std::runtime_error("Assembly failed.");
    }

    // link
    std::string link_cmd;
#if defined(__APPLE__) || defined(__MACH__)
    std::string sdk_path;
    try {
        sdk_path = executeCommand("xcrun --show-sdk-path");
    } catch (const std::runtime_error &e) {
        throw std::runtime_error("Failed to get SDK path with xcrun. Make sure Xcode Command Line Tools are installed.");
    }
    if (sdk_path.empty()) {
        throw std::runtime_error("xcrun returned an empty SDK path. Make sure Xcode Command Line Tools are installed.");
    }
    link_cmd = "ld " + objFile + " -o " + outputFile + " -e _start -lSystem -no_pie -syslibroot " + sdk_path;
#else
    link_cmd = "ld " + objFile + " -o " + outputFile + " -no-pie -e _start -lc";
#endif
    std::cout << "[Compiler] Running: " << link_cmd << "\n";
    if (std::system(link_cmd.c_str()) != 0) {
        throw std::runtime_error("Linking with ld failed.");
    }

    // cleanup
    std::remove(asmFile.c_str());
    std::remove(objFile.c_str());
    std::cout << "[CodeGenerator] Binary executable generated: " << outputFile << "\n";
}
