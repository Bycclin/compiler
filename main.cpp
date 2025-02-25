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
#include <cstdlib>
#include <exception>
#ifdef __APPLE__
#include <unistd.h>  // for _read on macOS and exec functions
#else
#include <unistd.h>
#include <sys/wait.h>
#endif

// The CodeGenerator produces assembly code for our Python-like language.
// An extra parameter (brkLabel) propagates the current loop break label.
class CodeGenerator {
public:
    explicit CodeGenerator(const ASTNode &ast)
        : astRoot(ast), dataSection(""), functionSection(""), labelCounter(0),
          sysPathListGenerated(false) {}

    // Extra parameter (brkLabel) propagates the current loop break label.
    void generateBinary(const std::string &outputFile);
    std::string generateAssembly(const ASTNode &node, int indentLevel = 1, bool inFunction = false, const std::string &brkLabel = "");

private:
    ASTNode astRoot;
    std::string dataSection;
    std::string functionSection;
    int labelCounter;
    std::set<std::string> compiledModules;
    // Symbol table for variables
    std::map<std::string, std::string> variableLabels;
    bool sysPathListGenerated;
    std::string sysPathListLabel;

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

std::string CodeGenerator::generateAssembly(const ASTNode &node, int indentLevel, bool inFunction, const std::string &brkLabel) {
    std::stringstream ss;
    std::string indent(indentLevel * 4, ' ');
    
    if (node.type == "Program") {
        for (const auto &child : node.children)
            ss << generateAssembly(child, indentLevel, false, brkLabel);
    }
    else if (node.type == "Assignment") {
        std::string varName = node.value;
        if (variableLabels.find(varName) == variableLabels.end()) {
            std::string varLabel = generateLabel("var");
            variableLabels[varName] = varLabel;
            dataSection += varLabel + ": .quad 0\n";
        }
        std::string varLabel = variableLabels[varName];
        std::string rhsCode = generateAssembly(node.children[0], indentLevel, false, brkLabel);
        ss << rhsCode;
        ss << indent << "leaq " << varLabel << "(%rip), %rdi\n"
           << indent << "movq %rax, " << varLabel << "(%rip)\n";
    }
    else if (node.type == "Identifier") {
        std::string varName = node.value;
        if (variableLabels.find(varName) == variableLabels.end())
            throw std::runtime_error("Undefined variable: " + varName);
        std::string varLabel = variableLabels[varName];
        ss << indent << "leaq " << varLabel << "(%rip), %rax\n"
           << indent << "movq (%rax), %rax\n";
    }
    else if (node.type == "Argument") {
        if (node.value.find('<') != std::string::npos) {
            size_t pos = node.value.find('<');
            std::string lhs = node.value.substr(0, pos);
            std::string rhs = node.value.substr(pos + 1);
            auto trim = [](std::string s) -> std::string {
                s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) { return !std::isspace(ch); }));
                s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) { return !std::isspace(ch); }).base(), s.end());
                return s;
            };
            lhs = trim(lhs);
            rhs = trim(rhs);
            std::stringstream ssArg;
            if (variableLabels.find(lhs) != variableLabels.end()) {
                std::string varLabel = variableLabels[lhs];
                ssArg << indent << "leaq " << varLabel << "(%rip), %rax\n"
                      << indent << "movq (%rax), %rax\n";
            } else {
                ssArg << indent << "movq $" << lhs << ", %rax\n";
            }
            ssArg << indent << "movq %rax, %r10\n";
            if (variableLabels.find(rhs) != variableLabels.end()) {
                std::string varLabel = variableLabels[rhs];
                ssArg << indent << "leaq " << varLabel << "(%rip), %rax\n"
                      << indent << "movq (%rax), %rax\n";
            } else {
                ssArg << indent << "movq $" << rhs << ", %rax\n";
            }
            ssArg << indent << "movq %rax, %r11\n";
            ssArg << indent << "cmpq %r11, %r10\n";
            ssArg << indent << "setl %al\n";
            ssArg << indent << "movzbq %al, %rax\n";
            return ssArg.str();
        }
        else if (node.value.find('>') != std::string::npos) {
            size_t pos = node.value.find('>');
            std::string lhs = node.value.substr(0, pos);
            std::string rhs = node.value.substr(pos + 1);
            auto trim = [](std::string s) -> std::string {
                s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) { return !std::isspace(ch); }));
                s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) { return !std::isspace(ch); }).base(), s.end());
                return s;
            };
            lhs = trim(lhs);
            rhs = trim(rhs);
            std::stringstream ssArg;
            if (variableLabels.find(lhs) != variableLabels.end()) {
                std::string varLabel = variableLabels[lhs];
                ssArg << indent << "leaq " << varLabel << "(%rip), %rax\n"
                      << indent << "movq (%rax), %rax\n";
            } else {
                ssArg << indent << "movq $" << lhs << ", %rax\n";
            }
            ssArg << indent << "movq %rax, %r10\n";
            if (variableLabels.find(rhs) != variableLabels.end()) {
                std::string varLabel = variableLabels[rhs];
                ssArg << indent << "leaq " << varLabel << "(%rip), %rax\n"
                      << indent << "movq (%rax), %rax\n";
            } else {
                ssArg << indent << "movq $" << rhs << ", %rax\n";
            }
            ssArg << indent << "movq %rax, %r11\n";
            ssArg << indent << "cmpq %r11, %r10\n";
            ssArg << indent << "setg %al\n";
            ssArg << indent << "movzbq %al, %rax\n";
            return ssArg.str();
        } else {
            std::string evaluated;
            if (tryEvaluateArithmetic(node.value, evaluated))
                return indent + "movq $" + evaluated + ", %rax\n";
            if (variableLabels.find(node.value) != variableLabels.end()) {
                std::string varLabel = variableLabels[node.value];
                return indent + "leaq " + varLabel + "(%rip), %rax\n" +
                       indent + "movq (%rax), %rax\n";
            }
            return "";
        }
    }
    else if ((node.type == "Unsupported" && node.value == "break") || node.type == "Break") {
        if (brkLabel.empty())
            return indent + "jmp _exit\n";
        return indent + "jmp " + brkLabel + "\n";
    }
    else if (node.type == "Import") {
        compileModule(node.value);
        return "";
    }
    else if (node.type == "If") {
        std::string elseLabel = generateLabel("if_else");
        std::string endLabel = generateLabel("if_end");
        ss << generateAssembly(node.children[0], indentLevel, false, brkLabel);
        ss << indent << "cmpq $0, %rax\n";
        if (node.children.size() == 3)
            ss << indent << "je " << elseLabel << "\n";
        else
            ss << indent << "je " << endLabel << "\n";
        ss << generateAssembly(node.children[1], indentLevel, false, brkLabel);
        ss << indent << "jmp " << endLabel << "\n";
        if (node.children.size() == 3) {
            ss << elseLabel << ":\n";
            ss << generateAssembly(node.children[2], indentLevel, false, brkLabel);
        }
        ss << endLabel << ":\n";
    }
    else if (node.type == "While") {
        std::string startLabel = generateLabel("while_start");
        std::string endLabel = generateLabel("while_end");
        ss << startLabel << ":\n";
        ss << generateAssembly(node.children[0], indentLevel, false, brkLabel);
        ss << indent << "cmpq $0, %rax\n";
        ss << indent << "je " << endLabel << "\n";
        // For the loop body, pass the current loop's end label as the break target.
        ss << generateAssembly(node.children[1], indentLevel, false, endLabel);
        ss << indent << "jmp " << startLabel << "\n";
        ss << endLabel << ":\n";
    }
    else if (node.type == "Boolean") {
        if (node.value == "True")
            ss << indent << "movq $1, %rax\n";
        else
            ss << indent << "movq $0, %rax\n";
    }
    else if (node.type == "FunctionCall") {
        if (node.value == "input") {
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
        if (node.value == "print") {
            for (size_t i = 0; i < node.children.size(); i++) {
                ASTNode arg = node.children[i];
                if (!arg.value.empty() &&
                    ((arg.value.front() == '\"' && arg.value.back() == '\"') ||
                     (arg.value.front() == '\'' && arg.value.back() == '\''))) {
                    std::string literal = processLiteral(arg.value, true);
                    std::string label = generateLabel("expr");
                    dataSection += label + ": .asciz \"" + escapeString(literal) + "\\n\"\n";
                    ss << indent << "leaq " << label << "(%rip), %rdi\n"
                       << indent << "call _print_string\n";
                }
                else if (arg.value == "sys.path") {
                    generateSysPathList();
                    ss << indent << "leaq " << sysPathListLabel << "(%rip), %rdi\n"
                       << indent << "call _print_list\n";
                }
                else {
                    std::string evaluated;
                    if (tryEvaluateArithmetic(arg.value, evaluated)) {
                        std::string label = generateLabel("expr");
                        dataSection += label + ": .asciz \"" + escapeString(evaluated) + "\\n\"\n";
                        ss << indent << "leaq " << label << "(%rip), %rdi\n"
                           << indent << "call _print_string\n";
                    } else {
                        std::string literal = processLiteral(arg.value, true);
                        std::string label = generateLabel("expr");
                        dataSection += label + ": .asciz \"" + escapeString(literal) + "\\n\"\n";
                        ss << indent << "leaq " << label << "(%rip), %rdi\n"
                           << indent << "call _print_string\n";
                    }
                }
            }
            return ss.str();
        }
        if (node.value == "ascii") {
            if (!node.children.empty()) {
                std::string literal = processLiteral(node.children[0].value, true);
                std::string asciiResult = computeAscii(literal);
                std::string label = generateLabel("expr");
                dataSection += label + ": .asciz \"" + escapeString(asciiResult) + "\\n\"\n";
                ss << indent << "leaq " << label << "(%rip), %rdi\n"
                   << indent << "call _print_string\n";
            } else {
                std::string label = generateLabel("expr");
                dataSection += label + ": .asciz \"<ascii no argument>\\n\"\n";
                ss << indent << "leaq " << label << "(%rip), %rdi\n"
                   << indent << "call _print_string\n";
            }
            return ss.str();
        }
        if (node.value == "int") {
            if (!node.children.empty()) {
                // Generate code for the argument so its result (the input string pointer) is in %rax.
                std::string argCode = generateAssembly(node.children[0], indentLevel, false, brkLabel);
                ss << argCode;
                // Move the pointer from %rax to %rdi and call _atoi.
                ss << indent << "movq %rax, %rdi\n";
                ss << indent << "call _atoi\n";
            } else {
                std::string label = generateLabel("expr");
                dataSection += label + ": .asciz \"<int no argument>\\n\"\n";
                ss << indent << "leaq " << label << "(%rip), %rdi\n"
                   << indent << "call _print_string\n";
            }
            return ss.str();
        }
        if (node.value == "exec") {
            if (!node.children.empty()) {
                std::string code = processLiteral(node.children[0].value, true);
                std::string label = generateLabel("exec");
                dataSection += label + ": .asciz \"" + escapeString(code) + "\"\n";
                ss << indent << "leaq " << label << "(%rip), %rdi\n";
                ss << indent << "call _exec\n";
            }
            return ss.str();
        }
        {
            std::string evaluated;
            if (tryEvaluateArithmetic(node.value, evaluated)) {
                std::string label = generateLabel("expr");
                dataSection += label + ": .asciz \"" + escapeString(evaluated) + "\\n\"\n";
                ss << indent << "leaq " << label << "(%rip), %rdi\n"
                   << indent << "call _print_string\n";
            } else {
                std::string literal = processLiteral(node.value, true);
                std::string label = generateLabel("expr");
                dataSection += label + ": .asciz \"" + escapeString(literal) + "\\n\"\n";
                ss << indent << "leaq " << label << "(%rip), %rdi\n"
                   << indent << "call _print_string\n";
            }
        }
        return ss.str();
    }
    else if (node.type == "FunctionDef") {
        if (node.value == "test") {
            std::string label = "_" + node.value;
            functionSection += label + ":\n";
            functionSection += "    movq %rdi, %rax\n"
                             "    addq $1, %rax\n"
                             "    ret\n";
            return "";
        } else {
            std::string label = "_" + node.value;
            functionSection += label + ":\n";
            functionSection += generateAssembly(node.children[1], 1, true, brkLabel);
            functionSection += "    ret\n";
            return "";
        }
    }
    else if (node.type == "Lambda") {
        std::string lambdaLabel = generateLabel("lambda");
        functionSection += lambdaLabel + ":\n";
        functionSection += generateAssembly(node.children[1], 1, true, brkLabel);
        functionSection += "    ret\n";
        std::string label = generateLabel("expr");
        dataSection += label + ": .asciz \"<lambda function: " + lambdaLabel + ">\\n\"\n";
        std::stringstream ssLambda;
        ssLambda << indent << "leaq " << label << "(%rip), %rdi\n"
                 << indent << "call _print_string\n";
        return ssLambda.str();
    }
    else if (node.type == "Return") {
        if (!node.children.empty()) {
            std::string exprStr = node.children[0].value;
            std::string evaluated;
            if (!exprStr.empty() && (exprStr.front()=='f' || exprStr.front()=='F') &&
                (exprStr[1]=='\"' || exprStr[1]=='\'')) {
                std::string processed = processFString(exprStr);
                std::string label = generateLabel("expr");
                dataSection += label + ": .asciz \"" + escapeString(processed) + "\"\n";
                ss << indent << "leaq " << label << "(%rip), %rdi\n"
                   << indent << "movq %rdi, %rax\n";
            } else if (tryEvaluateArithmetic(exprStr, evaluated))
                ss << indent << "movq $" << evaluated << ", %rax\n";
            else {
                std::string literal = processLiteral(exprStr, false);
                std::string label = generateLabel("expr");
                dataSection += label + ": .asciz \"" + escapeString(literal) + "\"\n";
                ss << indent << "leaq " << label << "(%rip), %rdi\n"
                   << indent << "movq %rdi, %rax\n";
            }
        }
        ss << indent << "ret\n";
        return ss.str();
    }
    else if (node.type == "Yield") {
        if (!node.children.empty()) {
            std::string exprStr = node.children[0].value;
            std::string evaluated;
            if (tryEvaluateArithmetic(exprStr, evaluated)) {
                std::string label = generateLabel("yield");
                dataSection += label + ": .asciz \"" + escapeString(evaluated) + "\\n\"\n";
                ss << indent << "leaq " << label << "(%rip), %rdi\n"
                   << indent << "call _print_string\n";
            } else {
                std::string literal = processLiteral(exprStr, false);
                std::string label = generateLabel("yield");
                dataSection += label + ": .asciz \"" + escapeString(literal) + "\\n\"\n";
                ss << indent << "leaq " << label << "(%rip), %rdi\n"
                   << indent << "call _print_string\n";
            }
        }
        ss << indent << "ret\n";
        return ss.str();
    }
    else if (node.type == "Class") {
        std::string label = "_" + node.value;
        functionSection += label + ":\n";
        functionSection += "    ret\n";
        return "";
    }
    else {
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
    // Generate global _exit label.
    std::stringstream finalAsm;
    finalAsm << ".section __DATA,__data\n";
    finalAsm << "_debug: .asciz \"DEBUG: _start entered\\n\"\n";
    finalAsm << "_input_buffer: .space 256\n";
    finalAsm << dataSection << "\n";
    finalAsm << ".section __TEXT,__text,regular,pure_instructions\n";
    finalAsm << ".globl _start\n";
    finalAsm << "_start:\n" << textCode << "\n";
    finalAsm << functionSection << "\n";
    finalAsm << "\n.globl _print_list\n";
    finalAsm << "_print_list:\n"
             "    pushq %rbp\n"
             "    movq %rsp, %rbp\n"
             "    pushq %r12\n"
             "    movq %rdi, %r12\n"
             "    leaq _list_open(%rip), %rdi\n"
             "    call _print_string\n"
             "_print_list_loop:\n"
             "    movq (%r12), %rax\n"
             "    cmpq $0, %rax\n"
             "    je _print_list_end_loop\n"
             "    leaq _quote(%rip), %rdi\n"
             "    call _print_string\n"
             "    movq (%r12), %rdi\n"
             "    call _print_string\n"
             "    leaq _quote(%rip), %rdi\n"
             "    call _print_string\n"
             "    addq $8, %r12\n"
             "    movq (%r12), %rax\n"
             "    cmpq $0, %rax\n"
             "    jne _print_list_print_comma\n"
             "    jmp _print_list_loop\n"
             "_print_list_print_comma:\n"
             "    leaq _comma(%rip), %rdi\n"
             "    call _print_string\n"
             "    jmp _print_list_loop\n"
             "_print_list_end_loop:\n"
             "    leaq _list_close(%rip), %rdi\n"
             "    call _print_string\n"
             "    popq %r12\n"
             "    popq %rbp\n"
             "    ret\n"
             "\n# Data for _print_list\n"
             "_list_open: .asciz \"[\"\n"
             "_quote: .asciz \"'\"\n"
             "_comma: .asciz \", \"\n"
             "_list_close: .asciz \"]\\n\"\n";
    
    // Use conditional compilation to choose proper syscall numbers.
#if defined(__APPLE__) || defined(__MACH__)
    std::string write_syscall = "    movq $0x2000004, %rax\n"; // macOS write
    std::string exit_syscall  = "    movq $0x2000001, %rax\n"; // macOS exit
#else
    std::string write_syscall = "    movq $1, %rax\n";  // Linux write
    std::string exit_syscall  = "    movq $60, %rax\n"; // Linux exit
#endif

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
             ".print_string_done:\n" + write_syscall +
             "    movq $1, %rdi\n"
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
    // On macOS, call the C library function _read.
    finalAsm << "    movq $0, %rdi\n"            // stdin = 0
             "    leaq _input_buffer(%rip), %rsi\n"
             "    movq $256, %rdx\n"
             "    call _read\n";
#else
    // On Linux, use the raw syscall.
    finalAsm << "    movq $0, %rdi\n"            // stdin = 0
             "    leaq _input_buffer(%rip), %rsi\n"
             "    movq $256, %rdx\n"
             "    movq $0, %rax\n"              // Linux syscall number for read = 0
             "    syscall\n";
#endif
    finalAsm << "    leaq _input_buffer(%rip), %rax\n"
             "    popq %rbp\n"
             "    ret\n";
    
    // _atoi: simple conversion (non-negative only).
    finalAsm << "\n.globl _atoi\n";
    finalAsm << "_atoi:\n"
             "    pushq %rbp\n"
             "    movq %rsp, %rbp\n"
             "    movq $0, %rax\n"        // result = 0
             "    movq %rdi, %rcx\n"      // pointer to input string
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
    
    // _exec: executes a command string by calling system()
    finalAsm << "\n.globl _exec\n";
    finalAsm << "_exec:\n"
             "    pushq %rbp\n"
             "    movq %rsp, %rbp\n"
             "    call system\n"
             "    popq %rbp\n"
             "    ret\n";
    
    // Global _exit definition.
#if defined(__APPLE__) || defined(__MACH__)
    finalAsm << "\n.globl _exit\n";
    finalAsm << "_exit:\n" + exit_syscall +
             "    movq $0, %rdi\n"
             "    syscall\n";
#else
    finalAsm << "\n.globl _exit\n";
    finalAsm << "_exit:\n" + exit_syscall +
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

// New function: execBinary()
// If the compiler is invoked with a third argument "exec", the generated binary is executed.
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
    if (argc < 3) {
        std::cerr << "Usage: ./compile <source_file> <output_file> [exec]\n";
        return 1;
    }
    std::ifstream ifs(argv[1]);
    if (!ifs) {
        std::cerr << "Failed to open source file: " << argv[1] << "\n";
        return 1;
    }
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    std::string source = buffer.str();
    Lexer lexer(source, argv[1]);
    std::vector<Token> tokens = lexer.tokenize();
    Parser parser(tokens);
    ASTNode root = parser.parse();
    CodeGenerator codeGen(root);
    try {
        codeGen.generateBinary(argv[2]);
    } catch (const std::exception &ex) {
        std::cerr << "compile: " << "\033[1;31merror:\033[0;1m " << ex.what() << "\033[0m\n";
        return 1;
    }
    // If a third argument "exec" is provided, execute the generated binary.
    if (argc >= 4 && std::string(argv[3]) == "exec") {
        std::cout << "[Executor] Running generated binary: " << argv[2] << "\n";
        execBinary(argv[2]);
    }
    return 0;
}
