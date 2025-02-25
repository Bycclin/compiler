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
#include <sstream>

//------------------------------------------------------------
// CodeGenerator with GOT–relative addressing for Linux ARM64 PIC.
//------------------------------------------------------------
class CodeGenerator {
public:
    // Pass in the source filename to support __file__
    CodeGenerator(const ASTNode &ast, const std::string &srcFilename)
        : astRoot(ast), dataSection(""), functionSection(""), labelCounter(0),
          sysPathListGenerated(false), sourceFilename(srcFilename) {}

    void generateBinary(const std::string &outputFile);
    std::string generateAssembly(const ASTNode &node, int indentLevel = 1, bool inFunction = false);

private:
    ASTNode astRoot;
    std::string dataSection;    // Regular data declarations.
    std::string functionSection;
    int labelCounter;
    std::set<std::string> compiledModules;
    std::map<std::string, std::string> variableLabels;
    bool sysPathListGenerated;
    std::string sysPathListLabel;
    std::string sourceFilename; // Stores source filename

    // --- GOT support for PIC ---
    std::string gotSection;         // Accumulates GOT entries.
    std::set<std::string> gotLabels;  // Ensures each label gets a GOT entry.

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

    // New helper: generate GOT–relative load sequence.
    // This emits:
    //   adrp reg, _GOT.<label>@GOTPAGE
    //   add  reg, reg, _GOT.<label>@GOTPAGEOFF
    //   ldr  reg, [reg]
    // and ensures a GOT entry (named _GOT.<label>) exists.
    std::string genLoadAddress(const std::string &reg, const std::string &label) {
        std::string gotLabel = "_GOT." + label;
        if (gotLabels.find(label) == gotLabels.end()) {
            gotSection += ".globl " + gotLabel + "\n";
            gotSection += gotLabel + ": .quad " + label + "\n";
            gotLabels.insert(label);
        }
        std::ostringstream oss;
        oss << "    adrp " << reg << ", " << gotLabel << "@GOTPAGE\n";
        oss << "    add  " << reg << ", " << reg << ", " << gotLabel << "@GOTPAGEOFF\n";
        oss << "    ldr  " << reg << ", [" << reg << "]\n";
        return oss.str();
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
        token.erase(token.begin(), std::find_if(token.begin(), token.end(), [](int ch) {
            return !std::isspace(ch);
        }));
        token.erase(std::find_if(token.rbegin(), token.rend(), [](int ch) {
            return !std::isspace(ch);
        }).base(), token.end());
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
        listDef += "    .xword " + lbl + "\n";
    }
    listDef += "    .xword 0\n";
    dataSection += listDef;
    sysPathListGenerated = true;
}

std::string CodeGenerator::generateAssembly(const ASTNode &node, int indentLevel, bool inFunction) {
    (void)inFunction;
    std::stringstream ss;
    std::string indent(indentLevel * 4, ' ');
    
    if (node.type == "Program") {
        for (const auto &child : node.children)
            ss << generateAssembly(child, indentLevel, false);
    }
    else if (node.type == "Assignment") {
        std::string varName = node.value;
        if (variableLabels.find(varName) == variableLabels.end()) {
            std::string varLabel = generateLabel("var");
            variableLabels[varName] = varLabel;
            dataSection += varLabel + ": .quad 0\n";
        }
        std::string varLabel = variableLabels[varName];
        std::string rhsCode = generateAssembly(node.children[0], indentLevel, false);
        ss << rhsCode;
        ss << genLoadAddress("x1", varLabel);
        ss << indent << "str x0, [x1]\n";
    }
    else if (node.type == "Identifier") {
        if (node.value == "__file__") {
            std::string fileLabel = generateLabel("file");
            dataSection += fileLabel + ": .asciz \"" + escapeString(sourceFilename) + "\"\n";
            ss << genLoadAddress("x0", fileLabel);
        } else {
            std::string varName = node.value;
            if (variableLabels.find(varName) == variableLabels.end())
                throw std::runtime_error("Undefined variable: " + varName);
            std::string varLabel = variableLabels[varName];
            ss << genLoadAddress("x0", varLabel);
            ss << indent << "ldr x0, [x0]\n";
        }
    }
    else if (node.type == "ListLiteral") {
        std::string listStr = "[";
        for (size_t i = 0; i < node.children.size(); i++) {
            listStr += node.children[i].value;
            if (i != node.children.size() - 1)
                listStr += ", ";
        }
        listStr += "]";
        std::string label = generateLabel("list");
        dataSection += label + ": .asciz \"" + escapeString(listStr) + "\\n\"\n";
        ss << genLoadAddress("x0", label);
        ss << indent << "bl _print_string\n";
    }
    else if (node.type == "Import") {
        compileModule(node.value);
        return "";
    }
    else if (node.type == "If") {
        std::string elseLabel = generateLabel("if_else");
        std::string endLabel = generateLabel("if_end");
        ss << generateAssembly(node.children[0], indentLevel, false);
        ss << indent << "cmp x0, #0\n";
        if (node.children.size() == 3)
            ss << indent << "beq " << elseLabel << "\n";
        else
            ss << indent << "beq " << endLabel << "\n";
        ss << generateAssembly(node.children[1], indentLevel, false);
        ss << indent << "b " << endLabel << "\n";
        if (node.children.size() == 3) {
            ss << elseLabel << ":\n";
            ss << generateAssembly(node.children[2], indentLevel, false);
        }
        ss << endLabel << ":\n";
    }
    else if (node.type == "While") {
        std::string startLabel = generateLabel("while_start");
        std::string endLabel = generateLabel("while_end");
        ss << startLabel << ":\n";
        ss << generateAssembly(node.children[0], indentLevel, false);
        ss << indent << "cmp x0, #0\n";
        ss << indent << "beq " << endLabel << "\n";
        ss << generateAssembly(node.children[1], indentLevel, false);
        ss << indent << "b " << startLabel << "\n";
        ss << endLabel << ":\n";
    }
    else if (node.type == "For") {
        ss << indent << "// For loop over variable: " << node.value << "\n";
        ss << indent << "bl _for_loop_stub\n";
    }
    else if (node.type == "With") {
        std::string contextCode = generateAssembly(node.children[0], indentLevel, false);
        std::string bodyCode = generateAssembly(node.children[1], indentLevel, false);
        ss << contextCode << bodyCode;
    }
    else if (node.type == "Boolean") {
        if (node.value == "True")
            ss << indent << "mov x0, #1\n";
        else
            ss << indent << "mov x0, #0\n";
    }
    else if (node.type == "FunctionCall") {
        if (node.value == "abs") {
            if (!node.children.empty()) {
                std::string argVal = node.children[0].value;
                std::string evaluated;
                if (tryEvaluateArithmetic(argVal, evaluated)) {
                    double val = std::stod(evaluated);
                    double absVal = (val < 0) ? -val : val;
                    std::ostringstream oss; oss << absVal;
                    std::string label = generateLabel("expr");
                    dataSection += label + ": .asciz \"" + escapeString(oss.str()) + "\\n\"\n";
                    ss << genLoadAddress("x0", label);
                    ss << indent << "bl _print_string\n";
                    return ss.str();
                }
            }
        }
        else if (node.value == "sum") {
            if (!node.children.empty()) {
                std::vector<long long> nums;
                if (tryEvaluateList(node.children[0].value, nums)) {
                    long long total = 0;
                    for (auto n : nums) total += n;
                    std::ostringstream oss; oss << total;
                    std::string label = generateLabel("expr");
                    dataSection += label + ": .asciz \"" + escapeString(oss.str()) + "\\n\"\n";
                    ss << genLoadAddress("x0", label);
                    ss << indent << "bl _print_string\n";
                    return ss.str();
                }
            }
        }
        if (node.value == "input") {
            if (!node.children.empty()) {
                std::string prompt = processLiteral(node.children[0].value, true);
                std::string label = generateLabel("prompt");
                dataSection += label + ": .asciz \"" + escapeString(prompt) + "\"\n";
                ss << genLoadAddress("x0", label);
                ss << indent << "bl _print_string\n";
            }
            ss << indent << "bl _input\n";
            return ss.str();
        }
        {
            std::string evaluated;
            if (tryEvaluateArithmetic(node.value, evaluated)) {
                std::string label = generateLabel("expr");
                dataSection += label + ": .asciz \"" + escapeString(evaluated) + "\\n\"\n";
                ss << genLoadAddress("x0", label);
                ss << indent << "bl _print_string\n";
            } else {
                std::string literal = processLiteral(node.value, true);
                std::string label = generateLabel("expr");
                dataSection += label + ": .asciz \"" + escapeString(literal) + "\\n\"\n";
                ss << genLoadAddress("x0", label);
                ss << indent << "bl _print_string\n";
            }
        }
        return ss.str();
    }
    else if (node.type == "Argument") {
        if (node.value.size() >= 6 &&
            node.value.substr(0, 4) == "int(" &&
            node.value.back() == ')') {
            std::string inner = node.value.substr(4, node.value.size() - 5);
            if (inner == "input()") {
                std::stringstream ssArg;
                ssArg << indent << "bl _input\n";
                ssArg << indent << "bl _atoi\n";
                return ssArg.str();
            }
        }
        std::string evaluated;
        if (tryEvaluateArithmetic(node.value, evaluated)) {
            return indent + "mov x0, #" + evaluated + "\n";
        } else {
            std::string label = generateLabel("expr");
            dataSection += label + ": .asciz \"" + escapeString(node.value) + "\\n\"\n";
            return genLoadAddress("x0", label);
        }
    }
    else if (node.type == "FunctionDef") {
        std::string label = "_" + node.value;
        functionSection += label + ":\n";
        functionSection += generateAssembly(node.children[1], 1, true);
        functionSection += "    ret\n";
        return "";
    }
    else if (node.type == "Lambda") {
        std::string lambdaLabel = generateLabel("lambda");
        functionSection += lambdaLabel + ":\n";
        functionSection += generateAssembly(node.children[1], 1, true);
        functionSection += "    ret\n";
        std::string label = generateLabel("expr");
        dataSection += label + ": .asciz \"<lambda function: " + lambdaLabel + ">\\n\"\n";
        std::stringstream ssLambda;
        ssLambda << genLoadAddress("x0", label);
        ssLambda << indent << "bl _print_string\n";
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
                ss << genLoadAddress("x0", label);
            } else if (tryEvaluateArithmetic(exprStr, evaluated))
                ss << indent << "mov x0, #" << evaluated << "\n";
            else {
                std::string literal = processLiteral(exprStr, false);
                std::string label = generateLabel("expr");
                dataSection += label + ": .asciz \"" + escapeString(literal) + "\"\n";
                ss << genLoadAddress("x0", label);
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
                ss << genLoadAddress("x0", label);
                ss << indent << "bl _print_string\n";
            } else {
                std::string literal = processLiteral(exprStr, false);
                std::string label = generateLabel("yield");
                dataSection += label + ": .asciz \"" + escapeString(literal) + "\\n\"\n";
                ss << genLoadAddress("x0", label);
                ss << indent << "bl _print_string\n";
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
    std::cerr << "[DEBUG] Starting assembly generation...\n";
    std::string mainCode = generateAssembly(astRoot);
    std::cerr << "[DEBUG] Assembly generation complete. Main code size: " << mainCode.size() << "\n";
    std::string preText = "";
    std::string textCode = preText + mainCode;
    textCode += "    mov x0, #0\n"
                "    bl _exit\n";
    std::stringstream finalAsm;
    finalAsm << ".section __DATA,__const\n";
    finalAsm << gotSection;
    finalAsm << ".section __DATA,__data\n";
    finalAsm << "_input_buffer: .space 256\n";
    finalAsm << dataSection << "\n";
    finalAsm << ".section __TEXT,__text,regular,pure_instructions\n";
    finalAsm << ".globl _start\n";
    finalAsm << "_start:\n" << textCode << "\n";
    finalAsm << functionSection << "\n";
    finalAsm << "\n.globl _print_list\n";
    finalAsm << "_print_list:\n"
             "    stp x29, x30, [sp, #-16]!\n"
             "    mov x29, sp\n"
             "    // (ARM64 _print_list implementation placeholder)\n"
             "    ldp x29, x30, [sp], #16\n"
             "    ret\n";
    finalAsm << "\n.globl _print_string\n";
    finalAsm << "_print_string:\n"
             "    stp x29, x30, [sp, #-16]!\n"
             "    mov x29, sp\n"
             "    mov x4, x0\n" // save pointer to string
             "    mov x1, x0\n"
             "    mov x2, #0\n"
             ".find_length_arm:\n"
             "    ldrb w3, [x1], #1\n"
             "    cbz w3, .length_found\n"
             "    add x2, x2, #1\n"
             "    b .find_length_arm\n"
             ".length_found:\n"
             "    mov x1, x4\n" // restore pointer for write
             "    mov x0, #1\n" // stdout file descriptor
             "    bl _write\n"
             "    ldp x29, x30, [sp], #16\n"
             "    ret\n";
    finalAsm << "\n.globl _input\n";
    finalAsm << "_input:\n"
             "    stp x29, x30, [sp, #-16]!\n"
             "    mov x29, sp\n";
    finalAsm << genLoadAddress("x1", "_input_buffer");
    finalAsm << "    mov x2, #256\n"
             "    mov x0, #0\n" // stdin file descriptor
             "    bl _read\n";
    finalAsm << genLoadAddress("x0", "_input_buffer");
    finalAsm << "    ldp x29, x30, [sp], #16\n"
             "    ret\n";
    finalAsm << "\n.extern _write\n";
    finalAsm << "\n.extern _read\n";
    finalAsm << "\n.extern _exit\n";
    finalAsm << "\n.extern _atoi\n";
    finalAsm << "\n.globl _for_loop_stub\n";
    finalAsm << "_for_loop_stub:\n";
    finalAsm << genLoadAddress("x0", "_for_msg");
    finalAsm << "    bl _print_string\n"
             "    ret\n";
    finalAsm << "\n.globl _for_msg\n";
    finalAsm << "_for_msg: .asciz \"[For loop executed]\\n\"\n";
    std::string assemblyCode = finalAsm.str();
    std::string assemblyFile = outputFile + ".s";
    std::ofstream asm_ofs(assemblyFile);
    if (!asm_ofs)
        throw std::runtime_error("Failed to open assembly file for writing.");
    asm_ofs << assemblyCode;
    asm_ofs.close();
    std::cerr << "[DEBUG] Assembly file generated: " << assemblyFile << "\n";
    // Force the system assembler.
    std::string compileCommand = "clang " + assemblyFile + " -o " + outputFile + " -e _start -no-integrated-as -lc";
    std::cerr << "[DEBUG] Running compile command: " << compileCommand << "\n";
    if (std::system(compileCommand.c_str()) != 0)
        throw std::runtime_error("Compilation (clang linking) failed.");
    std::remove(assemblyFile.c_str());
    std::cerr << "[DEBUG] Binary executable generated: " << outputFile << "\n";
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: ./compile <source_file> <output_file>\n";
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

    std::cerr << "[DEBUG] Starting lexing...\n";
    Lexer lexer(source, argv[1]);
    std::vector<Token> tokens = lexer.tokenize();
    std::cerr << "[DEBUG] Lexing complete. Tokens count: " << tokens.size() << "\n";

    std::cerr << "[DEBUG] Starting parsing...\n";
    Parser parser(tokens);
    ASTNode root = parser.parse();
    std::cerr << "[DEBUG] Parsing complete. AST structure:\n";
    root.print();

    std::cerr << "[DEBUG] Starting code generation...\n";
    CodeGenerator codeGen(root, argv[1]);
    try {
        codeGen.generateBinary(argv[2]);
    } catch (const std::exception &ex) {
        std::cerr << "compile: " << "\033[1;31merror:\033[0;1m " << ex.what() << "\033[0m\n";
        return 1;
    }
    return 0;
}
