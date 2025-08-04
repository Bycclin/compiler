// ast.h
#ifndef AST_H
#define AST_H

#include <string>
#include <vector>
#include <set>
#include <map>
#include "parser.h" // Contains ASTNode definition

class CodeGenerator {
public:
    explicit CodeGenerator(const ASTNode &ast);
    // Added assemblyOnly flag to emit .s only when -S is passed
    void generateBinary(const std::string &outputFile, bool assemblyOnly = false);

private:
    // Private members
    ASTNode astRoot;
    std::string dataSection;
    std::string functionSection;
    int labelCounter;
    std::set<std::string> compiledModules;
    std::map<std::string, std::string> variableLabels;
    bool sysPathListGenerated;
    std::string sysPathListLabel;
    std::set<std::string> definedNames;

    // Private methods
    std::string generateAssembly(const ASTNode &node, int indentLevel = 1, bool inFunction = false, const std::string &brkLabel = "");
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
    std::string processLiteral(const std::string &token, bool inPrintContext);
};

#endif // AST_H
