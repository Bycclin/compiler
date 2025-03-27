#ifndef PARSER_H
#define PARSER_H

#include <string>
#include <vector>
#include "lexer.h"

struct ASTNode {
    std::string type;
    std::string value;
    std::vector<ASTNode> children;
    
    ASTNode();
    ASTNode(const std::string& type, const std::vector<ASTNode>& children = {});
    ASTNode(const std::string& type, const std::string& value, const std::vector<ASTNode>& children = {});
    void print(size_t level = 0) const;
};

class Parser {
public:
    explicit Parser(const std::vector<Token>& tokens);
    ASTNode parse();

private:
    std::vector<Token> tokens;
    size_t position;
    
    ASTNode parseProgram();
    ASTNode parseStatement();
    ASTNode parseSuite(); // New: Parse a block (suite) of statements.

    // Control flow constructs.
    ASTNode parseIf();
    ASTNode parseWhile();
    ASTNode parseFor();       // For-loop statement.
    ASTNode parseWith();      // With statement support.

    ASTNode parseImport();
    ASTNode parseFromImport();
    ASTNode parseFunctionCall();
    ASTNode parseArgument();
    
    // Literal parsing.
    ASTNode parseListLiteral();   // List literal support.
    
    ASTNode parseFunctionDef();
    ASTNode parseReturn();
    ASTNode parseYield();
    ASTNode parseClass();
    ASTNode parseLambda();

    Token getNextToken();
    void skipUnsupportedStatement();
    std::string currentTokenLocation() const;

    // Helper functions for enhanced error messages.
    std::string getLineSnippet(const Token &tk);
    std::string formatError(const std::string &msg, const Token &tk);
};

#endif // PARSER_H
