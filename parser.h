#ifndef PARSER_H
#define PARSER_H
#include <string>
#include <vector>
#include "lexer.h"
struct ASTNode {
    std::string type;
    std::string value;
    std::vector<ASTNode> children;
    Token token_ref;
    ASTNode();
    ASTNode(const std::string& type, const Token& ref_tok, const std::vector<ASTNode>& children = {});
    ASTNode(const std::string& type, const std::string& value, const Token& ref_tok, const std::vector<ASTNode>& children = {});
    void print(size_t level = 0) const;
};
class Parser {
public:
    explicit Parser(const std::vector<Token>& tokens);
    ASTNode parse();
private:
    std::vector<Token> tokens_list;
    size_t position;
    Token currentToken() const;
    Token consumeToken();
    Token consumeToken(TokenType expectedType);
    void expectToken(TokenType expectedType);
    bool matchToken(TokenType type);
    void expectToken(TokenType expectedType, const std::string& value);
    bool matchToken(TokenType type, const std::string& value);
    ASTNode parseProgram();
    ASTNode parseStatement();
    ASTNode parseSimpleStatement();
    ASTNode parseSmallStatement();
    ASTNode parseCompoundStatement();
    ASTNode parseSuite();
    ASTNode parseIfStatement();
    ASTNode parseWhileStatement();
    ASTNode parseFunctionDef();
    ASTNode parseReturnStatement();
    ASTNode parseExpressionStatement();
    ASTNode parseAssignmentStatement();
    ASTNode parseBreakStatement();
    ASTNode parseArgument();
    ASTNode parseFunctionCall();
    ASTNode parsePrimary();
    ASTNode parseComparison();
    std::string formatError(const std::string &msg, const Token &tk);
    std::string getLineSnippet(const Token &tk);
};
#endif
