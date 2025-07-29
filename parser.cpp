#include "parser.h"
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <set>
#include <algorithm>
ASTNode::ASTNode() : type("Unknown"), value(""), token_ref(TokenType::UNKNOWN, "") {}
ASTNode::ASTNode(const std::string& type, const Token& ref_tok, const std::vector<ASTNode>& children)
    : type(type), value(""), children(children), token_ref(ref_tok) {}
ASTNode::ASTNode(const std::string& type, const std::string& value, const Token& ref_tok, const std::vector<ASTNode>& children)
    : type(type), value(value), children(children), token_ref(ref_tok) {}
void ASTNode::print(size_t level) const {
    std::string indent(level * 2, ' ');
    std::cerr << indent << "Node(Type: " << type;
    if (!value.empty()) {
        std::cerr << ", Value: \"" << value << "\"";
    }
    if (token_ref.type != TokenType::UNKNOWN && token_ref.type != TokenType::END ) {
         std::cerr << ", Line: " << token_ref.line << ", Col: " << token_ref.column;
    }
    if (!children.empty()) {
        std::cerr << ", Children: [\n";
        for (const auto &child : children) {
            child.print(level + 1);
        }
        std::cerr << indent << "])\n";
    } else {
        std::cerr << ")\n";
    }
}
std::string Parser::formatError(const std::string &msg, const Token &tk) {
    std::ostringstream oss;
    oss << tk.filename << ":" << tk.line << ":" << tk.column << ": error: " << msg;
    if (tk.type != TokenType::END && tk.type != TokenType::UNKNOWN) {
        oss << " (found token " << tk.type << " '" << tk.value << "').\n";
    } else {
        oss << " (at " << tk.type << ").\n";
    }
    return oss.str();
}
Parser::Parser(const std::vector<Token>& tokens)
    : tokens_list(tokens), position(0) {
    if (tokens_list.empty()) {
        Token dummyEnd(TokenType::END, "EOF_MARKER", 0,0,"<empty_input>");
        tokens_list.push_back(dummyEnd);
    }
}
Token Parser::currentToken() const {
    if (position >= tokens_list.size()) {
        if (!tokens_list.empty() && tokens_list.back().type == TokenType::END) return tokens_list.back();
        return Token(TokenType::END, "EOF_OVERRUN_MARKER",
                     !tokens_list.empty() ? tokens_list.back().line : 1,
                     !tokens_list.empty() ? tokens_list.back().column : 1,
                     !tokens_list.empty() ? tokens_list.back().filename : "unknown_ overrun");
    }
    return tokens_list[position];
}
Token Parser::consumeToken() {
    Token current = currentToken();
    if (current.type == TokenType::END && position >= tokens_list.size()-1) {
        if (position < tokens_list.size()) position++;
        return current;
    }
    if (position >= tokens_list.size()) {
        throw std::runtime_error(formatError("Unexpected end of input, tried to consume past END token.", current));
    }
    return tokens_list[position++];
}
Token Parser::consumeToken(TokenType expectedType) {
    Token tk = currentToken();
    if (tk.type != expectedType) {
        std::ostringstream oss;
        oss << "Expected token type " << expectedType;
        throw std::runtime_error(formatError(oss.str(), tk));
    }
    return consumeToken();
}
void Parser::expectToken(TokenType expectedType) {
    Token tk = currentToken();
    if (tk.type != expectedType) {
        std::ostringstream oss;
        oss << "Expected token type " << expectedType;
        throw std::runtime_error(formatError(oss.str(), tk));
    }
    consumeToken();
}
void Parser::expectToken(TokenType expectedType, const std::string& value) {
    Token tk = currentToken();
    if (tk.type != expectedType || tk.value != value) {
        std::ostringstream oss;
        oss << "Expected token " << expectedType << " with value '" << value << "'";
        throw std::runtime_error(formatError(oss.str(), tk));
    }
    consumeToken();
}
bool Parser::matchToken(TokenType type) {
    if (currentToken().type == type) {
        consumeToken();
        return true;
    }
    return false;
}
bool Parser::matchToken(TokenType type, const std::string& value) {
    if (currentToken().type == type && currentToken().value == value) {
        consumeToken();
        return true;
    }
    return false;
}
ASTNode Parser::parse() {
    return parseProgram();
}
ASTNode Parser::parseProgram() {
    Token startToken = currentToken();
    std::vector<ASTNode> statements;
    while (position < tokens_list.size() && currentToken().type != TokenType::END) {
        while (position < tokens_list.size() && (currentToken().type == TokenType::NEWLINE || currentToken().type == TokenType::DEDENT)) {
            consumeToken();
        }
        if (position >= tokens_list.size() || currentToken().type == TokenType::END) {
            break;
        }
        statements.push_back(parseStatement());
    }
    return ASTNode("Program", startToken, statements);
}
ASTNode Parser::parseStatement() {
    Token tk = currentToken();
    if (tk.type == TokenType::KEYWORD) {
        if (tk.value == "if" || tk.value == "while" || tk.value == "for" ||
            tk.value == "def" || tk.value == "class" || tk.value == "with" ||
            tk.value == "try") {
            return parseCompoundStatement();
        }
    }
    return parseSimpleStatement();
}
ASTNode Parser::parseCompoundStatement() {
    Token tk = currentToken();
    if (tk.type == TokenType::KEYWORD) {
        if (tk.value == "if") return parseIfStatement();
        if (tk.value == "while") return parseWhileStatement();
        if (tk.value == "def") return parseFunctionDef();
    }
    throw std::runtime_error(formatError("Expected a compound statement keyword (if, while, def, etc.)", tk));
}
ASTNode Parser::parseSimpleStatement() {
    Token startToken = currentToken();
    std::vector<ASTNode> small_stmts;
    small_stmts.push_back(parseSmallStatement());
    while (matchToken(TokenType::PUNCTUATION, ";")) {
        if (currentToken().type == TokenType::NEWLINE ||
            (currentToken().type == TokenType::END && position >= tokens_list.size()-1) ||
            currentToken().type == TokenType::DEDENT) {
            break;
        }
        small_stmts.push_back(parseSmallStatement());
    }
    if (currentToken().type == TokenType::NEWLINE) {
        consumeToken(TokenType::NEWLINE);
    } else if (!((currentToken().type == TokenType::END && position >= tokens_list.size()-1) || currentToken().type == TokenType::DEDENT)) {
        throw std::runtime_error(formatError("Simple statement list not terminated by NEWLINE, EOF, or DEDENT", currentToken()));
    }
    if (small_stmts.size() == 1) return small_stmts[0];
    return ASTNode("SimpleStmtList", startToken, small_stmts);
}
ASTNode Parser::parseSmallStatement() {
    Token tk = currentToken();
    if (tk.type == TokenType::NEWLINE || tk.type == TokenType::DEDENT || (tk.type == TokenType::END && position >= tokens_list.size()-1)) {
        throw std::runtime_error(formatError("Unexpected token at start of a small statement. Expected an expression, assignment, or keyword.", tk));
    }
    if (tk.type == TokenType::KEYWORD) {
        if (tk.value == "break") return parseBreakStatement();
        if (tk.value == "return") return parseReturnStatement();
        if (tk.value == "pass") {
            Token pass_tok = consumeToken();
            return ASTNode("PassStatement", pass_tok);
        }
    }
    if (tk.type == TokenType::IDENTIFIER && (position + 1 < tokens_list.size()) &&
        tokens_list[position + 1].type == TokenType::OPERATOR && tokens_list[position + 1].value == "=") {
        return parseAssignmentStatement();
    }
    return parseExpressionStatement();
}
ASTNode Parser::parseBreakStatement() {
    Token break_tok = consumeToken(TokenType::KEYWORD);
    return ASTNode("BreakStatement", break_tok);
}
ASTNode Parser::parseReturnStatement() {
    Token ret_tok = consumeToken(TokenType::KEYWORD);
    std::vector<ASTNode> children;
    if (currentToken().type != TokenType::NEWLINE &&
        !(currentToken().type == TokenType::PUNCTUATION && currentToken().value == ";") &&
        currentToken().type != TokenType::DEDENT && !(currentToken().type == TokenType::END && position >= tokens_list.size()-1)) {
        children.push_back(parseArgument());
    }
    return ASTNode("ReturnStatement", ret_tok, children);
}
ASTNode Parser::parseAssignmentStatement() {
    Token var_token = consumeToken(TokenType::IDENTIFIER);
    expectToken(TokenType::OPERATOR, "=");
    ASTNode value_node = parseArgument();
    return ASTNode("Assignment", var_token.value, var_token, {value_node});
}
ASTNode Parser::parseExpressionStatement() {
    Token expr_start_tok = currentToken();
    ASTNode expr_node = parseArgument();
    return ASTNode("ExpressionStatement", expr_start_tok, {expr_node});
}
ASTNode Parser::parseSuite() {
    Token suite_start_token = currentToken();
    std::vector<ASTNode> statements;
    if (matchToken(TokenType::NEWLINE)) {
        expectToken(TokenType::INDENT);
        while (currentToken().type != TokenType::DEDENT && !(currentToken().type == TokenType::END && position >= tokens_list.size()-1)) {
            while(currentToken().type == TokenType::NEWLINE) {
                consumeToken();
            }
            if(currentToken().type == TokenType::DEDENT || (currentToken().type == TokenType::END && position >= tokens_list.size()-1)) {
                break;
            }
            statements.push_back(parseStatement());
        }
        if (currentToken().type == TokenType::DEDENT) {
            consumeToken(TokenType::DEDENT);
        } else if (!((currentToken().type == TokenType::END && position >= tokens_list.size()-1))) {
             throw std::runtime_error(formatError("Expected DEDENT to close block", currentToken()));
        }
    } else {
        statements.push_back(parseSimpleStatement());
    }
    if (statements.empty()) {
        return ASTNode("Suite", suite_start_token, {ASTNode("PassStatement", suite_start_token)});
    }
    return ASTNode("Suite", suite_start_token, statements);
}
ASTNode Parser::parseIfStatement() {
    Token if_tok = consumeToken(TokenType::KEYWORD);
    ASTNode condition = parseArgument();
    expectToken(TokenType::PUNCTUATION, ":");
    ASTNode then_block = parseSuite();
    std::vector<ASTNode> children = {condition, then_block};
    if (currentToken().type == TokenType::KEYWORD && currentToken().value == "elif") {
        children.push_back(parseIfStatement());
    } else if (matchToken(TokenType::KEYWORD, "else")) {
        expectToken(TokenType::PUNCTUATION, ":");
        children.push_back(parseSuite());
    }
    return ASTNode("If", if_tok, children);
}
ASTNode Parser::parseWhileStatement() {
    Token while_tok = consumeToken(TokenType::KEYWORD);
    ASTNode condition = parseArgument();
    expectToken(TokenType::PUNCTUATION, ":");
    ASTNode body = parseSuite();
    return ASTNode("While", while_tok, {condition, body});
}
ASTNode Parser::parseFunctionDef() {
    Token def_tok = consumeToken(TokenType::KEYWORD);
    Token name_tok = consumeToken(TokenType::IDENTIFIER);
    expectToken(TokenType::PUNCTUATION, "(");
    std::vector<ASTNode> params_nodes;
    bool first_param = true;
    while(currentToken().type != TokenType::PUNCTUATION || currentToken().value != ")"){
        if(!first_param){
            expectToken(TokenType::PUNCTUATION, ",");
        }
        first_param = false;
        Token param_tok = consumeToken(TokenType::IDENTIFIER);
        params_nodes.push_back(ASTNode("Parameter", param_tok.value, param_tok));
    }
    expectToken(TokenType::PUNCTUATION, ")");
    expectToken(TokenType::PUNCTUATION, ":");
    ASTNode body = parseSuite();
    ASTNode params_container("Parameters", name_tok, params_nodes);
    return ASTNode("FunctionDef", name_tok.value, def_tok, {params_container, body});
}
ASTNode Parser::parseArgument() {
    return parseComparison();
}
ASTNode Parser::parseComparison() {
    Token expr_start_tok = currentToken();
    ASTNode left = parsePrimary();
    while (currentToken().type == TokenType::OPERATOR &&
           (currentToken().value == "<" || currentToken().value == ">" ||
            currentToken().value == "==" || currentToken().value == "!=" ||
            currentToken().value == "<=" || currentToken().value == ">=")) {
        Token op_tok = consumeToken(TokenType::OPERATOR);
        ASTNode right = parsePrimary();
        left = ASTNode("BinaryOp", op_tok.value, op_tok, {left, right});
    }
    return left;
}
ASTNode Parser::parsePrimary() {
    Token tk = currentToken();
    if (tk.type == TokenType::NUMBER) {
        consumeToken();
        return ASTNode("NumberLiteral", tk.value, tk);
    } else if (tk.type == TokenType::STRING) {
        consumeToken();
        return ASTNode("StringLiteral", tk.value, tk);
    } else if (tk.type == TokenType::IDENTIFIER) {
        if (position + 1 < tokens_list.size() && tokens_list[position + 1].type == TokenType::PUNCTUATION && tokens_list[position + 1].value == "(") {
            return parseFunctionCall();
        }
        consumeToken();
        return ASTNode("Identifier", tk.value, tk);
    } else if (tk.type == TokenType::BUILTIN) {
         if (position + 1 < tokens_list.size() && tokens_list[position + 1].type == TokenType::PUNCTUATION && tokens_list[position + 1].value == "(") {
            return parseFunctionCall();
        }
        throw std::runtime_error(formatError("Expected '(' after built-in function name", tk));
    } else if (tk.type == TokenType::KEYWORD && (tk.value == "True" || tk.value == "False" || tk.value == "None")) {
        consumeToken();
        return ASTNode("KeywordLiteral", tk.value, tk);
    } else if (matchToken(TokenType::PUNCTUATION, "(")) {
        ASTNode expr = parseArgument();
        expectToken(TokenType::PUNCTUATION, ")");
        return expr;
    }
    throw std::runtime_error(formatError("Unexpected token in expression primary", tk));
}
ASTNode Parser::parseFunctionCall() {
    Token name_tok = currentToken();
    if (name_tok.type != TokenType::IDENTIFIER && name_tok.type != TokenType::BUILTIN) {
         throw std::runtime_error(formatError("Expected function name (Identifier or Builtin) for call", name_tok));
    }
    consumeToken();
    expectToken(TokenType::PUNCTUATION, "(");
    std::vector<ASTNode> args;
    bool first_arg = true;
    while (!(currentToken().type == TokenType::PUNCTUATION && currentToken().value == ")")) {
        if (!first_arg) {
            expectToken(TokenType::PUNCTUATION, ",");
        }
        first_arg = false;
        if (currentToken().type == TokenType::IDENTIFIER &&
            (position + 1 < tokens_list.size()) &&
            tokens_list[position+1].type == TokenType::OPERATOR &&
            tokens_list[position+1].value == "=")
        {
            Token kw_name_tok = consumeToken(TokenType::IDENTIFIER);
            expectToken(TokenType::OPERATOR, "=");
            ASTNode kw_val_node = parseArgument();
            args.push_back(ASTNode("KeywordArgument", kw_name_tok.value, kw_name_tok, {kw_val_node}));
        } else {
            args.push_back(parseArgument());
        }
    }
    expectToken(TokenType::PUNCTUATION, ")");
    return ASTNode("FunctionCall", name_tok.value, name_tok, args);
}
