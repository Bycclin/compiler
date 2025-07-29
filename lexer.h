#ifndef LEXER_H
#define LEXER_H
#include <string>
#include <vector>
#include <iostream>
#include <stack>
enum class TokenType {
    KEYWORD,
    BUILTIN,
    IDENTIFIER,
    NUMBER,
    STRING,
    OPERATOR,
    PUNCTUATION,
    IMPORT,
    NEWLINE,
    INDENT,
    DEDENT,
    END,
    UNKNOWN
};
struct Token {
    TokenType type;
    std::string value;
    int line;
    int column;
    std::string filename;
    Token(TokenType type, const std::string& value, int line = 0, int column = 0, const std::string& filename = "")
        : type(type), value(value), line(line), column(column), filename(filename) {}
};
std::ostream& operator<<(std::ostream& os, const TokenType& type);
class Lexer {
public:
    explicit Lexer(const std::string& source, const std::string& filename = "");
    std::vector<Token> tokenize();
private:
    std::string source;
    size_t position;
    int line;
    int column;
    std::string filename;
    std::vector<std::string> keywords;
    std::vector<int> indent_stack;
    bool at_line_start;
    int paren_level;
    Token handleIdentifier();
    Token handleNumber();
    Token handleString(char quote);
    Token handleFString();
    void handleComment();
    Token handleOperator();
    bool isOperator(char current);
    bool isPunctuation(char current);
    Token handlePunctuation();
    std::string getLineSnippet(int lineNumber);
};
#endif
