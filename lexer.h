#ifndef LEXER_H
#define LEXER_H

#include <string>
#include <vector>
#include <iostream>

enum class TokenType {
    KEYWORD,
    IDENTIFIER,
    NUMBER,
    STRING,
    OPERATOR,
    PUNCTUATION,
    IMPORT,
    END
};

struct Token {
    TokenType type;
    std::string value;
    int line;
    int column;
    std::string filename; // New field for filename

    Token(TokenType type, const std::string& value, int line = 0, int column = 0, const std::string& filename = "")
        : type(type), value(value), line(line), column(column), filename(filename) {}
};

std::ostream& operator<<(std::ostream& os, const TokenType& type);

class Lexer {
public:
    // Accept an optional filename.
    explicit Lexer(const std::string& source, const std::string& filename = "");
    std::vector<Token> tokenize();

private:
    std::string source;
    size_t position;
    int line;
    int column;
    std::string filename; // Store filename
    std::vector<std::string> keywords;

    void handleWhitespace(char current);
    Token handleIdentifier();
    Token handleNumber();
    Token handleString(char quote);
    Token handleFString();
    void handleComment();
    Token handleOperator();
    bool isOperator(char current);
    bool isPunctuation(char current);
    Token handlePunctuation();

    // New helper to get the content of the current line for traceback purposes.
    std::string getLineSnippet(int lineNumber);
};

#endif // LEXER_H
