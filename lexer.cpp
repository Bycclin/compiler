#include "lexer.h"
#include <cctype>
#include <stdexcept>
#include <algorithm>
#include <iterator>
#include <sstream>
#include <set>

// Overloaded operator<< to print a TokenType.
std::ostream& operator<<(std::ostream& os, const TokenType& type) {
    switch (type) {
        case TokenType::KEYWORD: os << "KEYWORD"; break;
        case TokenType::BUILTIN: os << "BUILTIN"; break;
        case TokenType::IDENTIFIER: os << "IDENTIFIER"; break;
        case TokenType::NUMBER: os << "NUMBER"; break;
        case TokenType::STRING: os << "STRING"; break;
        case TokenType::OPERATOR: os << "OPERATOR"; break;
        case TokenType::PUNCTUATION: os << "PUNCTUATION"; break;
        case TokenType::IMPORT: os << "IMPORT"; break;
        case TokenType::END: os << "END"; break;
        default: os << "UNKNOWN"; break;
    }
    return os;
}

Lexer::Lexer(const std::string& source, const std::string& filename)
    : source(source), position(0), line(1), column(1), filename(filename) {
    // The keywords list now does NOT include built-in function names.
    keywords = {
        "import", "def", "if", "elif", "else", "while", "return",
        "for", "in", "is", "break", "continue", "class", "try", "except",
        "raise", "assert", "with", "as", "pass", "finally", "yield",
        "lambda", "from", "global"
    };
}

std::vector<Token> Lexer::tokenize() {
    std::vector<Token> tokens;
    while (position < source.size()) {
        char current = source[position];
        if (std::isspace(current)) {
            handleWhitespace(current);
        } else if (std::isalpha(current) || current == '_') {
            // Check for f-string literal.
            if ((current == 'f' || current == 'F') && position + 1 < source.size() &&
                (source[position+1] == '"' || source[position+1] == '\'')) {
                tokens.push_back(handleFString());
            } else {
                tokens.push_back(handleIdentifier());
            }
        } else if (std::isdigit(current)) {
            tokens.push_back(handleNumber());
        } else if (current == '"' || current == '\'') {
            tokens.push_back(handleString(current));
        } else if (current == '#') {
            handleComment();
        } else if (isOperator(current)) {
            tokens.push_back(handleOperator());
        } else if (isPunctuation(current)) {
            tokens.push_back(handlePunctuation());
        } else {
            ++position;
            ++column;
        }
    }
    // Append an END token.
    tokens.push_back(Token(TokenType::END, "", line, column, filename));
    return tokens;
}

void Lexer::handleWhitespace(char /*current*/) {
    while (position < source.size() && std::isspace(source[position])) {
        if (source[position] == '\n') {
            ++line;
            column = 1;
        } else {
            ++column;
        }
        ++position;
    }
}

Token Lexer::handleIdentifier() {
    int tokenLine = line;
    int tokenColumn = column;
    size_t start = position;
    while (position < source.size() &&
           (std::isalnum(source[position]) || source[position] == '_')) {
        ++position;
        ++column;
    }
    std::string value = source.substr(start, position - start);
    // Recognize built-in function names in the lexer.
    static const std::set<std::string> builtinFunctions = {"input", "print", "int", "ascii", "exec"};
    if (builtinFunctions.find(value) != builtinFunctions.end()) {
        return Token(TokenType::BUILTIN, value, tokenLine, tokenColumn, filename);
    }
    if (std::find(keywords.begin(), keywords.end(), value) != keywords.end()) {
        return Token(TokenType::KEYWORD, value, tokenLine, tokenColumn, filename);
    }
    return Token(TokenType::IDENTIFIER, value, tokenLine, tokenColumn, filename);
}

Token Lexer::handleNumber() {
    int tokenLine = line;
    int tokenColumn = column;
    size_t start = position;
    while (position < source.size() && std::isdigit(source[position])) {
        ++position;
        ++column;
    }
    return Token(TokenType::NUMBER, source.substr(start, position - start), tokenLine, tokenColumn, filename);
}

Token Lexer::handleString(char quote) {
    int tokenLine = line;
    int tokenColumn = column;
    ++position; // skip opening quote
    ++column;
    // Check for triple-quoted string.
    if (position + 1 < source.size() && source[position] == quote && source[position+1] == quote) {
        position += 2;
        column += 2;
        size_t strStart = position;
        while (position + 2 < source.size() &&
               !(source[position] == quote && source[position+1] == quote && source[position+2] == quote)) {
            ++position;
            ++column;
        }
        if (position + 2 >= source.size()) {
            std::string snippet = getLineSnippet(tokenLine);
            std::ostringstream oss;
            oss << filename << ":" << tokenLine << ":" << tokenColumn 
                << ": error: Unterminated triple-quoted string literal.\n"
                << snippet << "\n"
                << std::string(tokenColumn - 1, ' ') << "^\n";
            throw std::runtime_error(oss.str());
        }
        std::string value = source.substr(strStart, position - strStart);
        position += 3;
        column += 3;
        return Token(TokenType::STRING, std::string(3, quote) + value + std::string(3, quote), tokenLine, tokenColumn, filename);
    } else {
        size_t strStart = position;
        while (position < source.size() && source[position] != quote) {
            ++position;
            ++column;
        }
        if (position >= source.size()) {
            std::string snippet = getLineSnippet(tokenLine);
            std::ostringstream oss;
            oss << filename << ":" << tokenLine << ":" << tokenColumn 
                << ": error: Unterminated string literal.\n"
                << snippet << "\n"
                << std::string(tokenColumn - 1, ' ') << "^\n";
            throw std::runtime_error(oss.str());
        }
        std::string value = source.substr(strStart, position - strStart);
        ++position;
        ++column;
        return Token(TokenType::STRING, std::string(1, quote) + value + std::string(1, quote), tokenLine, tokenColumn, filename);
    }
}

Token Lexer::handleFString() {
    int tokenLine = line;
    int tokenColumn = column;
    char fChar = source[position];
    ++position;
    ++column;
    if (position >= source.size() || (source[position] != '"' && source[position] != '\'')) {
        return handleIdentifier();
    }
    char quote = source[position];
    ++position;
    ++column;
    size_t strStart = position;
    while (position < source.size() && source[position] != quote) {
        ++position;
        ++column;
    }
    if (position >= source.size()) {
        std::string snippet = getLineSnippet(tokenLine);
        std::ostringstream oss;
        oss << filename << ":" << tokenLine << ":" << tokenColumn 
            << ": error: Unterminated f-string literal.\n"
            << snippet << "\n"
            << std::string(tokenColumn - 1, ' ') << "^\n";
        throw std::runtime_error(oss.str());
    }
    std::string inner = source.substr(strStart, position - strStart);
    ++position;
    ++column;
    std::string tokenVal = std::string(1, fChar) + std::string(1, quote) + inner + std::string(1, quote);
    return Token(TokenType::STRING, tokenVal, tokenLine, tokenColumn, filename);
}

void Lexer::handleComment() {
    while (position < source.size() && source[position] != '\n') {
        ++position;
    }
}

bool Lexer::isOperator(char current) {
    static const std::string operators = "+-*/=<>!";
    return operators.find(current) != std::string::npos;
}

bool Lexer::isPunctuation(char current) {
    static const std::string punctuation = ",;(){}[].:";
    return punctuation.find(current) != std::string::npos;
}

// Updated operator handler to support multi-character operators like "=="
Token Lexer::handleOperator() {
    int tokenLine = line;
    int tokenColumn = column;
    char current = source[position];
    std::string op(1, current);
    ++position;
    ++column;
    // Check for a two-character operator (e.g. "==")
    if (current == '=' && position < source.size() && source[position] == '=') {
        op.push_back(source[position]);
        ++position;
        ++column;
    }
    return Token(TokenType::OPERATOR, op, tokenLine, tokenColumn, filename);
}

Token Lexer::handlePunctuation() {
    int tokenLine = line;
    int tokenColumn = column;
    char current = source[position++];
    ++column;
    return Token(TokenType::PUNCTUATION, std::string(1, current), tokenLine, tokenColumn, filename);
}

std::string Lexer::getLineSnippet(int lineNumber) {
    int currentLine = 1;
    size_t start = 0, end = 0;
    size_t pos = 0;
    while (pos < source.size()) {
        if (currentLine == lineNumber) {
            start = pos;
            while (pos < source.size() && source[pos] != '\n') {
                pos++;
            }
            end = pos;
            break;
        }
        if (source[pos] == '\n')
            currentLine++;
        pos++;
    }
    return source.substr(start, end - start);
}
