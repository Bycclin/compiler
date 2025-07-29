#include "lexer.h"
#include <cctype>
#include <stdexcept>
#include <algorithm>
#include <iterator>
#include <sstream>
#include <set>
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
        case TokenType::NEWLINE: os << "NEWLINE"; break;
        case TokenType::INDENT: os << "INDENT"; break;
        case TokenType::DEDENT: os << "DEDENT"; break;
        case TokenType::END: os << "END"; break;
        default: os << "UNKNOWN"; break;
    }
    return os;
}
Lexer::Lexer(const std::string& source, const std::string& filename)
    : source(source), position(0), line(1), column(1), filename(filename),
      at_line_start(true), paren_level(0) {
    keywords = {
        "import", "def", "if", "elif", "else", "while", "return",
        "for", "in", "is", "break", "continue", "class", "try", "except",
        "raise", "assert", "with", "as", "pass", "finally", "yield",
        "lambda", "from", "global", "True", "False", "None"
    };
    indent_stack.push_back(0);
}
std::vector<Token> Lexer::tokenize() {
    std::vector<Token> tokens;
    while (position < source.size()) {
        if (at_line_start && paren_level == 0) {
            at_line_start = false;
            int current_indent = 0;
            size_t indent_scan_pos = position;
            int indent_start_column = column;
            while (indent_scan_pos < source.size() && source[indent_scan_pos] == ' ') {
                current_indent++;
                indent_scan_pos++;
            }
            if (indent_scan_pos < source.size() && source[indent_scan_pos] == '\t') {
                 std::string snippet = getLineSnippet(line);
                 std::ostringstream oss;
                 oss << filename << ":" << line << ":" << (column + (indent_scan_pos - position))
                     << ": error: IndentationError: tabs are not allowed for indentation.\n"
                     << snippet << "\n"
                     << std::string(column + (indent_scan_pos - position) -1, ' ') << "^\n";
                 throw std::runtime_error(oss.str());
            }
            bool is_blank_or_comment_line = false;
            if (indent_scan_pos == source.size() || source[indent_scan_pos] == '\n' || source[indent_scan_pos] == '#') {
                is_blank_or_comment_line = true;
            }
            if (!is_blank_or_comment_line) {
                position = indent_scan_pos;
                column += current_indent;
                if (current_indent > indent_stack.back()) {
                    tokens.push_back(Token(TokenType::INDENT, "INDENT", line, indent_start_column, filename));
                    indent_stack.push_back(current_indent);
                } else {
                    while (current_indent < indent_stack.back()) {
                        indent_stack.pop_back();
                        tokens.push_back(Token(TokenType::DEDENT, "DEDENT", line, indent_start_column, filename));
                    }
                    if (current_indent != indent_stack.back()) {
                        std::string snippet = getLineSnippet(line);
                        std::ostringstream oss;
                        oss << filename << ":" << line << ":" << indent_start_column
                            << ": error: IndentationError: unindent does not match any outer indentation level.\n"
                            << snippet << "\n"
                            << std::string(indent_start_column + current_indent - 1, ' ') << "^\n";
                        throw std::runtime_error(oss.str());
                    }
                }
            } else {
                position = indent_scan_pos;
            }
        }
        if (position >= source.size()) break;
        char current = source[position];
        if (current == '\n') {
            if (paren_level == 0) {
                tokens.push_back(Token(TokenType::NEWLINE, "\\n", line, column, filename));
                at_line_start = true;
            }
            position++;
            line++;
            column = 1;
        } else if (current == '#') {
            handleComment();
        } else if (std::isspace(current)) {
            position++;
            column++;
        } else if (std::isalpha(current) || current == '_') {
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
        } else if (isOperator(current)) {
            tokens.push_back(handleOperator());
        } else if (isPunctuation(current)) {
            char punc_char = current;
            tokens.push_back(handlePunctuation());
            if (punc_char == '(' || punc_char == '[' || punc_char == '{') {
                paren_level++;
            } else if (punc_char == ')' || punc_char == ']' || punc_char == '}') {
                paren_level--;
                if (paren_level < 0) {
                     throw std::runtime_error(filename + ":" + std::to_string(line) + ":" + std::to_string(column-1) + ": error: Unmatched closing parenthesis/bracket/brace.");
                }
            }
        } else {
            std::string snippet = getLineSnippet(line);
            std::ostringstream oss;
            oss << filename << ":" << line << ":" << column
                << ": error: Unexpected character '" << current << "'.\n"
                << snippet << "\n"
                << std::string(column - 1, ' ') << "^\n";
            throw std::runtime_error(oss.str());
        }
    }
    if (paren_level == 0) {
        if (tokens.empty() || (tokens.back().type != TokenType::NEWLINE)) {
            if (source.empty() || source.back() != '\n') {
                tokens.push_back(Token(TokenType::NEWLINE, "\\n", line, column, filename));
            }
        }
    } else {
         throw std::runtime_error(filename + ":" + std::to_string(line) + ":" + std::to_string(column) + ": error: EOF in multi-line statement (parentheses not closed).");
    }
    while (indent_stack.back() > 0) {
        indent_stack.pop_back();
        int dedent_line = tokens.empty() ? line : tokens.back().line;
        if (!tokens.empty() && tokens.back().type == TokenType::NEWLINE) {
            dedent_line = tokens.back().line;
        }
        tokens.push_back(Token(TokenType::DEDENT, "DEDENT", dedent_line, 1, filename));
    }
    tokens.push_back(Token(TokenType::END, "END", line, column, filename));
    return tokens;
}
void Lexer::handleComment() {
    while (position < source.size() && source[position] != '\n') {
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
    char start_quote = quote;
    int quote_len = 1;
    ++position;
    ++column;
    if (position + 1 < source.size() && source[position] == quote && source[position+1] == quote) {
        position += 2;
        column += 2;
        quote_len = 3;
    }
    std::string value_content;
    size_t strStart = position;
    while (position < source.size()) {
        if (source[position] == '\\') {
            value_content += source.substr(strStart, position - strStart);
            position++;
            if (position < source.size()) {
                switch(source[position]) {
                    case 'n': value_content += '\n'; break;
                    case 't': value_content += '\t'; break;
                    case '\\': value_content += '\\'; break;
                    case '"': value_content += '"'; break;
                    case '\'': value_content += '\''; break;
                    default: value_content += source[position];
                }
                position++;
                strStart = position;
            } else {
                 std::string snippet = getLineSnippet(tokenLine);
                 std::ostringstream oss;
                 oss << filename << ":" << tokenLine << ":" << (column + (position - strStart) -1)
                     << ": error: EOF while scanning escape sequence in string literal.\n" << snippet << "\n"
                     << std::string(tokenColumn -1 + (position - strStart) -1, ' ') << "^\n";
                 throw std::runtime_error(oss.str());
            }
        } else if (source[position] == start_quote) {
            if (quote_len == 1) {
                value_content += source.substr(strStart, position - strStart);
                position++;
                column += (position - strStart);
                return Token(TokenType::STRING, std::string(1, start_quote) + value_content + std::string(1, start_quote), tokenLine, tokenColumn, filename);
            } else {
                if (position + 2 < source.size() && source[position+1] == start_quote && source[position+2] == start_quote) {
                    value_content += source.substr(strStart, position - strStart);
                    position += 3;
                    column += (position - strStart);
                    return Token(TokenType::STRING, std::string(3, start_quote) + value_content + std::string(3, start_quote), tokenLine, tokenColumn, filename);
                } else {
                    position++;
                }
            }
        } else if (source[position] == '\n' && quote_len == 1) {
            std::string snippet = getLineSnippet(tokenLine);
            std::ostringstream oss;
            oss << filename << ":" << tokenLine << ":" << tokenColumn
                << ": error: Unterminated string literal (found newline).\n"
                << snippet << "\n"
                << std::string(tokenColumn - 1, ' ') << "^\n";
            throw std::runtime_error(oss.str());
        } else {
            position++;
        }
    }
    std::string snippet = getLineSnippet(tokenLine);
    std::ostringstream oss;
    oss << filename << ":" << tokenLine << ":" << tokenColumn
        << ": error: Unterminated " << (quote_len==3 ? "triple-quoted " : "") << "string literal.\n"
        << snippet << "\n"
        << std::string(tokenColumn - 1, ' ') << "^\n";
    throw std::runtime_error(oss.str());
}
Token Lexer::handleFString() {
    int tokenLine = line;
    int tokenColumn = column;
    char fChar = source[position];
    position++; column++;
    char quote = source[position];
    std::string prefix = std::string(1, fChar) + std::string(1, quote);
    int f_quote_len = 1;
    position++; column++;
    if (position + 1 < source.size() && source[position] == quote && source[position+1] == quote) {
        position += 2; column += 2;
        f_quote_len = 3;
        prefix += std::string(2, quote);
    }
    std::string value_content;
    size_t strStart = position;
    while(position < source.size()){
        if(source[position] == quote){
            if(f_quote_len == 1){
                value_content += source.substr(strStart, position - strStart);
                position++; column += (position - strStart);
                return Token(TokenType::STRING, prefix + value_content + std::string(1, quote), tokenLine, tokenColumn, filename);
            } else {
                if(position + 2 < source.size() && source[position+1] == quote && source[position+2] == quote){
                    value_content += source.substr(strStart, position - strStart);
                    position += 3; column += (position - strStart);
                    return Token(TokenType::STRING, prefix + value_content + std::string(3, quote), tokenLine, tokenColumn, filename);
                } else {
                    position++;
                }
            }
        } else {
            position++;
        }
    }
    std::string snippet = getLineSnippet(tokenLine);
    std::ostringstream oss;
    oss << filename << ":" << tokenLine << ":" << tokenColumn
        << ": error: Unterminated f-string literal.\n" << snippet << "\n"
        << std::string(tokenColumn -1, ' ') << "^\n";
    throw std::runtime_error(oss.str());
}
bool Lexer::isOperator(char current) {
    static const std::string operators = "+-*/=<>!";
    return operators.find(current) != std::string::npos;
}
bool Lexer::isPunctuation(char current) {
    static const std::string punctuation = ",;(){}[].:";
    return punctuation.find(current) != std::string::npos;
}
Token Lexer::handleOperator() {
    int tokenLine = line;
    int tokenColumn = column;
    std::string op_val;
    op_val += source[position++];
    column++;
    if (op_val == "=" && position < source.size() && source[position] == '=') {
        op_val += source[position++];
        column++;
    } else if (op_val == "!" && position < source.size() && source[position] == '=') {
        op_val += source[position++];
        column++;
    } else if (op_val == "<" && position < source.size() && source[position] == '=') {
        op_val += source[position++];
        column++;
    } else if (op_val == ">" && position < source.size() && source[position] == '=') {
        op_val += source[position++];
        column++;
    }
    return Token(TokenType::OPERATOR, op_val, tokenLine, tokenColumn, filename);
}
Token Lexer::handlePunctuation() {
    int tokenLine = line;
    int tokenColumn = column;
    char punc_char = source[position++];
    column++;
    return Token(TokenType::PUNCTUATION, std::string(1, punc_char), tokenLine, tokenColumn, filename);
}
std::string Lexer::getLineSnippet(int lineNumber) {
    int currentLineNum = 1;
    size_t line_start_pos = 0;
    for(size_t i = 0; i < source.size(); ++i) {
        if (currentLineNum == lineNumber) {
            line_start_pos = i;
            break;
        }
        if (source[i] == '\n') {
            currentLineNum++;
        }
    }
    size_t line_end_pos = line_start_pos;
    while(line_end_pos < source.size() && source[line_end_pos] != '\n') {
        line_end_pos++;
    }
    return source.substr(line_start_pos, line_end_pos - line_start_pos);
}
