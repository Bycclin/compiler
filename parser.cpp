#include "parser.h"
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <set>
#include <algorithm>
#include <cctype>
#include <fstream>

//------------------------------------------------------------
// ASTNode definitions
//------------------------------------------------------------
ASTNode::ASTNode() : type(""), value(""), children() {}

ASTNode::ASTNode(const std::string& type, const std::vector<ASTNode>& children)
    : type(type), value(""), children(children) {}

ASTNode::ASTNode(const std::string& type, const std::string& value, const std::vector<ASTNode>& children)
    : type(type), value(value), children(children) {}

void ASTNode::print(size_t level) const {
    std::string indent(level, '-');
    std::cerr << indent << "Node(Type: " << type << ", Value: " << value << ")\n";
    for (const auto &child : children)
        child.print(level + 2);
}

//------------------------------------------------------------
// Parser helper: current token location
//------------------------------------------------------------
std::string Parser::currentTokenLocation() const {
    if (position < tokens.size()) {
        const Token &tk = tokens[position];
        std::string loc;
        if (!tk.filename.empty())
            loc = tk.filename + ":";
        loc += std::to_string(tk.line) + ":" + std::to_string(tk.column);
        return " at " + loc;
    }
    return " at end of file";
}

//------------------------------------------------------------
// New helper functions for enhanced error messages in Parser.
// They open the source file to extract the line where the error occurred.
//------------------------------------------------------------
std::string Parser::getLineSnippet(const Token &tk) {
    std::ifstream file(tk.filename);
    if (!file)
        return "";
    std::string lineStr;
    for (int i = 1; i <= tk.line; i++) {
        if(!std::getline(file, lineStr))
            break;
    }
    return lineStr;
}

std::string Parser::formatError(const std::string &msg, const Token &tk) {
    std::string snippet = getLineSnippet(tk);
    std::ostringstream oss;
    oss << tk.filename << ":" << tk.line << ":" << tk.column << ": error: " << msg << "\n";
    oss << snippet << "\n";
    oss << std::string(tk.column - 1, ' ') << "^\n";
    return oss.str();
}

//------------------------------------------------------------
// Parser constructor and core methods
//------------------------------------------------------------
Parser::Parser(const std::vector<Token>& tokens)
    : tokens(tokens), position(0) {}

Token Parser::getNextToken() {
    if (position >= tokens.size())
        return Token(TokenType::END, "");
    return tokens[position++];
}

ASTNode Parser::parse() {
    return parseProgram();
}

ASTNode Parser::parseProgram() {
    std::vector<ASTNode> statements;
    while (position < tokens.size() && tokens[position].type != TokenType::END) {
        statements.push_back(parseStatement());
    }
    return ASTNode("Program", statements);
}

void Parser::skipUnsupportedStatement() {
    while (position < tokens.size()) {
        const Token& tk = tokens[position];
        if ((tk.type == TokenType::KEYWORD &&
            (tk.value == "import" || tk.value == "from" || tk.value == "print" ||
             tk.value == "def" || tk.value == "return" || tk.value == "yield" ||
             tk.value == "class" || tk.value == "lambda" || tk.value == "if" ||
             tk.value == "while" || tk.value == "for" || tk.value == "with"))
            || tk.type == TokenType::STRING) {
            break;
        }
        ++position;
    }
}

//------------------------------------------------------------
// parseStatement: handles assignment, control flow, etc.
//------------------------------------------------------------
ASTNode Parser::parseStatement() {
    // New: Handle 'with' statement
    if (tokens[position].type == TokenType::KEYWORD && tokens[position].value == "with")
        return parseWith();

    // Handle 'for' loops (new)
    if (tokens[position].type == TokenType::KEYWORD && tokens[position].value == "for")
        return parseFor();

    if (tokens[position].type == TokenType::IDENTIFIER) {
        if (position + 1 < tokens.size() &&
            tokens[position+1].type == TokenType::OPERATOR &&
            tokens[position+1].value == "=") {
            std::string varName = tokens[position].value;
            position += 2; // consume identifier and '='
            ASTNode expr = parseArgument();
            return ASTNode("Assignment", varName, { expr });
        } else {
            ASTNode idNode("Identifier", tokens[position].value);
            ++position;
            return idNode;
        }
    }
    
    if (tokens[position].type == TokenType::STRING) {
        ASTNode docString("DocString", tokens[position].value);
        ++position;
        return docString;
    }
    
    if (tokens[position].type == TokenType::KEYWORD) {
        std::string kw = tokens[position].value;
        if (kw == "def")
            return parseFunctionDef();
        if (kw == "lambda")
            return parseLambda();
        if (kw == "return")
            return parseReturn();
        if (kw == "yield")
            return parseYield();
        if (kw == "class")
            return parseClass();
        if (kw == "if")
            return parseIf();
        if (kw == "while")
            return parseWhile();
        if (kw == "import")
            return parseImport();
        if (kw == "from")
            return parseFromImport();
    }
    
    if (tokens[position].type == TokenType::IDENTIFIER &&
       (tokens[position].value == "True" || tokens[position].value == "False")) {
        ASTNode boolNode("Boolean", tokens[position].value);
        ++position;
        return boolNode;
    }
    
    if (tokens[position].type == TokenType::IDENTIFIER ||
        (tokens[position].type == TokenType::KEYWORD &&
         (tokens[position].value == "print" || tokens[position].value == "int" || tokens[position].value == "input"))) {
         return parseFunctionCall();
    }
    
    std::string tokenValue = tokens[position].value;
    ++position;
    return ASTNode("Unsupported", tokenValue);
}

//------------------------------------------------------------
// parseIf, parseWhile, parseFor, parseWith, etc.
//------------------------------------------------------------
ASTNode Parser::parseIf() {
    Token ifToken = tokens[position];
    ++position; // consume 'if'
    ASTNode condition = parseArgument();
    if (position >= tokens.size() ||
        tokens[position].type != TokenType::PUNCTUATION || tokens[position].value != ":")
         throw std::runtime_error(formatError("Expected ':' after if condition", (position < tokens.size() ? tokens[position] : tokens.back())));
    ++position; // consume ':'
    ASTNode thenBlock = parseStatement();
    ASTNode currentIf("If", "", { condition, thenBlock });
    while (position < tokens.size() && tokens[position].type == TokenType::KEYWORD && tokens[position].value == "elif") {
         ++position; // consume 'elif'
         ASTNode elifCondition = parseArgument();
         if (position >= tokens.size() ||
             tokens[position].type != TokenType::PUNCTUATION || tokens[position].value != ":")
             throw std::runtime_error(formatError("Expected ':' after elif condition", (position < tokens.size() ? tokens[position] : tokens.back())));
         ++position; // consume ':'
         ASTNode elifBlock = parseStatement();
         currentIf = ASTNode("If", "", { currentIf, ASTNode("If", "", { elifCondition, elifBlock }) });
    }
    if (position < tokens.size() && tokens[position].type == TokenType::KEYWORD && tokens[position].value == "else") {
         ++position; // consume 'else'
         if (position >= tokens.size() ||
             tokens[position].type != TokenType::PUNCTUATION || tokens[position].value != ":")
             throw std::runtime_error(formatError("Expected ':' after else", (position < tokens.size() ? tokens[position] : tokens.back())));
         ++position; // consume ':'
         ASTNode elseBlock = parseStatement();
         currentIf = ASTNode("If", "", { currentIf, elseBlock });
    }
    return currentIf;
}

ASTNode Parser::parseWhile() {
    Token whileToken = tokens[position];
    ++position; // consume 'while'
    ASTNode condition = parseArgument();
    if (position >= tokens.size() ||
        tokens[position].type != TokenType::PUNCTUATION || tokens[position].value != ":")
         throw std::runtime_error(formatError("Expected ':' after while condition", (position < tokens.size() ? tokens[position] : tokens.back())));
    ++position; // consume ':'
    ASTNode body = parseStatement();
    return ASTNode("While", "", { condition, body });
}

ASTNode Parser::parseFor() {
    Token forToken = tokens[position];
    ++position; // consume 'for'
    if (position >= tokens.size() || tokens[position].type != TokenType::IDENTIFIER)
        throw std::runtime_error(formatError("Expected loop variable after 'for'", (position < tokens.size() ? tokens[position] : forToken)));
    std::string loopVar = tokens[position].value;
    ++position;
    if (position >= tokens.size() || tokens[position].value != "in")
        throw std::runtime_error(formatError("Expected 'in' after loop variable", (position < tokens.size() ? tokens[position] : tokens.back())));
    ++position; // consume 'in'
    ASTNode iterable = parseArgument();
    if (position >= tokens.size() ||
        tokens[position].type != TokenType::PUNCTUATION || tokens[position].value != ":")
        throw std::runtime_error(formatError("Expected ':' after for-loop header", (position < tokens.size() ? tokens[position] : tokens.back())));
    ++position; // consume ':'
    ASTNode body = parseStatement();
    return ASTNode("For", loopVar, { iterable, body });
}

ASTNode Parser::parseWith() {
    Token withToken = tokens[position];
    ++position; // consume 'with'
    ASTNode contextExpr = parseArgument();
    std::string varName = "";
    if (position < tokens.size() && tokens[position].type == TokenType::KEYWORD &&
        tokens[position].value == "as") {
        ++position; // consume 'as'
        if (position >= tokens.size() || tokens[position].type != TokenType::IDENTIFIER)
            throw std::runtime_error(formatError("Expected identifier after 'as'", (position < tokens.size() ? tokens[position] : tokens.back())));
        varName = tokens[position].value;
        ++position;
    }
    if (position >= tokens.size() ||
        tokens[position].type != TokenType::PUNCTUATION || tokens[position].value != ":")
         throw std::runtime_error(formatError("Expected ':' after with statement header", (position < tokens.size() ? tokens[position] : tokens.back())));
    ++position; // consume ':'
    ASTNode body = parseStatement();
    return ASTNode("With", varName, { contextExpr, body });
}

ASTNode Parser::parseImport() {
    Token importToken = tokens[position];
    ++position; // consume 'import'
    if (position >= tokens.size() || tokens[position].type != TokenType::IDENTIFIER)
        throw std::runtime_error(formatError("Expected identifier after 'import'", (position < tokens.size() ? tokens[position] : importToken)));
    std::string moduleName = tokens[position].value;
    ++position;
    while (position < tokens.size() &&
           tokens[position].type == TokenType::PUNCTUATION &&
           tokens[position].value == ",") {
        ++position;
        if (position < tokens.size() && tokens[position].type == TokenType::IDENTIFIER)
            ++position;
    }
    return ASTNode("Import", moduleName);
}

ASTNode Parser::parseFromImport() {
    Token fromToken = tokens[position];
    ++position; // consume 'from'
    if (position >= tokens.size() ||
       (tokens[position].type != TokenType::IDENTIFIER && tokens[position].type != TokenType::KEYWORD))
        throw std::runtime_error(formatError("Expected module identifier after 'from'", (position < tokens.size() ? tokens[position] : fromToken)));
    std::string moduleName = tokens[position].value;
    ++position;
    while (position < tokens.size() &&
           tokens[position].type == TokenType::PUNCTUATION &&
           tokens[position].value == ".") {
        moduleName += ".";
        ++position;
        if (position < tokens.size() &&
           (tokens[position].type == TokenType::IDENTIFIER || tokens[position].type == TokenType::KEYWORD)) {
            moduleName += tokens[position].value;
            ++position;
        } else {
            throw std::runtime_error(formatError("Expected identifier after '.' in module name", (position < tokens.size() ? tokens[position] : tokens.back())));
        }
    }
    if (position >= tokens.size() || tokens[position].type != TokenType::KEYWORD || tokens[position].value != "import")
        throw std::runtime_error(formatError("Expected 'import' keyword after module name in from-import statement", (position < tokens.size() ? tokens[position] : tokens.back())));
    ++position; // consume 'import'
    while (position < tokens.size() &&
           (tokens[position].type == TokenType::IDENTIFIER ||
            tokens[position].type == TokenType::KEYWORD ||
            (tokens[position].type == TokenType::PUNCTUATION && tokens[position].value == ",") ||
            (tokens[position].type == TokenType::KEYWORD && tokens[position].value == "as")))
    {
         ++position;
    }
    return ASTNode("Import", moduleName);
}

ASTNode Parser::parseListLiteral() {
    ++position; // consume '['
    std::vector<ASTNode> elements;
    while (position < tokens.size() && !(tokens[position].type == TokenType::PUNCTUATION && tokens[position].value == "]")) {
        elements.push_back(parseArgument());
        if (position < tokens.size() && tokens[position].type == TokenType::PUNCTUATION && tokens[position].value == ",")
            ++position;
    }
    if (position >= tokens.size() || tokens[position].value != "]")
        throw std::runtime_error(formatError("Expected ']' to close list literal", (position < tokens.size() ? tokens[position] : tokens.back())));
    ++position; // consume ']'
    return ASTNode("ListLiteral", "", elements);
}

//------------------------------------------------------------
// Modified parseArgument to avoid consuming tokens from subsequent statements
//------------------------------------------------------------
ASTNode Parser::parseArgument() {
    if (tokens[position].type == TokenType::PUNCTUATION && tokens[position].value == "[")
        return parseListLiteral();
    
    if (tokens[position].type == TokenType::IDENTIFIER &&
       (tokens[position].value == "True" || tokens[position].value == "False")) {
        ASTNode boolNode("Boolean", tokens[position].value);
        ++position;
        return boolNode;
    }
    
    std::string argumentValue;
    int bracketDepth = 0;
    int parenDepth = 0;
    // Expanded stopKeywords to prevent over-consuming tokens from subsequent statements.
    std::set<std::string> stopKeywords = {"def", "return", "yield", "class", "if", "while", "for", "with", "import", "from", "print", "break", "continue", "pass", "try", "except", "raise", "finally"};
    
    int tokenCount = 0;
    const int maxTokensPerArg = 1000;

    while (position < tokens.size() && tokenCount < maxTokensPerArg) {
        const Token& tk = tokens[position];
        
        // Stop if we see a punctuation ":" outside of any grouping.
        if (tk.type == TokenType::PUNCTUATION && tk.value == ":" && parenDepth == 0 && bracketDepth == 0)
            break;
        
        // Stop if the token is a KEYWORD that signals the start of a new statement, provided we've already consumed some tokens.
        if (tk.type == TokenType::KEYWORD && stopKeywords.find(tk.value) != stopKeywords.end() && tokenCount > 0)
            break;
        
        // Stop if we reach a closing parenthesis or comma outside of any grouping.
        if (tk.type == TokenType::PUNCTUATION && (tk.value == ")" || tk.value == ",") && parenDepth == 0 && bracketDepth == 0)
            break;
        
        if (tk.type == TokenType::END)
            break;
        
        if (tk.type == TokenType::PUNCTUATION) {
            if (tk.value == "(") parenDepth++;
            else if (tk.value == ")") {
                if (parenDepth == 0) break;
                parenDepth--;
            }
            else if (tk.value == "[") bracketDepth++;
            else if (tk.value == "]") bracketDepth--;
        }
        if (tk.type == TokenType::OPERATOR && tk.value == "=" && parenDepth == 0 && bracketDepth == 0)
            break;
        
        if (tk.value == "is")
            argumentValue += " is ";
        else
            argumentValue += tk.value;
        
        ++position;
        ++tokenCount;
    }
    
    if (tokenCount >= maxTokensPerArg) {
        std::cerr << "[DEBUG] parseArgument: reached maximum tokens per argument, breaking loop.\n";
    }
    
    return ASTNode("Argument", argumentValue);
}

ASTNode Parser::parseFunctionCall() {
    if (tokens[position].type != TokenType::IDENTIFIER &&
        tokens[position].type != TokenType::KEYWORD)
         throw std::runtime_error(formatError("Expected function name", tokens[position]));
    std::string functionName = tokens[position].value;
    ++position;
    while (position < tokens.size() &&
           tokens[position].type == TokenType::PUNCTUATION &&
           tokens[position].value == ".") {
         functionName += ".";
         ++position;
         if (position < tokens.size() &&
             (tokens[position].type == TokenType::IDENTIFIER || tokens[position].type == TokenType::KEYWORD)) {
             functionName += tokens[position].value;
             ++position;
         } else {
             throw std::runtime_error(formatError("Expected identifier after '.'", (position < tokens.size() ? tokens[position] : tokens.back())));
         }
    }
    if (position >= tokens.size() ||
        tokens[position].type != TokenType::PUNCTUATION ||
        tokens[position].value != "(") {
         skipUnsupportedStatement();
         return ASTNode("Unsupported", functionName);
    }
    ++position; // consume '('
    std::vector<ASTNode> arguments;
    while (true) {
         if (position >= tokens.size())
             throw std::runtime_error(formatError("Missing closing parenthesis in function call", (position < tokens.size() ? tokens[position] : tokens.back())));
         if (tokens[position].type == TokenType::PUNCTUATION && tokens[position].value == ")") {
             ++position;
             break;
         }
         if (tokens[position].type == TokenType::IDENTIFIER &&
             (position + 1 < tokens.size() && tokens[position+1].type == TokenType::OPERATOR && tokens[position+1].value == "=")) {
             std::string key = tokens[position].value;
             position += 2; // consume identifier and '='
             ASTNode valueNode = parseArgument();
             ASTNode kwArg("KeywordArgument", key, { valueNode });
             arguments.push_back(kwArg);
         } else {
             ASTNode argNode = parseArgument();
             arguments.push_back(argNode);
         }
         if (position < tokens.size() &&
             tokens[position].type == TokenType::PUNCTUATION && tokens[position].value == ",") {
             ++position;
             continue;
         }
    }
    return ASTNode("FunctionCall", functionName, arguments);
}

ASTNode Parser::parseFunctionDef() {
    Token defToken = tokens[position];
    ++position; // consume 'def'
    if (position >= tokens.size() || tokens[position].type != TokenType::IDENTIFIER)
         throw std::runtime_error(formatError("Expected function name after def", (position < tokens.size() ? tokens[position] : defToken)));
    std::string funcName = tokens[position].value;
    ++position;
    if (position >= tokens.size() || tokens[position].type != TokenType::PUNCTUATION || tokens[position].value != "(")
         throw std::runtime_error(formatError("Expected '(' after function name", (position < tokens.size() ? tokens[position] : tokens.back())));
    ++position; // consume '('
    std::vector<ASTNode> parameters;
    while (position < tokens.size() &&
           !(tokens[position].type == TokenType::PUNCTUATION && tokens[position].value == ")")) {
         if (tokens[position].type == TokenType::IDENTIFIER) {
              parameters.push_back(ASTNode("Parameter", tokens[position].value));
              ++position;
              if (position < tokens.size() &&
                  tokens[position].type == TokenType::PUNCTUATION && tokens[position].value == ",")
                  ++position;
         } else {
              ++position;
         }
    }
    if (position >= tokens.size() || tokens[position].type != TokenType::PUNCTUATION || tokens[position].value != ")")
         throw std::runtime_error(formatError("Expected ')' after parameter list", (position < tokens.size() ? tokens[position] : tokens.back())));
    ++position; // consume ')'
    while (position < tokens.size() &&
           !(tokens[position].type == TokenType::PUNCTUATION && tokens[position].value == ":")) {
         ++position;
    }
    if (position >= tokens.size())
         throw std::runtime_error(formatError("Expected ':' after function header", (position < tokens.size() ? tokens[position] : tokens.back())));
    ++position; // consume ':'
    ASTNode body = parseStatement();
    ASTNode params("Parameters", parameters);
    return ASTNode("FunctionDef", funcName, { params, body });
}

ASTNode Parser::parseReturn() {
    Token retToken = tokens[position];
    ++position; // consume 'return'
    if (position < tokens.size() &&
        !(tokens[position].type == TokenType::PUNCTUATION && tokens[position].value == "\n")) {
         ASTNode expr = parseArgument();
         return ASTNode("Return", "", { expr });
    } else {
         return ASTNode("Return", "");
    }
}

ASTNode Parser::parseYield() {
    Token yieldToken = tokens[position];
    ++position; // consume 'yield'
    if (position < tokens.size() &&
        !(tokens[position].type == TokenType::PUNCTUATION && tokens[position].value == "\n")) {
         ASTNode expr = parseArgument();
         return ASTNode("Yield", "", { expr });
    }
    return ASTNode("Yield", "");
}

ASTNode Parser::parseClass() {
    Token classToken = tokens[position];
    ++position; // consume 'class'
    if (position >= tokens.size() || tokens[position].type != TokenType::IDENTIFIER)
         throw std::runtime_error(formatError("Expected class name after 'class'", (position < tokens.size() ? tokens[position] : classToken)));
    std::string className = tokens[position].value;
    ++position;
    while (position < tokens.size() &&
           !(tokens[position].type == TokenType::PUNCTUATION && tokens[position].value == ":")) {
         ++position;
    }
    if (position < tokens.size()) ++position; // consume ':'
    ASTNode body = parseStatement();
    return ASTNode("Class", className, { body });
}

ASTNode Parser::parseLambda() {
    Token lambdaToken = tokens[position];
    ++position; // consume 'lambda'
    std::vector<ASTNode> parameters;
    while (position < tokens.size() && tokens[position].value != ":") {
        if (tokens[position].type == TokenType::IDENTIFIER) {
            parameters.push_back(ASTNode("Parameter", tokens[position].value));
        }
        ++position;
    }
    if (position >= tokens.size() || tokens[position].value != ":")
        throw std::runtime_error(formatError("Expected ':' in lambda expression", (position < tokens.size() ? tokens[position] : lambdaToken)));
    ++position; // consume ':'
    ASTNode expr = parseArgument();
    ASTNode paramsNode("Parameters", parameters);
    return ASTNode("Lambda", "", { paramsNode, expr });
}
