/**
 * @file p2-parser.c
 * @brief Compiler phase 2: parser
 * Team Lima: Alice Robertson and Alexander Bain
 */

#include "p2-parser.h"

/*
 * helper functions
 */

/**
 * @brief Look up the source line of the next token in the queue.
 * 
 * @param input Token queue to examine
 * @returns Source line
 */
int get_next_token_line(TokenQueue *input)
{
    if (TokenQueue_is_empty(input))
    {
        Error_throw_printf("Unexpected end of input\n");
    }
    return TokenQueue_peek(input)->line;
}

/**
 * @brief Check next token for a particular type and text and discard it
 * 
 * Throws an error if there are no more tokens or if the next token in the
 * queue does not match the given type or text.
 * 
 * @param input Token queue to modify
 * @param type Expected type of next token
 * @param text Expected text of next token
 */
void match_and_discard_next_token(TokenQueue *input, TokenType type, const char *text)
{
    if (TokenQueue_is_empty(input))
    {
        Error_throw_printf("Unexpected end of input (expected \'%s\')\n", text);
    }
    Token *token = TokenQueue_remove(input);
    if (token->type != type || !token_str_eq(token->text, text))
    {
        Error_throw_printf("Expected \'%s\' but found '%s' on line %d\n",
                           text, token->text, get_next_token_line(input));
    }
    Token_free(token);
}

/**
 * @brief Remove next token from the queue
 * 
 * Throws an error if there are no more tokens.
 * 
 * @param input Token queue to modify
 */
void discard_next_token(TokenQueue *input)
{
    if (TokenQueue_is_empty(input))
    {
        Error_throw_printf("Unexpected end of input\n");
    }
    Token_free(TokenQueue_remove(input));
}

/**
 * @brief Look ahead at the type of the next token
 * 
 * @param input Token queue to examine
 * @param type Expected type of next token
 * @returns True if the next token is of the expected type, false if not
 */
bool check_next_token_type(TokenQueue *input, TokenType type)
{
    if (TokenQueue_is_empty(input))
    {
        return false;
    }
    Token *token = TokenQueue_peek(input);
    return (token->type == type);
}

/**
 * @brief Look ahead at the type and text of the next token
 * 
 * @param input Token queue to examine
 * @param type Expected type of next token
 * @param text Expected text of next token
 * @returns True if the next token is of the expected type and text, false if not
 */
bool check_next_token(TokenQueue *input, TokenType type, const char *text)
{
    if (TokenQueue_is_empty(input))
    {
        return false;
    }
    Token *token = TokenQueue_peek(input);
    return (token->type == type) && (token_str_eq(token->text, text));
}

/**
 * @brief Parse and return a Decaf type
 * 
 * @param input Token queue to modify
 * @returns Parsed type (it is also removed from the queue)
 */
DecafType parse_type(TokenQueue *input)
{
    Token *token = TokenQueue_remove(input);
    if (token->type != KEY)
    {
        Error_throw_printf("Invalid type '%s' on line %d\n", token->text, get_next_token_line(input));
    }
    DecafType t = VOID;
    if (token_str_eq("int", token->text))
    {
        t = INT;
    }
    else if (token_str_eq("bool", token->text))
    {
        t = BOOL;
    }
    else if (token_str_eq("void", token->text))
    {
        t = VOID;
    }
    else
    {
        Error_throw_printf("Invalid type '%s' on line %d\n", token->text, get_next_token_line(input));
    }
    Token_free(token);
    return t;
}

/**
 * @brief Parse and return a Decaf identifier
 * 
 * @param input Token queue to modify
 * @param buffer String buffer for parsed identifier (should be at least
 * @c MAX_TOKEN_LEN characters long)
 */
void parse_id(TokenQueue *input, char *buffer)
{
    Token *token = TokenQueue_remove(input);
    if (token->type != ID)
    {
        Error_throw_printf("Invalid ID '%s' on line %d\n", token->text, get_next_token_line(input));
    }
    snprintf(buffer, MAX_ID_LEN, "%s", token->text);
    Token_free(token);
}

/**
 * @brief Parse a variable declaration
 * 
 * @param input Token queue to modify
 */
ASTNode *parse_vardecl(TokenQueue *input)
{
    /*
    *VarDecl -> Type
    */
    DecafType t = parse_type(input);
    char buffer[MAX_TOKEN_LEN];
    parse_id(input, buffer);
    int arrayLength = -1;

    // If array...

    // make sure queue is not empty
    if (TokenQueue_is_empty(input)) 
    {
        match_and_discard_next_token(input, SYM, ";");
    }

    char* first = TokenQueue_peek(input)->text;
    if (token_str_eq("\\[", first))
    {
        // First bracket
        match_and_discard_next_token(input, SYM, "[");

        // Second Bracket
        match_and_discard_next_token(input, SYM, "]");
    }

    match_and_discard_next_token(input, SYM, ";");

    if (arrayLength >= 0)
    {
        return VarDeclNode_new(buffer, t, true, arrayLength, 1);
    }

    return VarDeclNode_new(buffer, t, false, 0, 1);
}

/**
 * @brief Parse an expression
 * 
 * @param input Token queue to modify
 */
ASTNode *parse_expression(TokenQueue *input)
{
    char *type = TokenType_to_string(TokenQueue_peek(input)->type);
    
    // Base Expressions
    if (token_str_eq("ID", type))
    {
        // Loc or FuncCall
    }
    else if (token_str_eq("DECLIT", type)) 
    {
        // decimal literal
    }
    else if (token_str_eq("HEXLIT", type))
    {
        // hex literal
    }
    else if (token_str_eq("STRLIT", type))
    {
        // string literal
    }
    return NULL;
}

/**
 * @brief Parse a decaf statement
 * 
 * @param input Token queue to modify
 * @param isValid if the statement is valid
 */
ASTNode *parse_statement(TokenQueue *input, bool* isValid)
{
    char* type = TokenType_to_string(TokenQueue_peek(input)->type);
    char* first = TokenQueue_peek(input)->text;

    if (token_str_eq("if", first)) 
    {
        // if statement
    }
    else if (token_str_eq("while", first)) 
    {
        // while statement
    }
    else if (token_str_eq("return", first)) 
    {
        free(TokenQueue_remove(input));
        parse_expression(input);
        match_and_discard_next_token(input, SYM, ";");
        return ReturnNode_new(NULL, 1);
    }
    else if (token_str_eq("break",first))
    {
        free(TokenQueue_remove(input));
        match_and_discard_next_token(input, SYM, ";");
        return BreakNode_new(1);
    }
    else if (token_str_eq("continue",first))
    {
        free(TokenQueue_remove(input));
        match_and_discard_next_token(input, SYM, ";");
        return ContinueNode_new(1);
    }
    else if (token_str_eq("other",type)) // idk what to do for this if
    {
        // find ID
        char buffer[MAX_TOKEN_LEN];
        parse_id(input, buffer);

        first = TokenQueue_peek(input)->text;

        // if we find (), then its a function call
        if (token_str_eq("\\(", first)) // function call
        {
            match_and_discard_next_token(input, SYM, "\\)");
            if (token_str_eq("\\)", TokenQueue_peek(input)->text)) 
            {
                match_and_discard_next_token(input, SYM, "\\)");
            }
            else 
            {
                // parse args
                match_and_discard_next_token(input, SYM, "\\)");
            }
            // discard semicolon
            match_and_discard_next_token(input, SYM, ";");

            // create the function node 
            // IDK IF THIS GOES HERE
            return FuncCallNode_new(first, 1);
        }
        else if (token_str_eq("[", first)) // if we see [] its a loc
        {
            match_and_discard_next_token(input, SYM, "[");
            // parse expression

            match_and_discard_next_token(input, SYM, "]");
            // ignore =

            match_and_discard_next_token(input, SYM, "=");
            // parse expression

            match_and_discard_next_token(input, SYM, ";");
        }
        else // no [], but still Loc
        {
            // parse expression
            return LocationNode_new(first, 0, 1);
        }

    }

    *isValid = false;
    return NULL;
}

/**
 * @brief Parse a decaf block
 * 
 * @param input Token queue to modify
 */
ASTNode *parse_block(TokenQueue *input)
{
    // create a block node
    ASTNode *block = BlockNode_new(1);

    // discard the first bracket {
    match_and_discard_next_token(input, SYM, "{");
    bool isValid = true;
    // Statements
    // While program still says valid
    while (!TokenQueue_is_empty(input) && isValid)
    {
        // also check for variable declarations??? or that may be part of statement
        parse_statement(input, &isValid);
    }
    match_and_discard_next_token(input, SYM, "}");
    return block;
}

/**
 * @brief Parse a func declaration
 * 
 * @param input Token queue to modify
 */
ASTNode *parse_funcdecl(TokenQueue *input)
{
    // we know we have already seen def
    // find the Type
    DecafType t = parse_type(input);

    // find the ID
    char buffer[MAX_TOKEN_LEN];
    parse_id(input, buffer);

    match_and_discard_next_token(input, SYM, "(");
    // RESTART HERE FOR PARAMETERS
    match_and_discard_next_token(input, SYM, ")");

    // BLOCK
    ASTNode *block_node = parse_block(input);

    return FuncDeclNode_new(buffer, t, NULL, block_node, 1);
}

/*
 * node-level parsing functions
 */

ASTNode *parse_program(TokenQueue *input)
{
    ASTNode *node = ProgramNode_new();

    while (!TokenQueue_is_empty(input))
    {
        if (token_str_eq("def", TokenQueue_peek(input)->text))
        {
            Token *token = TokenQueue_remove(input);
            free(token);
            NodeList_add(node->program.variables, parse_funcdecl(input));
        }
        else
        {
            NodeList_add(node->program.variables, parse_vardecl(input));
        }
    }
    return node;
}

ASTNode *parse(TokenQueue *input)
{
    return parse_program(input);
}
