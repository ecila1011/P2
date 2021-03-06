/**
 * @file p2-parser.c
 * @brief Compiler phase 2: parser
 * Team Lima: Alice Robertson and Alexander Bain
 */

#include "p2-parser.h"

/*
 * declare functions here so that they are global
 */
ASTNode *parse_block(TokenQueue *input);

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
    int line = get_next_token_line(input);
    parse_id(input, buffer);
    int arrayLength = -1;

    // make sure queue is not empty
    if (TokenQueue_is_empty(input))
    {
        match_and_discard_next_token(input, SYM, ";");
    }

    char *first = TokenQueue_peek(input)->text;

    // see if there are brackets and take care of them (arrays)
    if (token_str_eq("[", first))
    {
        // First bracket
        match_and_discard_next_token(input, SYM, "[");

        if (check_next_token_type(input, DECLIT))
        {
            char *text = TokenQueue_remove(input)->text;
            arrayLength = strtol(text, NULL, 10);
        }
        // Second Bracket
        match_and_discard_next_token(input, SYM, "]");
    }

    match_and_discard_next_token(input, SYM, ";");

    if (arrayLength >= 0)
    {
        return VarDeclNode_new(buffer, t, true, arrayLength, line);
    }

    return VarDeclNode_new(buffer, t, false, 1, line);
}

/**
 * @brief Parse an expression
 * 
 * @param input Token queue to modify
 */
ASTNode *parse_expression(TokenQueue *input, bool hasParsedOp)
{
    ASTNode *n = NULL;
    int line = get_next_token_line(input);
    // make sure queue is not empty
    if (!TokenQueue_is_empty(input))
    {

        //TokenType type = TokenQueue_peek(input)->type;
        char *text = TokenQueue_peek(input)->text;

        // Unary Operators
        if (token_str_eq("!", text) && !hasParsedOp)
        {
            UnaryOpType op = NOTOP;
            free(TokenQueue_remove(input));
            n = UnaryOpNode_new(op, parse_expression(input, true), line);
        }

        // Base Expressions
        if (check_next_token_type(input, ID)) // FuncCall or Loc
        {
            // find ID
            char buffer[MAX_TOKEN_LEN];
            parse_id(input, buffer);

            char *first = TokenQueue_peek(input)->text;

            // if we find (), then its a function call
            if (token_str_eq("(", first)) // function call
            {
                ASTNode *node = FuncCallNode_new(buffer, line);

                match_and_discard_next_token(input, SYM, "("); // skip (

                while (!token_str_eq(")", TokenQueue_peek(input)->text))
                {
                    NodeList_add(node->funccall.arguments, parse_expression(input, false));
                    if (token_str_eq(",", TokenQueue_peek(input)->text))
                    {
                        match_and_discard_next_token(input, SYM, ",");
                    }
                }

                match_and_discard_next_token(input, SYM, ")"); // skip )
                //match_and_discard_next_token(input, SYM, ";"); // skip ;

                // create the function node
                n = node;
            }
            else if (token_str_eq("[", first)) // if we see [] its a loc
            {
                match_and_discard_next_token(input, SYM, "["); // skip [

                ASTNode *index = parse_expression(input, false);

                match_and_discard_next_token(input, SYM, "]"); // skip ]

                ASTNode *loc = LocationNode_new(buffer, index, 1);

                //match_and_discard_next_token(input, SYM, ";"); // skip ;

                n = loc;
            }
            else // no [], but still Loc
            {
                ASTNode *loc = LocationNode_new(buffer, NULL, line);

                //match_and_discard_next_token(input, SYM, ";"); // skip ;

                n = loc;
            }
        }
        else if (check_next_token_type(input, DECLIT)) // decimal literal
        {
            Token *token = TokenQueue_remove(input);
            int num = strtol(token->text, NULL, 10);
            free(token);
            n = LiteralNode_new_int(num, line);
        }
        else if (check_next_token_type(input, HEXLIT)) // hex literal
        {
            Token *token = TokenQueue_remove(input);
            int num = strtol(token->text, NULL, 16);
            free(token);
            n = LiteralNode_new_int(num, line);
        }
        else if (check_next_token_type(input, STRLIT)) // string literal
        {
            Token *token = TokenQueue_remove(input);
            char *str = (token->text);
            // Remove quotes from beginning and end
            ssize_t length = strlen(str) - 1;
            *(str + (length * sizeof(char))) = NULL;
            str = str + sizeof(char);
            // Handle new line characters
            char *ptr = strstr(str, "\\n");
            if (ptr != NULL)
            {
                *ptr = '\n';
                ptr += sizeof(char);
                while (*ptr != NULL)
                {
                    *ptr = *(ptr + sizeof(char));
                    ptr += sizeof(char);
                }
            }
            free(token);
            n = LiteralNode_new_string(str, line);
        }
        else if (token_str_eq("true", text)) // true
        {
            free(TokenQueue_remove(input));
            n = LiteralNode_new_bool(true, line);
        }
        else if (token_str_eq("false", text)) // false
        {
            free(TokenQueue_remove(input));
            n = LiteralNode_new_bool(false, line);
        }
    }

    // Need to make sure the queue is not empty!!!!
    if (!TokenQueue_is_empty(input))
    {

        char *text = TokenQueue_peek(input)->text;
        // Handling negative versus substraction
        if (token_str_eq("-", text) && n != NULL && !hasParsedOp) // subtraction
        {
            free(TokenQueue_remove(input));
            BinaryOpType op = SUBOP;
            n = BinaryOpNode_new(op, n, parse_expression(input, true), line);
        }
        else if (token_str_eq("-", text) && n == NULL && !hasParsedOp) // negative
        {
            UnaryOpType op = NEGOP;
            free(TokenQueue_remove(input));
            n = UnaryOpNode_new(op, parse_expression(input, true), line);
        }
        
        // Binary Operations
        if (token_str_eq("+", text) && !hasParsedOp) // plus
        {
            free(TokenQueue_remove(input));
            BinaryOpType op = ADDOP;
            n = BinaryOpNode_new(op, n, parse_expression(input, true), line);
        }
        else if (token_str_eq("&&", text) && !hasParsedOp)
        {
            free(TokenQueue_remove(input));
            BinaryOpType op = ANDOP;
            n = BinaryOpNode_new(op, n, parse_expression(input, true), line);
        }
        else if (token_str_eq("||", text) && !hasParsedOp)
        {
            free(TokenQueue_remove(input));
            BinaryOpType op = OROP;
            n = BinaryOpNode_new(op, n, parse_expression(input, true), line);
        }
        else if (token_str_eq("==", text) && !hasParsedOp)
        {
            free(TokenQueue_remove(input));
            BinaryOpType op = EQOP;
            n = BinaryOpNode_new(op, n, parse_expression(input, true), line);
        }
        else if (token_str_eq("!=", text) && !hasParsedOp)
        {
            free(TokenQueue_remove(input));
            BinaryOpType op = NEQOP;
            n = BinaryOpNode_new(op, n, parse_expression(input, true), line);
        }
        else if (token_str_eq("<=", text) && !hasParsedOp)
        {
            free(TokenQueue_remove(input));
            BinaryOpType op = LEOP;
            n = BinaryOpNode_new(op, n, parse_expression(input, true), line);
        }
        else if (token_str_eq("<", text) && !hasParsedOp)
        {
            free(TokenQueue_remove(input));
            BinaryOpType op = LTOP;
            n = BinaryOpNode_new(op, n, parse_expression(input, true), line);
        }
        else if (token_str_eq(">=", text) && !hasParsedOp)
        {
            free(TokenQueue_remove(input));
            BinaryOpType op = GEOP;
            n = BinaryOpNode_new(op, n, parse_expression(input, true), line);
        }
        else if (token_str_eq(">", text) && !hasParsedOp)
        {
            free(TokenQueue_remove(input) && !hasParsedOp);
            BinaryOpType op = GTOP;
            n = BinaryOpNode_new(op, n, parse_expression(input, true), line);
        }
        else if (token_str_eq("*", text))
        {
            free(TokenQueue_remove(input) && !hasParsedOp);
            BinaryOpType op = MULOP;
            n = BinaryOpNode_new(op, n, parse_expression(input, true), line);
        }
        else if (token_str_eq("/", text))
        {
            free(TokenQueue_remove(input) && !hasParsedOp);
            BinaryOpType op = DIVOP;
            n = BinaryOpNode_new(op, n, parse_expression(input, true), line);
        }
        else if (token_str_eq("%", text) && !hasParsedOp)
        {
            free(TokenQueue_remove(input));
            BinaryOpType op = MODOP;
            n = BinaryOpNode_new(op, n, parse_expression(input, true), line);
        }
    }
    return n;
}

/**
 * @brief Parse a decaf statement
 * 
 * @param input Token queue to modify
 * @param isValid if the statement is valid
 */
ASTNode *parse_statement(TokenQueue *input, bool *isValid)
{
    // make sure token queue is not null
    if (TokenQueue_is_empty(input))
    {
        ASTNode *n = NULL;
        return n;
    }
    int line = get_next_token_line(input);
    TokenType type = TokenQueue_peek(input)->type;
    char *first = TokenQueue_peek(input)->text;

    if (token_str_eq("if", first)) // if statement
    {
        free(TokenQueue_remove(input));
        match_and_discard_next_token(input, SYM, "("); // skip (

        // parse and save condition node
        ASTNode *condition = parse_expression(input, false);

        match_and_discard_next_token(input, SYM, ")"); // skip )

        // parse and save if block
        ASTNode *if_block = parse_block(input);

        // check for else statement
        ASTNode *else_block = NULL;
        if (token_str_eq("else", TokenQueue_peek(input)->text))
        {
            else_block = parse_block(input);
        }

        return ConditionalNode_new(condition, if_block, else_block, line);
    }
    else if (token_str_eq("while", first))
    {
        free(TokenQueue_remove(input));
        match_and_discard_next_token(input, SYM, "("); // skip (

        // parse and save condition node
        ASTNode *condition = parse_expression(input, false);

        match_and_discard_next_token(input, SYM, ")"); // skip )

        // parse and save while block
        ASTNode *while_block = parse_block(input);

        return WhileLoopNode_new(condition, while_block, line);
    }
    else if (token_str_eq("return", first))
    {
        free(TokenQueue_remove(input));

        // parse and save return statement
        ASTNode *expr = parse_expression(input, false);

        match_and_discard_next_token(input, SYM, ";"); // skip ;

        return ReturnNode_new(expr, line);
    }
    else if (token_str_eq("break", first))
    {
        free(TokenQueue_remove(input));
        // has no expression or block, so just skip semicolon
        match_and_discard_next_token(input, SYM, ";");
        return BreakNode_new(line);
    }
    else if (token_str_eq("continue", first))
    {
        free(TokenQueue_remove(input));
        // has no expression or block, so just skip semicolon
        match_and_discard_next_token(input, SYM, ";");
        return ContinueNode_new(line);
    }
    else if (type == ID)
    {
        // find ID
        char buffer[MAX_TOKEN_LEN];
        parse_id(input, buffer);
line = get_next_token_line(input);
        first = TokenQueue_peek(input)->text;

        // if we find (), then its a function call
        if (token_str_eq("(", first)) // function call
        {
            ASTNode *node = FuncCallNode_new(buffer, line);

            match_and_discard_next_token(input, SYM, "("); // skip (

            while (!token_str_eq(")", TokenQueue_peek(input)->text))
            {
                NodeList_add(node->funccall.arguments, parse_expression(input, false));
                if (token_str_eq(",", TokenQueue_peek(input)->text))
                {
                    match_and_discard_next_token(input, SYM, ",");
                }
            }

            match_and_discard_next_token(input, SYM, ")"); // skip )
            match_and_discard_next_token(input, SYM, ";"); // skip ;

            // create the function node
            return node;
        }
        else if (token_str_eq("[", first)) // if we see [] its a loc
        {
            match_and_discard_next_token(input, SYM, "["); // skip [

            ASTNode *index = parse_expression(input, false);

            match_and_discard_next_token(input, SYM, "]"); // skip ]

            ASTNode *loc = LocationNode_new(buffer, index, line);

            match_and_discard_next_token(input, SYM, "="); // skip =

            ASTNode *expr = parse_expression(input, false);

            match_and_discard_next_token(input, SYM, ";"); // skip ;

            return AssignmentNode_new(loc, expr, line);
        }
        else // no [], but still Loc
        {
            ASTNode *loc = LocationNode_new(buffer, NULL, line);

            match_and_discard_next_token(input, SYM, "="); // skip =

            ASTNode *expr = parse_expression(input, false);

            match_and_discard_next_token(input, SYM, ";"); // skip ;

            return AssignmentNode_new(loc, expr, line);
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
    int line = get_next_token_line(input);
    // create a block node
    ASTNode *node = BlockNode_new(line);

    // discard the first bracket {
    match_and_discard_next_token(input, SYM, "{");

    bool isValid = true;
    char *curr = NULL;

    // Statements

    // While program still says valid
    while (!TokenQueue_is_empty(input) && isValid)
    {
        curr = TokenQueue_peek(input)->text;

        // if type is int, bool, or void, parse for variable declaration
        if (token_str_eq("int", curr) || token_str_eq("bool", curr) || token_str_eq("void", curr))
        {
            NodeList_add(node->block.variables, parse_vardecl(input));
            //parse_vardecl(input);
        }
        else // parse as a statement
        {
            NodeList_add(node->block.statements, parse_statement(input, &isValid));
            // parse_statement(input, &isValid);
        }
    }

    match_and_discard_next_token(input, SYM, "}");
    return node;
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
    int line = get_next_token_line(input);
    DecafType t = parse_type(input);

    // find the ID
    char buffer[MAX_TOKEN_LEN];
    parse_id(input, buffer);

    match_and_discard_next_token(input, SYM, "(");

    // RESTART HERE FOR PARAMETERS
    ParameterList *params = ParameterList_new();
    char param_buffer[MAX_TOKEN_LEN];

    while (!token_str_eq(")", TokenQueue_peek(input)->text))
    {
        DecafType dt = parse_type(input);
        parse_id(input, param_buffer);
        // add parameter to list
        ParameterList_add_new(params, param_buffer, dt);
        if (token_str_eq(",", TokenQueue_peek(input)->text))
        {
            match_and_discard_next_token(input, SYM, ",");
        }
    }
    match_and_discard_next_token(input, SYM, ")");

    // BLOCK
    ASTNode *block_node = parse_block(input);

    return FuncDeclNode_new(buffer, t, params, block_node, line);
}

/*
 * node-level parsing functions
 */

ASTNode *parse_program(TokenQueue *input)
{
    ASTNode *node = ProgramNode_new();
    if (input == NULL)
    {
        Error_throw_printf("No input provided\n");
    }
    while (!TokenQueue_is_empty(input))
    {
        // printf("%s", TokenQueue_peek(input)->text);
        // printf("%d", strncmp("def", TokenQueue_peek(input)->text, MAX_TOKEN_LEN));
        if (token_str_eq("def", TokenQueue_peek(input)->text))
        {
            Token *token = TokenQueue_remove(input);
            free(token);
            NodeList_add(node->program.functions, parse_funcdecl(input));
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
