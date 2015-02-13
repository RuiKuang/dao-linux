/*
 * C-Inside (libc-inside) - C language interpreter library
 * Copyright (C) 2008-2015  Jason Todd <jtodd1@earthlink.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* language.h - definitions of operators and other language elements */

#ifndef __LANGUAGE_H__
#define __LANGUAGE_H__

#include "internal.h"

/**** empty token: cleared in expression evaluation, followed by zero ****/
#define CINSIDE_TOKEN_NONE      0x0000

/**** simple (non-operators, non-terminals), followed by "pairing value" ****/
/*
 * Pairing value applies only to (/)/{/}/[/]/?/: (note, ?/: special case)
 * Layout: bits 24-31 = level outside of the pairing (1 = outermost pairing)
 *         bits  0-23 = absolute value of relative index of paired token
 */
#define CINSIDE_TOKEN_SEMICOLON 0x0001  /* semicolon ( ; ) */
#define CINSIDE_TOKEN_LPAREN    0x0002  /* left parenthesis ( ( ) */
#define CINSIDE_TOKEN_RPAREN    0x0003  /* right parenthesis ( ) ) */
#define CINSIDE_TOKEN_LBRACE    0x0004  /* left brace ( { ) */
#define CINSIDE_TOKEN_RBRACE    0x0005  /* right brace ( } ) */
#define CINSIDE_TOKEN_LBRACKET  0x0006  /* left bracket ( [ ) */
#define CINSIDE_TOKEN_RBRACKET  0x0007  /* right bracket ( ] ) */

/**** operators, followed by zero: bits 8-15 define precedence ****/
/* comma */
#define CINSIDE_TOKEN_COMMA     0x0101  /* comma ( , ) */

/* assignments */
#define CINSIDE_TOKEN_EQUAL     0x0201  /* equal ( = ) */
#define CINSIDE_TOKEN_PLUSEQ    0x0202  /* plus, equal ( += ) */
#define CINSIDE_TOKEN_MINUSEQ   0x0203  /* minus, equal ( -= ) */
#define CINSIDE_TOKEN_MULEQ     0x0204  /* asterisk, equal ( *= ) */
#define CINSIDE_TOKEN_DIVEQ     0x0205  /* slash, equal ( /= ) */
#define CINSIDE_TOKEN_MODEQ     0x0206  /* percent, equal ( %= ) */
#define CINSIDE_TOKEN_ANDEQ     0x0207  /* ampersand, equal ( &= ) */
#define CINSIDE_TOKEN_XOREQ     0x0208  /* caret, equal ( ^= ) */
#define CINSIDE_TOKEN_OREQ      0x0209  /* pipe, equal ( |= ) */
#define CINSIDE_TOKEN_SHLEQ     0x020A  /* less, less, equal ( <<= ) */
#define CINSIDE_TOKEN_SHREQ     0x020B  /* greater, greater, equal ( >>= ) */

/* ternary conditional (ternary operators must be paired, unique bits 8-15) */
#define CINSIDE_TOKEN_QUESTION  0x0301  /* question ( ? ) */
#define CINSIDE_TOKEN_COLON     0x0302  /* colon ( : ) */

/* logic or */
#define CINSIDE_TOKEN_LOGICOR   0x0401  /* pipe, pipe ( || ) */

/* logic and */
#define CINSIDE_TOKEN_LOGICAND  0x0501  /* ampersand, ampersand ( && ) */

/* bitwise or */
#define CINSIDE_TOKEN_BITOR     0x0601  /* pipe ( | ) */

/* bitwise xor */
#define CINSIDE_TOKEN_BITXOR    0x0701  /* caret ( ^ ) */

/* bitwise and */
#define CINSIDE_TOKEN_BITAND    0x0801  /* ampersand ( & ) */

/* relational equality/inequality */
#define CINSIDE_TOKEN_EQEQ      0x0901  /* equal, equal ( == ) */
#define CINSIDE_TOKEN_NOTEQ     0x0902  /* exclamation, equal ( != ) */

/* relational less than [or equal]/greater than [or equal] */
#define CINSIDE_TOKEN_LESS      0x0A01  /* less ( < ) */
#define CINSIDE_TOKEN_GREATER   0x0A02  /* greater ( > ) */
#define CINSIDE_TOKEN_LESSEQ    0x0A03  /* less, equal ( <= ) */
#define CINSIDE_TOKEN_GREATEREQ 0x0A04  /* greater, equal ( >= ) */

/* bitwise shift left/right */
#define CINSIDE_TOKEN_SHL       0x0B01  /* less, less ( << ) */
#define CINSIDE_TOKEN_SHR       0x0B02  /* greater, greater ( >> ) */

/* arithmetic add/subtract */
#define CINSIDE_TOKEN_ADD       0x0C01  /* plus ( + ) */
#define CINSIDE_TOKEN_SUB       0x0C02  /* minus ( - ) */

/* arithmetic multiply/divide/modulus */
#define CINSIDE_TOKEN_MUL       0x0D01  /* asterisk ( * ) */
#define CINSIDE_TOKEN_DIV       0x0D02  /* slash ( / ) */
#define CINSIDE_TOKEN_MOD       0x0D03  /* percent ( % ) */

/* unary operators */
#define CINSIDE_TOKEN_NOT       0x0E01  /* exclamation ( ! ) */
#define CINSIDE_TOKEN_COMPL     0x0E02  /* tilde ( ~ ) */
#define CINSIDE_TOKEN_PREINC    0x0E03  /* plus, plus ( ++ ) */
#define CINSIDE_TOKEN_PREDEC    0x0E04  /* dash, dash ( -- ) */
#define CINSIDE_TOKEN_POSTINC   0x0E05  /* plus, plus ( ++ ) */
#define CINSIDE_TOKEN_POSTDEC   0x0E06  /* dash, dash ( -- ) */
#define CINSIDE_TOKEN_POSITIVE  0x0E07  /* plus ( + ) */
#define CINSIDE_TOKEN_NEGATIVE  0x0E08  /* minus ( - ) */
#define CINSIDE_TOKEN_ADDRESS   0x0E09  /* ampersand ( & ) */
#define CINSIDE_TOKEN_DEREF     0x0E0A  /* asterisk ( * ) */

/**** terminals, all followed by one value ****/
#define CINSIDE_TOKEN_DATA      0x8001  /* result of evaluation: value */
#define CINSIDE_TOKEN_INT       0x8002  /* integer literal: value */
#define CINSIDE_TOKEN_STRING    0x8003  /* string literal: ...string_hdr */
#define CINSIDE_TOKEN_NAME      0x8004  /* namespace word: pointer to string */
#define CINSIDE_TOKEN_KEYWORD   0x8005  /* keyword: pointer to string */
#define CINSIDE_TOKEN_DIRECTIVE 0x8006  /* #directive: pointer to string */
#define CINSIDE_TOKEN_BUILTIN   0x8007  /* built-in cmd: pointer to string */

#define CINSIDE_MIN_OPERATOR    0x0101
#define CINSIDE_MAX_OPERATOR    0x7FFF

#define CINSIDE_SYMBOLS \
{ \
    {';', 0,   0,   CINSIDE_TOKEN_SEMICOLON, 0,                   NULL}, \
    {'(', 0,   0,   CINSIDE_TOKEN_LPAREN,    0,                   NULL}, \
    {')', 0,   0,   CINSIDE_TOKEN_RPAREN,    0,                   NULL}, \
    {'{', 0,   0,   CINSIDE_TOKEN_LBRACE,    0,                   NULL}, \
    {'}', 0,   0,   CINSIDE_TOKEN_RBRACE,    0,                   NULL}, \
    {'[', 0,   0,   CINSIDE_TOKEN_LBRACKET,  CINSIDE_AFTER_VALUE, NULL}, \
    {']', 0,   0,   CINSIDE_TOKEN_RBRACKET,  CINSIDE_AFTER_VALUE, NULL}, \
    {'<', '<', '=', CINSIDE_TOKEN_SHLEQ,     CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_RL, _cinside_eval_assign}, \
    {'>', '>', '=', CINSIDE_TOKEN_SHREQ,     CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_RL, _cinside_eval_assign}, \
    {'+', '=', 0,   CINSIDE_TOKEN_PLUSEQ,    CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_RL, _cinside_eval_assign}, \
    {'-', '=', 0,   CINSIDE_TOKEN_MINUSEQ,   CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_RL, _cinside_eval_assign}, \
    {'*', '=', 0,   CINSIDE_TOKEN_MULEQ,     CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_RL, _cinside_eval_assign}, \
    {'/', '=', 0,   CINSIDE_TOKEN_DIVEQ,     CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_RL, _cinside_eval_assign}, \
    {'%', '=', 0,   CINSIDE_TOKEN_MODEQ,     CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_RL, _cinside_eval_assign}, \
    {'&', '=', 0,   CINSIDE_TOKEN_ANDEQ,     CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_RL, _cinside_eval_assign}, \
    {'^', '=', 0,   CINSIDE_TOKEN_XOREQ,     CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_RL, _cinside_eval_assign}, \
    {'|', '=', 0,   CINSIDE_TOKEN_OREQ,      CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_RL, _cinside_eval_assign}, \
    {'|', '|', 0,   CINSIDE_TOKEN_LOGICOR,   CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_LR, _cinside_eval_logicor}, \
    {'&', '&', 0,   CINSIDE_TOKEN_LOGICAND,  CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_LR, _cinside_eval_logicand}, \
    {'=', '=', 0,   CINSIDE_TOKEN_EQEQ,      CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_LR, _cinside_eval_binary}, \
    {'!', '=', 0,   CINSIDE_TOKEN_NOTEQ,     CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_LR, _cinside_eval_binary}, \
    {'<', '=', 0,   CINSIDE_TOKEN_LESSEQ,    CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_LR, _cinside_eval_binary}, \
    {'>', '=', 0,   CINSIDE_TOKEN_GREATEREQ, CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_LR, _cinside_eval_binary}, \
    {'<', '<', 0,   CINSIDE_TOKEN_SHL,       CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_LR, _cinside_eval_binary}, \
    {'>', '>', 0,   CINSIDE_TOKEN_SHR,       CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_LR, _cinside_eval_binary}, \
    {'+', '+', 0,   CINSIDE_TOKEN_POSTINC,   CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_RL, _cinside_eval_unary}, \
    {'-', '-', 0,   CINSIDE_TOKEN_POSTDEC,   CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_RL, _cinside_eval_unary}, \
    {'+', '+', 0,   CINSIDE_TOKEN_PREINC,    CINSIDE_ASSOC_RL, _cinside_eval_unary}, \
    {'-', '-', 0,   CINSIDE_TOKEN_PREDEC,    CINSIDE_ASSOC_RL, _cinside_eval_unary}, \
    {',', 0,   0,   CINSIDE_TOKEN_COMMA,     CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_LR, _cinside_eval_binary}, \
    {'?', 0,   0,   CINSIDE_TOKEN_QUESTION,  CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_RL | CINSIDE_COMBINED, _cinside_eval_ternary}, \
    {':', 0,   0,   CINSIDE_TOKEN_COLON,     CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_RL | CINSIDE_COMBINED, _cinside_eval_ternary}, \
    {'=', 0,   0,   CINSIDE_TOKEN_EQUAL,     CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_RL, _cinside_eval_assign}, \
    {'|', 0,   0,   CINSIDE_TOKEN_BITOR,     CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_LR, _cinside_eval_binary}, \
    {'^', 0,   0,   CINSIDE_TOKEN_BITXOR,    CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_LR, _cinside_eval_binary}, \
    {'&', 0,   0,   CINSIDE_TOKEN_BITAND,    CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_LR, _cinside_eval_binary}, \
    {'<', 0,   0,   CINSIDE_TOKEN_LESS,      CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_LR, _cinside_eval_binary}, \
    {'>', 0,   0,   CINSIDE_TOKEN_GREATER,   CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_LR, _cinside_eval_binary}, \
    {'+', 0,   0,   CINSIDE_TOKEN_ADD,       CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_LR, _cinside_eval_binary}, \
    {'-', 0,   0,   CINSIDE_TOKEN_SUB,       CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_LR, _cinside_eval_binary}, \
    {'*', 0,   0,   CINSIDE_TOKEN_MUL,       CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_LR, _cinside_eval_binary}, \
    {'/', 0,   0,   CINSIDE_TOKEN_DIV,       CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_LR, _cinside_eval_binary}, \
    {'%', 0,   0,   CINSIDE_TOKEN_MOD,       CINSIDE_AFTER_VALUE | CINSIDE_ASSOC_LR, _cinside_eval_binary}, \
    {'!', 0,   0,   CINSIDE_TOKEN_NOT,       CINSIDE_ASSOC_RL, _cinside_eval_unary}, \
    {'~', 0,   0,   CINSIDE_TOKEN_COMPL,     CINSIDE_ASSOC_RL, _cinside_eval_unary}, \
    {'+', 0,   0,   CINSIDE_TOKEN_POSITIVE,  CINSIDE_ASSOC_RL, _cinside_eval_unary}, \
    {'-', 0,   0,   CINSIDE_TOKEN_NEGATIVE,  CINSIDE_ASSOC_RL, _cinside_eval_unary}, \
    {'&', 0,   0,   CINSIDE_TOKEN_ADDRESS,   CINSIDE_ASSOC_RL, _cinside_eval_unary}, \
    {'*', 0,   0,   CINSIDE_TOKEN_DEREF,     CINSIDE_ASSOC_RL, _cinside_eval_unary} \
}

#define CINSIDE_VALUE_END \
{ \
    CINSIDE_TOKEN_INT, CINSIDE_TOKEN_STRING, CINSIDE_TOKEN_NAME, \
    CINSIDE_TOKEN_RPAREN, CINSIDE_TOKEN_RBRACE, CINSIDE_TOKEN_RBRACKET, \
    CINSIDE_TOKEN_POSTINC, CINSIDE_TOKEN_POSTDEC \
}

#define CINSIDE_SEPARATORS \
    " \t\r\n\\,;(){}[]=+-*/%&^|<>?:!~"

#define CINSIDE_NUM_SYMBOLS \
    (sizeof(_cinside_symbol) / sizeof(cinside_token_def))

#define CINSIDE_NUM_VALUE_END \
    (sizeof(_cinside_value_end) / sizeof(uint32_t))

#endif  /* __LANGUAGE_H__ */
