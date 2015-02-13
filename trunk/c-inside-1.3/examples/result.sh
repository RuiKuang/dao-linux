#!/bin/bash

# results.sh - demonstrate various ways of obtaining the result of C-Inside
#              command evaluation from within a shell script


# simplest case: function causes no output
RESULT=`c-inside -c 'getpid();'`
echo "getpid(): '${RESULT}'"

RESULT=`c-inside -c 'printf("%d\n", getpid());'`
echo "getpid() within printf(): '${RESULT}'"

echo


# next: function causes output that is always linefeed-terminated
RESULT=`c-inside -c 'printf("How many characters am I printing?\n");'`
echo "printf(): '${RESULT}'"

RESULT=`c-inside -c 'printf("%d\n", printf("How many characters am I printing?\n"));'`
echo "printf() within printf(): '${RESULT}'"

OUTPUT=`echo "${RESULT}" | sed -ne '$!p'`
RESULT=`echo "${RESULT}" | tail -1`
echo "-- output: '${OUTPUT}'"
echo "-- result: '${RESULT}'"

echo


# worst case: function causes output that is not linefeed-terminated
RESULT=`c-inside -c 'printf("How many now?");'`
echo "printf(): '${RESULT}'"

RESULT=`c-inside -c 'printf("=%d\n", printf("How many now?"));'`
echo "printf() within printf(): '${RESULT}'"

OUTPUT=`echo "${RESULT}" | sed -ne '$!p'; echo "${RESULT}" | tail -1 | sed -e 's/^\(.*\)=\([^=]*\)$/\1/'`
RESULT=`echo "${RESULT}" | tail -1 | sed -e 's/^\(.*\)=\([^=]*\)$/\2/'`
echo "-- output: '${OUTPUT}'"
echo "-- result: '${RESULT}'"

echo


# the "worst case" above is general, can be applied to the other two scenarios
RESULT=`c-inside -c 'printf("=%d\n", getpid());'`
echo "getpid() within printf(): '${RESULT}'"

OUTPUT=`echo "${RESULT}" | sed -ne '$!p'; echo "${RESULT}" | tail -1 | sed -e 's/^\(.*\)=\([^=]*\)$/\1/'`
RESULT=`echo "${RESULT}" | tail -1 | sed -e 's/^\(.*\)=\([^=]*\)$/\2/'`
echo "-- output: '${OUTPUT}'"
echo "-- result: '${RESULT}'"

echo

RESULT=`c-inside -c 'printf("=%d\n", printf("How many characters am I printing?\n"));'`
echo "printf() within printf(): '${RESULT}'"

OUTPUT=`echo "${RESULT}" | sed -ne '$!p'; echo "${RESULT}" | tail -1 | sed -e 's/^\(.*\)=\([^=]*\)$/\1/'`
RESULT=`echo "${RESULT}" | tail -1 | sed -e 's/^\(.*\)=\([^=]*\)$/\2/'`
echo "-- output: '${OUTPUT}'"
echo "-- result: '${RESULT}'"

echo


echo "If you simply ran ${0}, without reading its source,"
echo "then the above output almost surely will not make any sense.  Please read"
echo "its source if you are interested in using C-Inside within shell scripts."

echo
