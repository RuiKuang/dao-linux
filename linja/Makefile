CINSIDE = ../c-inside-1.3
UDIS86 = ../udis86-1.7
EXAMPLES_DIR = ../examples

CINSIDE_INC = $(CINSIDE)/include
CINSIDE_LIB = $(CINSIDE)/lib

CPPFLAGS += -D_GNU_SOURCE -I$(CINSIDE_INC) -I$(UDIS86)
LDLIBS = -ldl -L$(CINSIDE_LIB)
APP = linja
OBJ = syscalls.o
EXAMPLES_LIST = breakpoint ptrace signal timing

EXAMPLES = $(EXAMPLES_LIST:%=$(EXAMPLES_DIR)/%)

all: $(APP) $(EXAMPLES)

$(APP): $(APP).c $(OBJ) $(CINSIDE)/libc-inside/.libs/libc-inside.a \
    $(UDIS86)/libudis86/.libs/libudis86.a

$(OBJ): %.o: %.c

$(EXAMPLES): %: %.c

clean:
	rm -f $(APP) $(OBJ) $(EXAMPLES)
