##
## EPITECH PROJECT, 2018
## Makefile objdump
## File description:
## makefile objdump
##

NAME		=	strace

CC		=	cc

CFLAGS		+=	-g -Iinc -W -Wall -Wextra

LDFLAGS		+=	-L -lm -fdiagnostics-color=always

FILES		=	src/main.c				\
				src/arg_tab.c			\
				src/check_command.c		\
				src/getenv.c			\
				src/my_strtok.c			\
				src/print.c				\
				src/my_strace.c			\
				src/my_strace_s.c		\
				src/my_print_s_inout.c	\
				src/my_strace_p.c		\
				src/utils.c				\

SRCS		=	$(FILES)

OBJ		=	$(SRCS:.c=.o) $(MAIN:.c=.o)

.PHONY: fclean clean all re debug

RED		=	\033[0;31m
GREEN		=	\033[0;32m
NC		=	\033[0m
GREY		=	\033[90m
BG_COLOR	=	\033[46m

all:			$(NAME)

$(NAME):	$(OBJ)
	@echo -e 'Flags: $(LDFLAGS) $(CFLAGS)${NC}'
	@echo -e '${GREEN}Create${NC}: ${GREY}./$(NAME)${NC}'
	@$(CC) $(OBJ) -o $(NAME) $(LDFLAGS)

%.o:		%.c
	@echo -e '${GREEN} [ OK ]${NC} Building : $<'
	@$(CC) -o $@ -c $< $(LDFLAGS) $(CFLAGS)

clean:
	@rm -rf $(OBJ)
	@rm -rf $(OBJ_T)
	@rm -rf vgcore.*
	@rm -f gmon.out
	@rm -rf a.out
	@find . -name *.gc* -delete
	@echo -e '${RED}Clean${NC} : OK'

fclean:		clean
	@rm -rf $(NAME)
	@echo -e '${RED}Fclean${NC}: ./$(NAME) removed'

re:		fclean all
