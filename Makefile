CC		= gcc
MD		= mkdir
RM		= rm
CFLAGS	= -g -Wall
LIBS	= -lpthread -lrt

INC_DIR = include
SRC_DIR = src
BLD_DIR = build

TARGET 	= ${BLD_DIR}/cache_proxy

SRCS = 	${SRC_DIR}/main.c				\
		${SRC_DIR}/logger.c				\
		${SRC_DIR}/cache-storage.c		\
		${SRC_DIR}/cache-entry.c		\
		${SRC_DIR}/threadpool.c			\
		${SRC_DIR}/proxy.c				\
		${SRC_DIR}/client-handler.c		\
		${SRC_DIR}/picohttpparser.c

INCS = 	${INC_DIR}/logger.h				\
		${INC_DIR}/cache-storage.h		\
		${INC_DIR}/cache-entry.h		\
		${INC_DIR}/threadpool.h			\
		${INC_DIR}/proxy.h				\
		${INC_DIR}/client-handler.h		\
		${INC_DIR}/picohttpparser.h

all: ${TARGET}

run: ${TARGET}
	./$<

${TARGET}: ${SRCS} ${INCS} | ${BLD_DIR}
	${CC} ${CFLAGS} -I${INC_DIR} ${SRCS} ${LIBS} -o $@

${BLD_DIR}:
	${MD} -p $@

clean:
	${RM} -rf ${BLD_DIR}

.PHONY: all clean
