SYSTEM := $(shell uname -s)

all:

ifeq ($(SYSTEM), Darwin)
	gcc -DCK_GENERIC -o info -I/Library/Frameworks/jcPKCS11.framework/Headers -framework jcPKCS11 info.c
else
	gcc -DCK_GENERIC -o info -I/usr/include/jcPKCS11 -ljcPKCS11 info.c
endif
