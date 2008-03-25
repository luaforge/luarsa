# $Id: Makefile,v 1.1 2008-03-25 18:02:02 jasonsantos Exp $

T= luarsa
V= 0.1.0


CONFIG= ./config

include $(CONFIG)

LUARSA_OBJS= src/luarsa.o 
LUARSA_LUAS= src/rsa.lua

all: src/rsa/core.so

src/$(LIBNAME) : $(LUARSA_OBJS) $(XYSSL_LIB)
	export MACOSX_DEPLOYMENT_TARGET="10.3"; $(CC) $(CFLAGS) $(LIB_OPTION) -o src/$(LIBNAME) $(LUARSA_OBJS) -lxyssl

src/rsa/core.so: src/$(LIBNAME) 
	cp src/$(LIBNAME) src/rsa/core.so

install:
	mkdir -p $(LUA_LIBDIR)/rsa
	cp src/$(LIBNAME) $(LUA_LIBDIR)/rsa
	cd $(LUA_LIBDIR)/rsa; ln -f -s $(LIBNAME) core.so
	mkdir -p $(LUA_DIR)
	cp $(LUARSA_LUAS) $(LUA_DIR)

clean:
	rm -f src/$(LIBNAME) $(OBJS)

