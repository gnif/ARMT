CC       = g++-4.3
OBJCOPY  = objcopy
CFLAGS   = -Wall -D__STDC_LIMIT_MACROS
OBJECTS  = armt.o
INCFLAGS = -I./
LDFLAGS  = -Wl,-rpath,/usr/local/lib
OUTPUT   = armt

CFLAGS  += -g -O0
LDFLAGS += -Wl,-Bstatic -static -static-libgcc
LDFLAGS += -Wl,-wrap,gethostbyname

INCFLAGS += -Ilibs/zlib-1.2.7
INCFLAGS += -Ilibs/pcre-8.20
INCFLAGS += -Ilibs/polarssl/include

OBJECTS += common/CCommon.o
OBJECTS += common/CCompress.o
OBJECTS += common/CDNS.o
OBJECTS += common/CProcInfo.o
OBJECTS += common/CPCIInfo.o
OBJECTS += common/CHTTP.o
OBJECTS += common/CMessageBuilder.o
OBJECTS += common/CScheduler.o

OBJECTS += block/CBlockEnumerator.o
OBJECTS += block/CSMARTBlockDevice.o
OBJECTS += block/CCCISSBlockDevice.o
OBJECTS += block/CMDBlockDevice.o

OBJECTS += fs/CFSVerifier.o

ARCHIVES += libs/libs.a
ARCHIVES += utils/utils.a

#CFLAGS += -DHAS_LIBPCI
#LIBS   += -lpci -lz -lresolv

all: armt

armt: $(ARCHIVES) $(OBJECTS)
	$(CC) -o $(OUTPUT)_`uname -m` $(OBJECTS) $(ARCHIVES) $(LDFLAGS) $(LIBS)

%.o: %.cc
	$(CC) -c -o $@ $(CFLAGS) $< $(INCFLAGS)

utils/utils.a:
	$(MAKE) -C utils

libs/libs.a:
	$(MAKE) -C libs

clean:
	rm -f $(OBJECTS) $(OUTPUT)_`uname -m`

distclean: clean
	$(MAKE) -C utils distclean
	$(MAKE) -C libs  distclean

pack:
	strip -s $(OUTPUT)_`uname -m`
	upx --ultra-brute $(OUTPUT)_`uname -m`

.PHONY: all
.PHONY: clean
.PHONY: pack
