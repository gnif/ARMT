PCRE = pcre-8.20
SSL  = polarssl-1.1.4
ZLIB = zlib-1.2.7

all: libs.a

libs.a: pcre-stamp ssl-stamp zlib-stamp
	rm .objects -rf

	mkdir -p .objects/pcre
	cd .objects/pcre && $(AR) -x $(CURDIR)/$(PCRE)/.libs/libpcrecpp.a
	cd .objects/pcre && $(AR) -x $(CURDIR)/$(PCRE)/.libs/libpcre.a

	mkdir -p .objects/ssl
	cd .objects/ssl && $(AR) -x $(CURDIR)/$(SSL)/library/libpolarssl.a

	mkdir -p .objects/zlib
	cd .objects/zlib && $(AR) -x $(CURDIR)/$(ZLIB)/libz.a

	$(AR) -r libs.a .objects/*/*.o

pcre-stamp:
	cd $(PCRE)			&& \
		libtoolize		&& \
		autoreconf -f	&& \
		./configure --enable-static=yes --enable-shared=no
	$(MAKE) -C $(PCRE)
	touch pcre-stamp

ssl-stamp:
	$(MAKE) -C $(SSL)
	touch ssl-stamp

zlib-stamp:
	cd $(ZLIB) && ./configure --static
	$(MAKE) -C $(ZLIB)
	touch zlib-stamp

clean:
	rm -rf libs.a *-stamp
	$(MAKE) -C $(PCRE) clean
	$(MAKE) -C $(SSL)  clean
	$(MAKE) -C $(ZLIB) clean

distclean: clean
	$(MAKE) -C $(PCRE) distclean
	$(MAKE) -C $(ZLIB) distclean

.PHONY: all clean distclean
