GCC     = gcc

OBJECTS += cciss_vol_status.o
OBJECTS += smartctl.o
OBJECTS += lsscsi.o
OBJECTS += megactl.o

all: $(OBJECTS) utils.a

utils.a:
	$(AR) -r utils.a $(OBJECTS)

cciss_vol_status.o:
	$(MAKE) -C cciss_vol_status
	strip -s cciss_vol_status/cciss_vol_status
	$(GCC) -c cciss_vol_status.S -o cciss_vol_status.o

smartctl.o:
	$(MAKE) -C smartmontools
	strip -s smartmontools/smartctl
	$(GCC) -c smartctl.S -o smartctl.o

lsscsi.o:
	$(MAKE) -C lsscsi
	strip -s lsscsi/src/lsscsi
	$(GCC) -c lsscsi.S -o lsscsi.o

megactl.o:
	$(MAKE) -C megactl/src
	strip -s megactl/src/megactl
	strip -s megactl/src/megasasctl
	$(GCC) -c megactl.S -o megactl.o

clean:
	rm -f $(OBJECTS) utils.a
	$(MAKE) -C cciss_vol_status clean
	$(MAKE) -C smartmontools clean
	$(MAKE) -C lsscsi clean

.PHONY: all clean

