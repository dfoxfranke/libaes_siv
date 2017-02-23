DESTDIR=/usr/local
PREFIX=$(DESTDIR)

WARNFLAGS=-Wall -Wconversion
LDFLAGS=-lcrypto -ftest-coverage -fprofile-arcs
OPTFLAGS=-O3 -fomit-frame-pointer -funroll-loops -ftree-vectorize -DNDEBUG
DEBUGFLAGS=-g -Og -DAES_SIV_DEBUG=1 -ftest-coverage -fprofile-arcs


all: aes-siv-test libaes_siv.a AES_SIV_CTX_new.3 AES_SIV_Encrypt.3 AES_SIV_Init.3

install: aes_siv.h libaes_siv.a AES_SIV_CTX_new.3 AES_SIV_Encrypt.3 AES_SIV_Init.3
	install -m 644 aes_siv.h $(PREFIX)/include
	install libaes_siv.a $(PREFIX)/lib
	install -m 644 *.3 $(PREFIX)/share/man/man3

clean:
	$(RM) aes_siv.o aes_siv_test.o tests.o aes-siv-test libaes_siv.a
	$(RM) AES_SIV_CTX_copy.3 AES_SIV_CTX_cleanup.3 AES_SIV_CTX_free.3 AES_SIV_CTX_new.3
	$(RM) AES_SIV_Decrypt.3 AES_SIV_Encrypt.3
	$(RM) AES_SIV_AssociateData.3 AES_SIV_EncryptFinal.3 AES_SIV_DecryptFinal.3 AES_SIV_Init.3

aes_siv.o: aes_siv.c aes_siv.h
	$(CC) -c $(WARNFLAGS) $(OPTFLAGS) aes_siv.c

aes_siv_test.o: aes_siv.c aes_siv.h
	$(CC) -c -o aes_siv_test.o $(WARNFLAGS) $(DEBUGFLAGS) aes_siv.c

tests.o: tests.c aes_siv.h
	$(CC) -c $(WARNFLAGS) $(DEBUGFLAGS) tests.c

aes-siv-test: aes_siv_test.o tests.o
	$(CC) -o aes-siv-test $(WARNFLAGS) $(LDFLAGS) aes_siv_test.o tests.o

libaes_siv.a: aes_siv.o
	$(AR) rcs libaes_siv.a aes_siv.o

%.3: %.adoc
	a2x -f manpage $<

AES_SIV_CTX_copy.3 AES_SIV_CTX_cleanup.3 AES_SIV_CTX_free.3: AES_SIV_CTX_new.3
AES_SIV_Decrypt.3: AES_SIV_Encrypt.3
AES_SIV_AssociateData.3 AES_SIV_EncryptFinal.3 AES_SIV_DecryptFinal.3: AES_SIV_Init.3
