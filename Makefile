AR = /usr/bin/ar
CC = /usr/bin/gcc
CFLAGS = -Wall -O3 -g

all: hss_lib.a \
     hss_lib_thread.a \
     hss_verify.a \
     demo \
	 demo_st \
     test_hss

hss_lib.a: hss.o hss_alloc.o hss_aux.o hss_common.o \
     hss_compute.o hss_generate.o hss_keygen.o hss_param.o hss_reserve.o \
     hss_sign.o hss_sign_inc.o hss_thread_single.o \
     hss_verify.o hss_verify_inc.o hss_derive.o \
     hss_derive.o hss_zeroize.o lm_common.o \
     lm_ots_common.o lm_ots_sign.o lm_ots_verify.o lm_verify.o endian.o \
     hash.o sha256.o ossl_sha3.o ossl_keccak1600.o bh_sha3.o
	$(AR) rcs $@ $^

hss_lib_thread.a: hss.o hss_alloc.o hss_aux.o hss_common.o \
     hss_compute.o hss_generate.o hss_keygen.o hss_param.o hss_reserve.o \
     hss_sign.o hss_sign_inc.o hss_thread_pthread.o \
     hss_verify.o hss_verify_inc.o \
     hss_derive.o hss_zeroize.o lm_common.o \
     lm_ots_common.o lm_ots_sign.o lm_ots_verify.o lm_verify.o endian.o \
     hash.o sha256.o ossl_sha3.o ossl_keccak1600.o bh_sha3.o
	$(AR) rcs $@ $^

hss_verify.a: hss_verify.o hss_verify_inc.o hss_common.o hss_thread_single.o \
    hss_zeroize.o lm_common.o lm_ots_common.o lm_ots_verify.o lm_verify.o \
    endian.o hash.o sha256.o ossl_sha3.o ossl_keccak1600.o bh_sha3.o
	$(AR) rcs $@ $^

demo: demo.c hss_lib_thread.a
	$(CC) $(CFLAGS) demo.c hss_lib_thread.a -lcrypto -lpthread -o demo
	
demo_st: demo.c hss_lib.a
	$(CC) $(CFLAGS) demo.c hss_lib.a -lcrypto -o demo_st

test_1: test_1.c lm_ots_common.o lm_ots_sign.o lm_ots_verify.o  endian.o hash.o sha256.o ossl_sha3.o bh_sha3.o hss_zeroize.o
	$(CC) $(CFLAGS) -o test_1 test_1.c lm_ots_common.o lm_ots_sign.o lm_ots_verify.o  endian.o hash.o sha256.o ossl_sha3.o bh_sha3.o hss_zeroize.o -lcrypto

test_hss: test_hss.c test_hss.h test_testvector.c test_stat.c test_keygen.c test_load.c test_sign.c test_sign_inc.c test_verify.c test_verify_inc.c test_keyload.c test_reserve.c test_thread.c test_h25.c hss.h hss_lib_thread.a
	$(CC) $(CFLAGS) test_hss.c test_testvector.c test_stat.c test_keygen.c test_sign.c test_sign_inc.c test_load.c test_verify.c test_verify_inc.c test_keyload.c test_reserve.c test_thread.c test_h25.c hss_lib_thread.a -lcrypto -lpthread -o test_hss

hss.o: hss.c hss.h common_defs.h hash.h endian.h hss_internal.h hss_aux.h hss_derive.h
	$(CC) $(CFLAGS) -c hss.c -o $@

hss_alloc.o: hss_alloc.c hss.h hss_internal.h lm_common.h
	$(CC) $(CFLAGS) -c hss_alloc.c -o $@

hss_aux.o: hss_aux.c hss_aux.h hss_internal.h common_defs.h lm_common.h endian.h hash.h
	$(CC) $(CFLAGS) -c hss_aux.c -o $@

hss_common.o: hss_common.c common_defs.h hss_common.h lm_common.h
	$(CC) $(CFLAGS) -c hss_common.c -o $@

hss_compute.o: hss_compute.c hss_internal.h hash.h hss_thread.h lm_ots_common.h lm_ots.h endian.h hss_derive.h
	$(CC) $(CFLAGS) -c hss_compute.c -o $@

hss_derive.o: hss_derive.c hss_derive.h hss_internal.h hash.h endian.h
	$(CC) $(CFLAGS) -c hss_derive.c -o $@

hss_generate.o: hss_generate.c hss.h hss_internal.h hss_aux.h hash.h hss_thread.h hss_reserve.h lm_ots_common.h endian.h
	$(CC) $(CFLAGS) -c hss_generate.c -o $@

hss_keygen.o: hss_keygen.c hss.h common_defs.h hss_internal.h hss_aux.h endian.h hash.h hss_thread.h lm_common.h lm_ots_common.h
	$(CC) $(CFLAGS) -c hss_keygen.c -o $@

hss_param.o: hss_param.c hss.h hss_internal.h endian.h hss_zeroize.h
	$(CC) $(CFLAGS) -c hss_param.c -o $@

hss_reserve.o: hss_reserve.c common_defs.h hss_internal.h hss_reserve.h endian.h
	$(CC) $(CFLAGS) -c hss_reserve.c -o $@
   
hss_sign.o: hss_sign.c common_defs.h hss.h hash.h endian.h hss_internal.h hss_aux.h hss_thread.h hss_reserve.h lm_ots.h lm_ots_common.h hss_derive.h
	$(CC) $(CFLAGS) -c hss_sign.c -o $@
   
hss_sign_inc.o: hss_sign_inc.c hss.h common_defs.h hss.h hash.h endian.h hss_internal.h hss_aux.h hss_reserve.h hss_derive.h lm_ots.h lm_ots_common.h hss_sign_inc.h
	$(CC) $(CFLAGS) -c hss_sign_inc.c -o $@

hss_thread_single.o: hss_thread_single.c hss_thread.h
	$(CC) $(CFLAGS) -c hss_thread_single.c -o $@

hss_thread_pthread.o: hss_thread_pthread.c hss_thread.h
	$(CC) $(CFLAGS) -c hss_thread_pthread.c -o $@

hss_verify.o: hss_verify.c hss_verify.h common_defs.h lm_verify.h lm_common.h lm_ots_verify.h hash.h endian.h hss_thread.h
	$(CC) $(CFLAGS) -c hss_verify.c -o $@

hss_verify_inc.o: hss_verify_inc.c hss_verify_inc.h common_defs.h lm_verify.h lm_common.h lm_ots_verify.h hash.h endian.h hss_thread.h
	$(CC) $(CFLAGS) -c hss_verify_inc.c -o $@

hss_zeroize.o: hss_zeroize.c hss_zeroize.h
	$(CC) $(CFLAGS) -c hss_zeroize.c -o $@

lm_common.o: lm_common.c lm_common.h hash.h common_defs.h lm_ots_common.h
	$(CC) $(CFLAGS) -c lm_common.c -o $@

lm_ots_common.o: lm_ots_common.c common_defs.h hash.h
	$(CC) $(CFLAGS) -c lm_ots_common.c -o $@

lm_ots_sign.o: lm_ots_sign.c common_defs.h lm_ots.h lm_ots_common.h hash.h endian.h hss_zeroize.h hss_derive.h
	$(CC) $(CFLAGS) -c lm_ots_sign.c -o $@

lm_ots_verify.o: lm_ots_verify.c lm_ots_verify.h lm_ots_common.h hash.h endian.h common_defs.h
	$(CC) $(CFLAGS) -c lm_ots_verify.c -o $@

lm_verify.o: lm_verify.c lm_verify.h lm_common.h lm_ots_common.h lm_ots_verify.h hash.h endian.h common_defs.h
	$(CC) $(CFLAGS) -c lm_verify.c -o $@

endian.o: endian.c endian.h
	$(CC) $(CFLAGS) -c endian.c -o $@

hash.o: hash.c hash.h sha256.h ossl_sha3.h bh_sha3.h hss_zeroize.h
	$(CC) $(CFLAGS) -c hash.c -o $@

sha256.o: sha256.c sha256.h endian.h
	$(CC) $(CFLAGS) -c sha256.c -o $@

ossl_sha3.o: ossl_sha3.c ossl_sha3.h ossl_keccak1600.c ossl_nelem.h endian.h
	$(CC) $(CFLAGS) -c ossl_sha3.c -o $@

ossl_keccak1600.o: ossl_keccak1600.c ossl_nelem.h
	$(CC) $(CFLAGS) -c ossl_keccak1600.c -o $@

bh_sha3.o: bh_sha3.c bh_sha3.h
	$(CC) $(CFLAGS) -c bh_sha3.c -o $@
clean:
	-rm *.o *.a demo demo_st test_hss


