#include "fct.h"

#include <polarssl/aes.h>

#include <polarssl/config.h>

#ifdef _MSC_VER
#include <basetsd.h>
typedef UINT32 uint32_t;
#else
#include <inttypes.h>
#endif

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

int unhexify(unsigned char *obuf, const char *ibuf)
{
    unsigned char c, c2;
    int len = strlen(ibuf) / 2;
    assert(!(strlen(ibuf) %1)); // must be even number of bytes

    while (*ibuf != 0)
    {
        c = *ibuf++;
        if( c >= '0' && c <= '9' )
            c -= '0';
        else if( c >= 'a' && c <= 'f' )
            c -= 'a' - 10;
        else if( c >= 'A' && c <= 'F' )
            c -= 'A' - 10;
        else
            assert( 0 );

        c2 = *ibuf++;
        if( c2 >= '0' && c2 <= '9' )
            c2 -= '0';
        else if( c2 >= 'a' && c2 <= 'f' )
            c2 -= 'a' - 10;
        else if( c2 >= 'A' && c2 <= 'F' )
            c2 -= 'A' - 10;
        else
            assert( 0 );

        *obuf++ = ( c << 4 ) | c2;
    }

    return len;
}

void hexify(unsigned char *obuf, const unsigned char *ibuf, int len)
{
    unsigned char l, h;

    while (len != 0)
    {
        h = (*ibuf) / 16;
        l = (*ibuf) % 16;

        if( h < 10 )
            *obuf++ = '0' + h;
        else
            *obuf++ = 'a' + h - 10;

        if( l < 10 )
            *obuf++ = '0' + l;
        else
            *obuf++ = 'a' + l - 10;

        ++ibuf;
        len--;
    }
}

/**
 * This function just returns data from rand().
 * Although predictable and often similar on multiple
 * runs, this does not result in identical random on
 * each run. So do not use this if the results of a
 * test depend on the random data that is generated.
 *
 * rng_state shall be NULL.
 */
static int rnd_std_rand( void *rng_state, unsigned char *output, size_t len )
{
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();

    return( 0 );
}

/**
 * This function only returns zeros
 *
 * rng_state shall be NULL.
 */
static int rnd_zero_rand( void *rng_state, unsigned char *output, size_t len )
{
    if( rng_state != NULL )
        rng_state  = NULL;

    memset( output, 0, len );

    return( 0 );
}

typedef struct
{
    unsigned char *buf;
    size_t length;
} rnd_buf_info;

/**
 * This function returns random based on a buffer it receives.
 *
 * rng_state shall be a pointer to a rnd_buf_info structure.
 * 
 * The number of bytes released from the buffer on each call to
 * the random function is specified by per_call. (Can be between
 * 1 and 4)
 *
 * After the buffer is empty it will return rand();
 */
static int rnd_buffer_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_buf_info *info = (rnd_buf_info *) rng_state;
    size_t use_len;

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    use_len = len;
    if( len > info->length )
        use_len = info->length;

    if( use_len )
    {
        memcpy( output, info->buf, use_len );
        info->buf += use_len;
        info->length -= use_len;
    }

    if( len - use_len > 0 )
        return( rnd_std_rand( NULL, output + use_len, len - use_len ) );

    return( 0 );
}

/**
 * Info structure for the pseudo random function
 *
 * Key should be set at the start to a test-unique value.
 * Do not forget endianness!
 * State( v0, v1 ) should be set to zero.
 */
typedef struct
{
    uint32_t key[16];
    uint32_t v0, v1;
} rnd_pseudo_info;

/**
 * This function returns random based on a pseudo random function.
 * This means the results should be identical on all systems.
 * Pseudo random is based on the XTEA encryption algorithm to
 * generate pseudorandom.
 *
 * rng_state shall be a pointer to a rnd_pseudo_info structure.
 */
static int rnd_pseudo_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_pseudo_info *info = (rnd_pseudo_info *) rng_state;
    uint32_t i, *k, sum, delta=0x9E3779B9;
    unsigned char result[4];

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    k = info->key;

    while( len > 0 )
    {
        size_t use_len = ( len > 4 ) ? 4 : len;
        sum = 0;

        for( i = 0; i < 32; i++ )
        {
            info->v0 += (((info->v1 << 4) ^ (info->v1 >> 5)) + info->v1) ^ (sum + k[sum & 3]);
            sum += delta;
            info->v1 += (((info->v0 << 4) ^ (info->v0 >> 5)) + info->v0) ^ (sum + k[(sum>>11) & 3]);
        }

        PUT_ULONG_BE( info->v0, result, 0 );
        memcpy( output, result, use_len );
        len -= use_len;
    }

    return( 0 );
}


FCT_BGN()
{
#ifdef POLARSSL_AES_C


    FCT_SUITE_BGN(test_suite_aes)
    {

        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "f34481ec3cc627bacd5dc3fb08f273e6" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "0336763e966d92595a567cc9ce537f5e" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "9798c4640bad75c7c3227db910174e72" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "a9a1631bf4996954ebc093957b234589" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "96ab5c2ff612d9dfaae8c31f30c42168" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "ff4f8391a6a40ca5b25d23bedd44a597" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "e0000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "72a1da770f5d7ac4c9ef94d822affd97" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "970014d634e2b7650777e8e84d03ccd8" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f8000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "f17e79aed0db7e279e955b5f493875a7" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffff0000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "7b90785125505fad59b13c186dd66ce3" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffff8000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "8b527a6aebdaec9eaef8eda2cb7783e5" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffc000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "43fdaf53ebbc9880c228617d6a9b548b" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffffffffffffffffc000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "70c46bb30692be657f7eaa93ebad9897" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffffffffffffffffe000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "323994cfb9da285a5d9642e1759b224a" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffff000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "1dbf57877b7b17385c85d0b54851e371" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_13)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "ffffffffffffffc00000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "3a4d354f02bb5a5e47d39666867f246a" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_14)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "ffffffffffffffe00000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "d451b8d6e1e1a0ebb155fbbf6e7b7dc3" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_15)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "fffffffffffffff00000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "6898d4f42fa7ba6a10ac05e87b9f2080" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_16)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "ffffffffffffffffffffffffe0000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "082eb8be35f442fb52668e16a591d1d6" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_17)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "fffffffffffffffffffffffff0000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "e656f9ecf5fe27ec3e4a73d00c282fb3" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_encrypt_nist_kat_18)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "fffffffffffffffffffffffff8000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "2ca8209d63274cd9a29bb74bcd77683a" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_decrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "db4f1aa530967d6732ce4715eb0ee24b" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "ff000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_decrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "a81738252621dd180a34f3455b4baa2f" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "ff800000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_decrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "77e2b508db7fd89234caf7939ee5621a" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "ffc00000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_decrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "dc43be40be0e53712f7e2bf5ca707209" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "6a118a874519e64e9963798a503f1d35" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_decrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "92beedab1895a94faa69b632e5cc47ce" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "cb9fceec81286ca3e989bd979b0cb284" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_decrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( src_str, "459264f4798f6a78bacb89c15ed3d601" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "b26aeb1874e47ca8358ff22378f09144" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_decrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "b69418a85332240dc82492353956ae0c" );
            unhexify( src_str, "a303d940ded8f0baff6f75414cac5243" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_decrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "71b5c08a1993e1362e4d0ce9b22b78d5" );
            unhexify( src_str, "c2dabd117f8a3ecabfbb11d12194d9d0" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_decrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "e234cdca2606b81f29408d5f6da21206" );
            unhexify( src_str, "fff60a4740086b3b9c56195b98d91a7b" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_decrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffff0000000000000000" );
            unhexify( src_str, "84be19e053635f09f2665e7bae85b42d" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_ecb_decrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffff8000000000000000" );
            unhexify( src_str, "32cd652842926aea4aa6137bb2be2b5e" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "fffffffffffffffffffff80000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "156f07767a85a4312321f63968338a01" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "fffffffffffffffffffffc0000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "15eec9ebf42b9ca76897d2cd6c5a12e2" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "fffffffffffffffffffffe0000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "db0d3a6fdcc13f915e2b302ceeb70fd8" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "51719783d3185a535bd75adc65071ce1" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "4f354592ff7c8847d2d0870ca9481b7c" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "26aa49dcfe7629a8901a69a9914e6dfd" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "d5e08bf9a182e857cf40b3a36ee248cc" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "941a4773058224e1ef66d10e0a6ee782" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "067cd9d3749207791841562507fa9626" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "d2926527e0aa9f37b45e2ec2ade5853ef807576104c7ace3" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "dd619e1cf204446112e0af2b9afa8f8c" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "982215f4e173dfa0fcffe5d3da41c4812c7bcc8ed3540f93" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "d4f0aae13c8fe9339fbf9e69ed0ad74d" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "98c6b8e01e379fbd14e61af6af891596583565f2a27d59e9" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "19c80ec4a6deb7e5ed1033dda933498f" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffff800000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "8dd274bd0f1b58ae345d9e7233f9b8f3" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffc00000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "9d6bdc8f4ce5feb0f3bed2e4b9a9bb0b" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_encrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffe00000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "fd5548bcf3f42565f7efa94562528d46" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffffffff000000000000000" );
            unhexify( src_str, "bb2852c891c5947d2ed44032c421b85f" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffffffff800000000000000" );
            unhexify( src_str, "1b9f5fbd5e8a4264c0a85b80409afa5e" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffffffffc00000000000000" );
            unhexify( src_str, "30dab809f85a917fe924733f424ac589" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "61257134a518a0d57d9d244d45f6498cbc32f2bafc522d79" );
            unhexify( src_str, "cfe4d74002696ccf7d87b14a2f9cafc9" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "b0ab0a6a818baef2d11fa33eac947284fb7d748cfb75e570" );
            unhexify( src_str, "d2eafd86f63b109b91f5dbb3a3fb7e13" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ee053aa011c8b428cdcc3636313c54d6a03cac01c71579d6" );
            unhexify( src_str, "9b9fdd1c5975655f539998b306a324af" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "275cfc0413d8ccb70513c3859b1d0f72" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "1b077a6af4b7f98229de786d7516b639" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "c9b8135ff1b5adc413dfd053b21bd96d" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "9c2d8842e5f48f57648205d39a239af1" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "4a3650c3371ce2eb35e389a171427440" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "bff52510095f518ecca60af4205444bb" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "b2099795e88cc158fd75ea133d7e7fbe" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "ffffffffffffffffffffc00000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "a6cae46fb6fadfe7a2c302a34242817b" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "ffffffffffffffffffffe00000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_ecb_decrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "026a7024d6a902e0b3ffccbaa910cc3f" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "fffffffffffffffffffff00000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "c1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "352065272169abf9856843927d0674fd" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "984ca75f4ee8d706f46c2d98c0bf4a45f5b00d791c2dfeb191b5ed8e420fd627" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "4307456a9e67813b452e15fa8fffe398" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "4663446607354989477a5c6f0f007ef4" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "0b24af36193ce4665f2825d7b4749c98" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "a9ff75bd7cf6613d3731c77c3b6d0c04" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "761c1fe41a18acf20d241650611d90f1" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "623a52fcea5d443e48d9181ab32c7421" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "8a560769d605868ad80d819bdba03771" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "38f2c7ae10612415d27ca190d27da8b4" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "ffffff80000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "36aff0ef7bf3280772cf4cac80a0d2b2" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "ffffffc0000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "1f8eedea0f62a1406d58cfc3ecea72cf" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "ffffffe0000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "abf4154a3375a1d3e6b1d454438f95a6" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffffffffffffffffffffffff8000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "45d089c36d5c5a4efc689e3b0de10dd5" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffffffffffffffffffffffffc000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "b4da5df4becb5462e03a0ed00d295629" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_encrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffffffffffffffffffffffffe000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "dcf4e129136c1a4b7a0f38935cc34b2b" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffffffffffffffffffffff00000000000000000" );
            unhexify( src_str, "edf61ae362e882ddc0167474a7a77f3a" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffffffffffffffffffffff80000000000000000" );
            unhexify( src_str, "6168b00ba7859e0970ecfd757efecf7c" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffffffffffffffffffffffc0000000000000000" );
            unhexify( src_str, "d1415447866230d28bb1ea18a4cdfd02" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f8be9ba615c5a952cabbca24f68f8593039624d524c816acda2c9183bd917cb9" );
            unhexify( src_str, "a3944b95ca0b52043584ef02151926a8" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "797f8b3d176dac5b7e34a2d539c4ef367a16f8635f6264737591c5c07bf57a3e" );
            unhexify( src_str, "a74289fe73a4c123ca189ea1e1b49ad5" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "6838d40caf927749c13f0329d331f448e202c73ef52c5f73a37ca635d4c47707" );
            unhexify( src_str, "b91d4ea4488644b56cf0812fa7fcf5fc" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "623a52fcea5d443e48d9181ab32c7421" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "761c1fe41a18acf20d241650611d90f1" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "38f2c7ae10612415d27ca190d27da8b4" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "8a560769d605868ad80d819bdba03771" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "1bc704f1bce135ceb810341b216d7abe" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "91fbef2d15a97816060bee1feaa49afe" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "ddc6bf790c15760d8d9aeb6f9a75fd4e" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "80000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "0a6bdc6d4c1e6280301fd8e97ddbe601" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "c0000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_ecb_decrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( src_str, "9b80eefb7ebe2d2b16247aa0efc72f5d" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "e0000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffff8000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "8b527a6aebdaec9eaef8eda2cb7783e5" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffc000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "43fdaf53ebbc9880c228617d6a9b548b" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffe000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "53786104b9744b98f052c46f1c850d0b" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "e37b1c6aa2846f6fdb413f238b089f23" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "43c9f7e62f5d288bb27aa40ef8fe1ea8" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "6c002b682483e0cabcc731c253be5674" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "3580d19cff44f1014a7c966a69059de5" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "143ae8ed6555aba96110ab58893a8ae1" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "806da864dd29d48deafbe764f8202aef" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "6a118a874519e64e9963798a503f1d35" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "dc43be40be0e53712f7e2bf5ca707209" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "cb9fceec81286ca3e989bd979b0cb284" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "92beedab1895a94faa69b632e5cc47ce" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "b26aeb1874e47ca8358ff22378f09144" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "459264f4798f6a78bacb89c15ed3d601" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "ffffffffffffffffffffffc000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "90684a2ac55fe1ec2b8ebd5622520b73" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "ffffffffffffffffffffffe000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "7472f9a7988607ca79707795991035e6" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_encrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "fffffffffffffffffffffff000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "56aff089878bf3352f8df172a3ae47d8" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffe00000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "23f710842b9bb9c32f26648c786807ca" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffff00000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "44a98bf11e163f632c47ec6a49683a89" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffff80000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "0f18aff94274696d9b61848bd50ac5e5" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "e234cdca2606b81f29408d5f6da21206" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "fff60a4740086b3b9c56195b98d91a7b" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "13237c49074a3da078dc1d828bb78c6f" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "8146a08e2357f0caa30ca8c94d1a0544" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "3071a2a48fe6cbd04f1a129098e308f8" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "4b98e06d356deb07ebb824e5713f7be3" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "0336763e966d92595a567cc9ce537f5e" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "f34481ec3cc627bacd5dc3fb08f273e6" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "a9a1631bf4996954ebc093957b234589" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "9798c4640bad75c7c3227db910174e72" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "ff4f8391a6a40ca5b25d23bedd44a597" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "96ab5c2ff612d9dfaae8c31f30c42168" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "f9b0fda0c4a898f5b9e6f661c4ce4d07" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "fffffffffffffffffffffffffffffff0" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "8ade895913685c67c5269f8aae42983e" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "fffffffffffffffffffffffffffffff8" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_128_cbc_decrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "39bde67d5c8ed8a8b1c37eb8fa9f5ac0" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "fffffffffffffffffffffffffffffffc" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffffffffffffffffffffe00" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "ddb505e6cc1384cbaec1df90b80beb20" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffffffffffffffffffffffffffffffffff00" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "5674a3bed27bf4bd3622f9f5fe208306" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffffffffffffffffffffffffffffffffff80" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "b687f26a89cfbfbb8e5eeac54055315e" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "25a39dbfd8034f71a81f9ceb55026e4037f8f6aa30ab44ce" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "3608c344868e94555d23a120f8a5502d" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "e08c15411774ec4a908b64eadc6ac4199c7cd453f3aaef53" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "77da2021935b840b7f5dcc39132da9e5" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "3b375a1ff7e8d44409696e6326ec9dec86138e2ae010b980" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "3b7c24f825e3bf9873c9f14d39a0e6f4" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "51719783d3185a535bd75adc65071ce1" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "4f354592ff7c8847d2d0870ca9481b7c" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "26aa49dcfe7629a8901a69a9914e6dfd" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "d5e08bf9a182e857cf40b3a36ee248cc" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "941a4773058224e1ef66d10e0a6ee782" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "067cd9d3749207791841562507fa9626" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "ffc00000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "030d7e5b64f380a7e4ea5387b5cd7f49" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "ffe00000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "0dc9a2610037009b698f11bb7e86c83e" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_encrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "fff00000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "0046612c766d1840c226364f1fa7ed72" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "902d88d13eae52089abd6143cfe394e9" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "ffffffffe00000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "d49bceb3b823fedd602c305345734bd2" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "fffffffff00000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "707b1dbb0ffa40ef7d95def421233fae" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "fffffffff80000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffc0000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "8dfd999be5d0cfa35732c0ddc88ff5a5" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffe0000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "02647c76a300c3173b841487eb2bae9f" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffffffff0000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "172df8b02f04b53adab028b4e01acd87" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "b3ad5cea1dddc214ca969ac35f37dae1a9a9d1528f89bb35" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "3cf5e1d21a17956d1dffad6a7c41c659" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "45899367c3132849763073c435a9288a766c8b9ec2308516" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "69fd12e8505f8ded2fdcb197a121b362" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ec250e04c3903f602647b85a401a1ae7ca2f02f67fa4253e" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "8aa584e2cc4d17417a97cb9a28ba29c8" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "c9b8135ff1b5adc413dfd053b21bd96d" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "9c2d8842e5f48f57648205d39a239af1" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "4a3650c3371ce2eb35e389a171427440" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "bff52510095f518ecca60af4205444bb" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_192_cbc_decrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "4f354592ff7c8847d2d0870ca9481b7c" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "51719783d3185a535bd75adc65071ce1" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "8000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "e35a6dcb19b201a01ebcfa8aa22b5759" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "c000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "b29169cdcf2d83e838125a12ee6aa400" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "e000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "d8f3a72fc3cdf74dfaf6c3e6b97b2fa6" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "dc0eba1f2232a7879ded34ed8428eeb8769b056bbaf8ad77cb65c3541430b4cf" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "fc6aec906323480005c58e7e1ab004ad" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f8be9ba615c5a952cabbca24f68f8593039624d524c816acda2c9183bd917cb9" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "a3944b95ca0b52043584ef02151926a8" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "797f8b3d176dac5b7e34a2d539c4ef367a16f8635f6264737591c5c07bf57a3e" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "a74289fe73a4c123ca189ea1e1b49ad5" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "761c1fe41a18acf20d241650611d90f1" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "623a52fcea5d443e48d9181ab32c7421" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "8a560769d605868ad80d819bdba03771" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "38f2c7ae10612415d27ca190d27da8b4" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "91fbef2d15a97816060bee1feaa49afe" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "1bc704f1bce135ceb810341b216d7abe" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "ffffffffffffff800000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "0d9ac756eb297695eed4d382eb126d26" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "ffffffffffffffc00000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "56ede9dda3f6f141bff1757fa689c3e1" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "ffffffffffffffe00000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "768f520efe0f23e61d3ec8ad9ce91774" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "49af6b372135acef10132e548f217b17" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "ff000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "8bcd40f94ebb63b9f7909676e667f1e7" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "ff800000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "fe1cffb83f45dcfb38b29be438dbd3ab" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "ffc00000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc00" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "cca7c3086f5f9511b31233da7cab9160" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe00" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "5b40ff4ec9be536ba23035fa4f06064c" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "60eb5af8416b257149372194e8b88749" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "90143ae20cd78c5d8ebdd6cb9dc1762427a96c78c639bccc41a61424564eafe1" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "798c7c005dee432b2c8ea5dfa381ecc3" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "b7a5794d52737475d53d5a377200849be0260a67a2b22ced8bbef12882270d07" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "637c31dc2591a07636f646b72daabbe7" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fca02f3d5011cfc5c1e23165d413a049d4526a991827424d896fe3435e0bf68e" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "179a49c712154bbffbe6e7a84a18e220" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "5c9d844ed46f9885085e5d6a4f94c7d7" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "014730f80ac625fe84f026c60bfd547d" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "a9ff75bd7cf6613d3731c77c3b6d0c04" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "0b24af36193ce4665f2825d7b4749c98" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "623a52fcea5d443e48d9181ab32c7421" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == 0 );
            if( 0 == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "761c1fe41a18acf20d241650611d90f1" ) == 0 );
            }
        }
        FCT_TEST_END();

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f0000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "970014d634e2b7650777e8e84d03ccd8" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f8000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "f17e79aed0db7e279e955b5f493875a7" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fc000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "9ed5a75136a940d0963da379db4af26a" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "64cf9c7abc50b888af65f49d521944b2" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "f7efc89d5dba578104016ce5ad659c05" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "47d6742eefcc0465dc96355e851b64d9" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "0306194f666d183624aa230a8b264ae7" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "3eb39790678c56bee34bbcdeccf6cdb5" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "858075d536d79ccee571f7d7204b1f67" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "6a118a874519e64e9963798a503f1d35" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "dc43be40be0e53712f7e2bf5ca707209" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "cb9fceec81286ca3e989bd979b0cb284" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "92beedab1895a94faa69b632e5cc47ce" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "b26aeb1874e47ca8358ff22378f09144" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "459264f4798f6a78bacb89c15ed3d601" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "fffffffffffffffffffffffffffffff0" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "f9b0fda0c4a898f5b9e6f661c4ce4d07" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "fffffffffffffffffffffffffffffff8" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "8ade895913685c67c5269f8aae42983e" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_encrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "fffffffffffffffffffffffffffffffc" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "39bde67d5c8ed8a8b1c37eb8fa9f5ac0" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffe000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "1114bc2028009b923f0b01915ce5e7c4" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffff000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "9c28524a16a1e1c1452971caa8d13476" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffff800000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "ed62e16363638360fdd6ad62112794f0" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "3071a2a48fe6cbd04f1a129098e308f8" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "4b98e06d356deb07ebb824e5713f7be3" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "90f42ec0f68385f2ffc5dfc03a654dce" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "7a20a53d460fc9ce0423a7a0764c6cf2" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "febd9a24d8b65c1c787d50a4ed3619a9" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "f4a70d8af877f9b02b4c40df57d45b17" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "f34481ec3cc627bacd5dc3fb08f273e6" );
            unhexify( src_str, "0336763e966d92595a567cc9ce537f5e" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "9798c4640bad75c7c3227db910174e72" );
            unhexify( src_str, "a9a1631bf4996954ebc093957b234589" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "96ab5c2ff612d9dfaae8c31f30c42168" );
            unhexify( src_str, "ff4f8391a6a40ca5b25d23bedd44a597" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "ffffffffffffffff0000000000000000" );
            unhexify( src_str, "f807c3e7985fe0f5a50e2cdb25c5109e" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "ffffffffffffffff8000000000000000" );
            unhexify( src_str, "41f992a856fb278b389a62f5d274d7e9" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_128_cfb128_decrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "00000000000000000000000000000000" );
            unhexify( iv_str, "ffffffffffffffffc000000000000000" );
            unhexify( src_str, "10d3ed7a6fe15ab4d91acbc7d0767ab1" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffc0000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "8dfd999be5d0cfa35732c0ddc88ff5a5" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffe0000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "02647c76a300c3173b841487eb2bae9f" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffffffff0000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "172df8b02f04b53adab028b4e01acd87" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "d184c36cf0dddfec39e654195006022237871a47c33d3198" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "2e19fb60a3e1de0166f483c97824a978" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "4c6994ffa9dcdc805b60c2c0095334c42d95a8fc0ca5b080" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "7656709538dd5fec41e0ce6a0f8e207d" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "c88f5b00a4ef9a6840e2acaf33f00a3bdc4e25895303fa72" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "a67cf333b314d411d3c0ae6e1cfcd8f5" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "9c2d8842e5f48f57648205d39a239af1" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "c9b8135ff1b5adc413dfd053b21bd96d" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "bff52510095f518ecca60af4205444bb" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "4a3650c3371ce2eb35e389a171427440" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "51719783d3185a535bd75adc65071ce1" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "4f354592ff7c8847d2d0870ca9481b7c" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "ffffffffffffffe00000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "f34e4a6324ea4a5c39a661c8fe5ada8f" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "fffffffffffffff00000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "0882a16f44088d42447a29ac090ec17e" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_encrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "fffffffffffffff80000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "3a3c15bfc11a9537c130687004e136ee" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffffffffffffffffffffffffffffffffffe00000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "60136703374f64e860b48ce31f930716" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffffffffffffffffff00000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "8d63a269b14d506ccc401ab8a9f1b591" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffffffffffffffffffffffffffffffffffffffff80000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "d317f81dc6aa454aee4bd4a5a5cff4bd" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "98c6b8e01e379fbd14e61af6af891596583565f2a27d59e9" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "19c80ec4a6deb7e5ed1033dda933498f" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "b3ad5cea1dddc214ca969ac35f37dae1a9a9d1528f89bb35" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "3cf5e1d21a17956d1dffad6a7c41c659" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "45899367c3132849763073c435a9288a766c8b9ec2308516" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "69fd12e8505f8ded2fdcb197a121b362" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "1b077a6af4b7f98229de786d7516b639" );
            unhexify( src_str, "275cfc0413d8ccb70513c3859b1d0f72" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "9c2d8842e5f48f57648205d39a239af1" );
            unhexify( src_str, "c9b8135ff1b5adc413dfd053b21bd96d" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "bff52510095f518ecca60af4205444bb" );
            unhexify( src_str, "4a3650c3371ce2eb35e389a171427440" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "ffffffffffffffffffff000000000000" );
            unhexify( src_str, "54d632d03aba0bd0f91877ebdd4d09cb" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "ffffffffffffffffffff800000000000" );
            unhexify( src_str, "d3427be7e4d27cd54f5fe37b03cf0897" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_192_cfb128_decrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "ffffffffffffffffffffc00000000000" );
            unhexify( src_str, "b2099795e88cc158fd75ea133d7e7fbe" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffe000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "bbd1097a62433f79449fa97d4ee80dbf" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffff000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "07058e408f5b99b0e0f061a1761b5b3b" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "fffffff800000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "5fd1f13fa0f31e37fabde328f894eac2" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "13428b5e4c005e0636dd338405d173ab135dec2a25c22c5df0722d69dcc43887" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "649a71545378c783e368c9ade7114f6c" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "07eb03a08d291d1b07408bf3512ab40c91097ac77461aad4bb859647f74f00ee" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "47cb030da2ab051dfc6c4bf6910d12bb" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "90143ae20cd78c5d8ebdd6cb9dc1762427a96c78c639bccc41a61424564eafe1" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "798c7c005dee432b2c8ea5dfa381ecc3" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "0b24af36193ce4665f2825d7b4749c98" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "a9ff75bd7cf6613d3731c77c3b6d0c04" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "761c1fe41a18acf20d241650611d90f1" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "623a52fcea5d443e48d9181ab32c7421" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "8a560769d605868ad80d819bdba03771" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "38f2c7ae10612415d27ca190d27da8b4" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "ffffffffffffffffffffffffe0000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "2be1fae5048a25582a679ca10905eb80" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "fffffffffffffffffffffffff0000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "da86f292c6f41ea34fb2068df75ecc29" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_encrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "fffffffffffffffffffffffff8000000" );
            unhexify( src_str, "00000000000000000000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_ENCRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "220df19f85d69b1b562fa69a3c5beca5" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_1)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffff800000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "be66cfea2fecd6bf0ec7b4352c99bcaa" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_2)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffc00000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "df31144f87a2ef523facdcf21a427804" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_3)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "ffffffffffe00000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "b5bb0f5629fb6aae5e1839a3c3625d63" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_4)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "1d85a181b54cde51f0e098095b2962fdc93b51fe9b88602b3f54130bf76a5bd9" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "531c2c38344578b84d50b3c917bbb6e1" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_5)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "dc0eba1f2232a7879ded34ed8428eeb8769b056bbaf8ad77cb65c3541430b4cf" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "fc6aec906323480005c58e7e1ab004ad" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_6)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "f8be9ba615c5a952cabbca24f68f8593039624d524c816acda2c9183bd917cb9" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            unhexify( src_str, "a3944b95ca0b52043584ef02151926a8" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_7)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "761c1fe41a18acf20d241650611d90f1" );
            unhexify( src_str, "623a52fcea5d443e48d9181ab32c7421" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_8)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "8a560769d605868ad80d819bdba03771" );
            unhexify( src_str, "38f2c7ae10612415d27ca190d27da8b4" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_9)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "91fbef2d15a97816060bee1feaa49afe" );
            unhexify( src_str, "1bc704f1bce135ceb810341b216d7abe" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_10)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "e0000000000000000000000000000000" );
            unhexify( src_str, "9b80eefb7ebe2d2b16247aa0efc72f5d" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_11)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "f0000000000000000000000000000000" );
            unhexify( src_str, "7f2c5ece07a98d8bee13c51177395ff7" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */

#ifdef POLARSSL_CIPHER_MODE_CFB

        FCT_TEST_BGN(aes_256_cfb128_decrypt_nist_kat_12)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            size_t iv_offset = 0;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "f8000000000000000000000000000000" );
            unhexify( src_str, "7818d800dcf6f4be1e0e94f403d1e4c2" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cfb128( &ctx, AES_DECRYPT, 16, &iv_offset, iv_str, src_str, output ) == 0 );
            hexify( dst_str, output, 16 );
        
            fct_chk( strcmp( (char *) dst_str, "00000000000000000000000000000000" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_CIPHER_MODE_CFB */


        FCT_TEST_BGN(aes_ecb_encrypt_invalid_keylength)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000" );
            unhexify( src_str, "f34481ec3cc627bacd5dc3fb08f273e6" );
        
            fct_chk( aes_setkey_enc( &ctx, key_str, key_len * 8 ) == POLARSSL_ERR_AES_INVALID_KEY_LENGTH );
            if( POLARSSL_ERR_AES_INVALID_KEY_LENGTH == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_ENCRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "0336763e966d92595a567cc9ce537f5e" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_ecb_decrypt_invalid_keylength)
        {
            unsigned char key_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len;
        
            memset(key_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "000000000000000000000000000000" );
            unhexify( src_str, "f34481ec3cc627bacd5dc3fb08f273e6" );
        
            fct_chk( aes_setkey_dec( &ctx, key_str, key_len * 8 ) == POLARSSL_ERR_AES_INVALID_KEY_LENGTH );
            if( POLARSSL_ERR_AES_INVALID_KEY_LENGTH == 0 )
            {
                fct_chk( aes_crypt_ecb( &ctx, AES_DECRYPT, src_str, output ) == 0 );
                hexify( dst_str, output, 16 );
        
                fct_chk( strcmp( (char *) dst_str, "0336763e966d92595a567cc9ce537f5e" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_encrypt_invalid_input_length)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "ffffffffffffffe000000000000000" );
        
            aes_setkey_enc( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_ENCRYPT, data_len, iv_str, src_str, output ) == POLARSSL_ERR_AES_INVALID_INPUT_LENGTH );
            if( POLARSSL_ERR_AES_INVALID_INPUT_LENGTH == 0 )
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(aes_256_cbc_decrypt_invalid_input_length)
        {
            unsigned char key_str[100];
            unsigned char iv_str[100];
            unsigned char src_str[100];
            unsigned char dst_str[100];
            unsigned char output[100];
            aes_context ctx;
            int key_len, data_len;
        
            memset(key_str, 0x00, 100);
            memset(iv_str, 0x00, 100);
            memset(src_str, 0x00, 100);
            memset(dst_str, 0x00, 100);
            memset(output, 0x00, 100);
        
            key_len = unhexify( key_str, "0000000000000000000000000000000000000000000000000000000000000000" );
            unhexify( iv_str, "00000000000000000000000000000000" );
            data_len = unhexify( src_str, "623a52fcea5d443e48d9181ab32c74" );
        
            aes_setkey_dec( &ctx, key_str, key_len * 8 );
            fct_chk( aes_crypt_cbc( &ctx, AES_DECRYPT, data_len, iv_str, src_str, output ) == POLARSSL_ERR_AES_INVALID_INPUT_LENGTH );
            if( POLARSSL_ERR_AES_INVALID_INPUT_LENGTH == 0)
            {
                hexify( dst_str, output, data_len );
        
                fct_chk( strcmp( (char *) dst_str, "" ) == 0 );
            }
        }
        FCT_TEST_END();

#ifdef POLARSSL_SELF_TEST

        FCT_TEST_BGN(aes_selftest)
        {
            fct_chk( aes_self_test( 0 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SELF_TEST */

    }
    FCT_SUITE_END();

#endif /* POLARSSL_AES_C */

}
FCT_END();

