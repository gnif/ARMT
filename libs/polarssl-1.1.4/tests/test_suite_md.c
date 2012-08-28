#include "fct.h"

#include <polarssl/md.h>
#include <polarssl/md2.h>
#include <polarssl/md4.h>
#include <polarssl/md5.h>
#include <polarssl/sha1.h>
#include <polarssl/sha2.h>
#include <polarssl/sha4.h>

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
#ifdef POLARSSL_MD_C


    FCT_SUITE_BGN(test_suite_md)
    {
#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(generic_md2_test_vector_rfc1319_1)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "" );
            
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            fct_chk ( 0 == md( md_info, src_str, strlen( (char *) src_str ), output ) );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "8350e5a3e24c153df2275c9f80692773" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(generic_md2_test_vector_rfc1319_2)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "a" );
            
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            fct_chk ( 0 == md( md_info, src_str, strlen( (char *) src_str ), output ) );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "32ec01ec4a6dac72c0ab96fb34c0b5d1" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(generic_md2_test_vector_rfc1319_3)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "abc" );
            
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            fct_chk ( 0 == md( md_info, src_str, strlen( (char *) src_str ), output ) );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "da853b0d3f88d99b30283a69e6ded6bb" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(generic_md2_test_vector_rfc1319_4)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "message digest" );
            
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            fct_chk ( 0 == md( md_info, src_str, strlen( (char *) src_str ), output ) );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "ab4f496bfb2a530b219ff33031fe06b0" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(generic_md2_test_vector_rfc1319_5)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "abcdefghijklmnopqrstuvwxyz" );
            
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            fct_chk ( 0 == md( md_info, src_str, strlen( (char *) src_str ), output ) );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "4e8ddff3650292ab5a4108c3aa47940b" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(generic_md2_test_vector_rfc1319_6)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" );
            
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            fct_chk ( 0 == md( md_info, src_str, strlen( (char *) src_str ), output ) );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "da33def2a42df13975352846c30338cd" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(generic_md2_test_vector_rfc1319_7)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "12345678901234567890123456789012345678901234567890123456789012345678901234567890" );
            
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            fct_chk ( 0 == md( md_info, src_str, strlen( (char *) src_str ), output ) );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "d5976f79d83d3a0dc9806c3c66f3efd8" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(generic_md4_test_vector_rfc1320_1)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "" );
            
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            fct_chk ( 0 == md( md_info, src_str, strlen( (char *) src_str ), output ) );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "31d6cfe0d16ae931b73c59d7e0c089c0" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(generic_md4_test_vector_rfc1320_2)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "a" );
            
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            fct_chk ( 0 == md( md_info, src_str, strlen( (char *) src_str ), output ) );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "bde52cb31de33e46245e05fbdbd6fb24" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(generic_md4_test_vector_rfc1320_3)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "abc" );
            
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            fct_chk ( 0 == md( md_info, src_str, strlen( (char *) src_str ), output ) );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "a448017aaf21d8525fc10ae87aa6729d" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(generic_md4_test_vector_rfc1320_4)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "message digest" );
            
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            fct_chk ( 0 == md( md_info, src_str, strlen( (char *) src_str ), output ) );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "d9130a8164549fe818874806e1c7014b" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(generic_md4_test_vector_rfc1320_5)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "abcdefghijklmnopqrstuvwxyz" );
            
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            fct_chk ( 0 == md( md_info, src_str, strlen( (char *) src_str ), output ) );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "d79e1c308aa5bbcdeea8ed63df412da9" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(generic_md4_test_vector_rfc1320_6)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" );
            
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            fct_chk ( 0 == md( md_info, src_str, strlen( (char *) src_str ), output ) );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "043f8582f241db351ce627e153e7f0e4" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(generic_md4_test_vector_rfc1320_7)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "12345678901234567890123456789012345678901234567890123456789012345678901234567890" );
            
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            fct_chk ( 0 == md( md_info, src_str, strlen( (char *) src_str ), output ) );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "e33b4ddc9c38f2199c3e7b164fcc0536" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_md5_test_vector_rfc1321_1)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "" );
            
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            fct_chk ( 0 == md( md_info, src_str, strlen( (char *) src_str ), output ) );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "d41d8cd98f00b204e9800998ecf8427e" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_md5_test_vector_rfc1321_2)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "a" );
            
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            fct_chk ( 0 == md( md_info, src_str, strlen( (char *) src_str ), output ) );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "0cc175b9c0f1b6a831c399e269772661" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_md5_test_vector_rfc1321_3)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "abc" );
            
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            fct_chk ( 0 == md( md_info, src_str, strlen( (char *) src_str ), output ) );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "900150983cd24fb0d6963f7d28e17f72" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_md5_test_vector_rfc1321_4)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "message digest" );
            
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            fct_chk ( 0 == md( md_info, src_str, strlen( (char *) src_str ), output ) );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "f96b697d7cb7938d525a2f31aaf161d0" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_md5_test_vector_rfc1321_5)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "abcdefghijklmnopqrstuvwxyz" );
            
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            fct_chk ( 0 == md( md_info, src_str, strlen( (char *) src_str ), output ) );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "c3fcd3d76192e4007dfb496cca67e13b" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_md5_test_vector_rfc1321_6)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" );
            
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            fct_chk ( 0 == md( md_info, src_str, strlen( (char *) src_str ), output ) );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "d174ab98d277d9f5a5611c2c9f419d9f" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_md5_test_vector_rfc1321_7)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "12345678901234567890123456789012345678901234567890123456789012345678901234567890" );
            
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            fct_chk ( 0 == md( md_info, src_str, strlen( (char *) src_str ), output ) );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "57edf4a22be3c955ac49da2e2107b67a" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(generic_hmac_md2_hash_file_openssl_test_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "61616161616161616161616161616161" );
            src_len = unhexify( src_str, "b91ce5ac77d33c234e61002ed6" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "d5732582f494f5ddf35efd166c85af9c", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(generic_hmac_md2_hash_file_openssl_test_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "61616161616161616161616161616161" );
            src_len = unhexify( src_str, "270fcf11f27c27448457d7049a7edb084a3e554e0b2acf5806982213f0ad516402e4c869c4ff2171e18e3489baa3125d2c3056ebb616296f9b6aa97ef68eeabcdc0b6dde47775004096a241efcf0a90d19b34e898cc7340cdc940f8bdd46e23e352f34bca131d4d67a7c2ddb8d0d68b67f06152a128168e1c341c37e0a66c5018999b7059bcc300beed2c19dd1152d2fe062853293b8f3c8b5" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "54ab68503f7d1b5c7741340dff2722a9", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(generic_hmac_md2_hash_file_openssl_test_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161" );
            src_len = unhexify( src_str, "b91ce5ac77d33c234e61002ed6" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "d850e5f554558cf0fe79a0612e1d0365", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(generic_hmac_md4_hash_file_openssl_test_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "61616161616161616161616161616161" );
            src_len = unhexify( src_str, "b91ce5ac77d33c234e61002ed6" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "eabd0fbefb82fb0063a25a6d7b8bdc0f", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(generic_hmac_md4_hash_file_openssl_test_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "61616161616161616161616161616161" );
            src_len = unhexify( src_str, "270fcf11f27c27448457d7049a7edb084a3e554e0b2acf5806982213f0ad516402e4c869c4ff2171e18e3489baa3125d2c3056ebb616296f9b6aa97ef68eeabcdc0b6dde47775004096a241efcf0a90d19b34e898cc7340cdc940f8bdd46e23e352f34bca131d4d67a7c2ddb8d0d68b67f06152a128168e1c341c37e0a66c5018999b7059bcc300beed2c19dd1152d2fe062853293b8f3c8b5" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "cec3c5e421a7b783aa89cacf78daf6dc", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(generic_hmac_md4_hash_file_openssl_test_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161" );
            src_len = unhexify( src_str, "b91ce5ac77d33c234e61002ed6" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "ad5f0a04116109b397b57f9cc9b6df4b", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_hmac_md5_hash_file_openssl_test_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "61616161616161616161616161616161" );
            src_len = unhexify( src_str, "b91ce5ac77d33c234e61002ed6" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "42552882f00bd4633ea81135a184b284", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_hmac_md5_hash_file_openssl_test_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "61616161616161616161616161616161" );
            src_len = unhexify( src_str, "270fcf11f27c27448457d7049a7edb084a3e554e0b2acf5806982213f0ad516402e4c869c4ff2171e18e3489baa3125d2c3056ebb616296f9b6aa97ef68eeabcdc0b6dde47775004096a241efcf0a90d19b34e898cc7340cdc940f8bdd46e23e352f34bca131d4d67a7c2ddb8d0d68b67f06152a128168e1c341c37e0a66c5018999b7059bcc300beed2c19dd1152d2fe062853293b8f3c8b5" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "a16a842891786d01fe50ba7731db7464", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_hmac_md5_hash_file_openssl_test_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161" );
            src_len = unhexify( src_str, "b91ce5ac77d33c234e61002ed6" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "e97f623936f98a7f741c4bd0612fecc2", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_hmac_md5_test_vector_rfc2202_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" );
            src_len = unhexify( src_str, "4869205468657265" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "9294727a3638bb1c13f48ef8158bfc9d", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_hmac_md5_test_vector_rfc2202_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "4a656665" );
            src_len = unhexify( src_str, "7768617420646f2079612077616e7420666f72206e6f7468696e673f" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "750c783e6ab0b503eaa86e310a5db738", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_hmac_md5_test_vector_rfc2202_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" );
            src_len = unhexify( src_str, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "56be34521d144c88dbb8c733f0e8b3f6", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_hmac_md5_test_vector_rfc2202_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "0102030405060708090a0b0c0d0e0f10111213141516171819" );
            src_len = unhexify( src_str, "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "697eaf0aca3a3aea3a75164746ffaa79", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_hmac_md5_test_vector_rfc2202_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c" );
            src_len = unhexify( src_str, "546573742057697468205472756e636174696f6e" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "56461ef2342edc00f9bab995", 12 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_hmac_md5_test_vector_rfc2202_6)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" );
            src_len = unhexify( src_str, "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_hmac_md5_test_vector_rfc2202_7)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" );
            src_len = unhexify( src_str, "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "6f630fad67cda0ee1fb1f562db3aa53e", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD_C
#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(generic_multi_step_md2_test_vector_rfc1319_1)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "" );
            
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, strlen( (char *) src_str ) ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "8350e5a3e24c153df2275c9f80692773" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD_C */
#endif /* POLARSSL_MD2_C */

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(generic_multi_step_md2_test_vector_rfc1319_2)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "a" );
            
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, strlen( (char *) src_str ) ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "32ec01ec4a6dac72c0ab96fb34c0b5d1" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(generic_multi_step_md2_test_vector_rfc1319_3)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "abc" );
            
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, strlen( (char *) src_str ) ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "da853b0d3f88d99b30283a69e6ded6bb" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(generic_multi_step_md2_test_vector_rfc1319_4)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "message digest" );
            
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, strlen( (char *) src_str ) ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "ab4f496bfb2a530b219ff33031fe06b0" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(generic_multi_step_md2_test_vector_rfc1319_5)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "abcdefghijklmnopqrstuvwxyz" );
            
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, strlen( (char *) src_str ) ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "4e8ddff3650292ab5a4108c3aa47940b" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(generic_multi_step_md2_test_vector_rfc1319_6)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" );
            
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, strlen( (char *) src_str ) ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "da33def2a42df13975352846c30338cd" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(generic_multi_step_md2_test_vector_rfc1319_7)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "12345678901234567890123456789012345678901234567890123456789012345678901234567890" );
            
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, strlen( (char *) src_str ) ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "d5976f79d83d3a0dc9806c3c66f3efd8" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(generic_multi_step_md4_test_vector_rfc1320_1)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "" );
            
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, strlen( (char *) src_str ) ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "31d6cfe0d16ae931b73c59d7e0c089c0" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(generic_multi_step_md4_test_vector_rfc1320_2)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "a" );
            
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, strlen( (char *) src_str ) ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "bde52cb31de33e46245e05fbdbd6fb24" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(generic_multi_step_md4_test_vector_rfc1320_3)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "abc" );
            
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, strlen( (char *) src_str ) ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "a448017aaf21d8525fc10ae87aa6729d" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(generic_multi_step_md4_test_vector_rfc1320_4)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "message digest" );
            
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, strlen( (char *) src_str ) ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "d9130a8164549fe818874806e1c7014b" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(generic_multi_step_md4_test_vector_rfc1320_5)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "abcdefghijklmnopqrstuvwxyz" );
            
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, strlen( (char *) src_str ) ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "d79e1c308aa5bbcdeea8ed63df412da9" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(generic_multi_step_md4_test_vector_rfc1320_6)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" );
            
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, strlen( (char *) src_str ) ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "043f8582f241db351ce627e153e7f0e4" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(generic_multi_step_md4_test_vector_rfc1320_7)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "12345678901234567890123456789012345678901234567890123456789012345678901234567890" );
            
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, strlen( (char *) src_str ) ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "e33b4ddc9c38f2199c3e7b164fcc0536" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_multi_step_md5_test_vector_rfc1321_1)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "" );
            
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, strlen( (char *) src_str ) ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "d41d8cd98f00b204e9800998ecf8427e" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_multi_step_md5_test_vector_rfc1321_2)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "a" );
            
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, strlen( (char *) src_str ) ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "0cc175b9c0f1b6a831c399e269772661" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_multi_step_md5_test_vector_rfc1321_3)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "abc" );
            
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, strlen( (char *) src_str ) ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "900150983cd24fb0d6963f7d28e17f72" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_multi_step_md5_test_vector_rfc1321_4)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "message digest" );
            
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, strlen( (char *) src_str ) ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "f96b697d7cb7938d525a2f31aaf161d0" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_multi_step_md5_test_vector_rfc1321_5)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "abcdefghijklmnopqrstuvwxyz" );
            
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, strlen( (char *) src_str ) ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "c3fcd3d76192e4007dfb496cca67e13b" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_multi_step_md5_test_vector_rfc1321_6)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" );
            
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, strlen( (char *) src_str ) ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "d174ab98d277d9f5a5611c2c9f419d9f" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_multi_step_md5_test_vector_rfc1321_7)
        {
            char md_name[100];
            unsigned char src_str[1000];
            unsigned char hash_str[1000];
            unsigned char output[100];
            
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 1000);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strcpy( (char *) src_str, "12345678901234567890123456789012345678901234567890123456789012345678901234567890" );
            
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, strlen( (char *) src_str ) ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "57edf4a22be3c955ac49da2e2107b67a" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(generic_multi_step_hmac_md2_hash_file_openssl_test_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "61616161616161616161616161616161" );
            src_len = unhexify( src_str, "b91ce5ac77d33c234e61002ed6" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "d5732582f494f5ddf35efd166c85af9c", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(generic_multi_step_hmac_md2_hash_file_openssl_test_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "61616161616161616161616161616161" );
            src_len = unhexify( src_str, "270fcf11f27c27448457d7049a7edb084a3e554e0b2acf5806982213f0ad516402e4c869c4ff2171e18e3489baa3125d2c3056ebb616296f9b6aa97ef68eeabcdc0b6dde47775004096a241efcf0a90d19b34e898cc7340cdc940f8bdd46e23e352f34bca131d4d67a7c2ddb8d0d68b67f06152a128168e1c341c37e0a66c5018999b7059bcc300beed2c19dd1152d2fe062853293b8f3c8b5" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "54ab68503f7d1b5c7741340dff2722a9", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */

#ifdef POLARSSL_MD2_C

        FCT_TEST_BGN(generic_multi_step_hmac_md2_hash_file_openssl_test_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161" );
            src_len = unhexify( src_str, "b91ce5ac77d33c234e61002ed6" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "d850e5f554558cf0fe79a0612e1d0365", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(generic_multi_step_hmac_md4_hash_file_openssl_test_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "61616161616161616161616161616161" );
            src_len = unhexify( src_str, "b91ce5ac77d33c234e61002ed6" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "eabd0fbefb82fb0063a25a6d7b8bdc0f", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(generic_multi_step_hmac_md4_hash_file_openssl_test_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "61616161616161616161616161616161" );
            src_len = unhexify( src_str, "270fcf11f27c27448457d7049a7edb084a3e554e0b2acf5806982213f0ad516402e4c869c4ff2171e18e3489baa3125d2c3056ebb616296f9b6aa97ef68eeabcdc0b6dde47775004096a241efcf0a90d19b34e898cc7340cdc940f8bdd46e23e352f34bca131d4d67a7c2ddb8d0d68b67f06152a128168e1c341c37e0a66c5018999b7059bcc300beed2c19dd1152d2fe062853293b8f3c8b5" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "cec3c5e421a7b783aa89cacf78daf6dc", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD4_C

        FCT_TEST_BGN(generic_multi_step_hmac_md4_hash_file_openssl_test_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161" );
            src_len = unhexify( src_str, "b91ce5ac77d33c234e61002ed6" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "ad5f0a04116109b397b57f9cc9b6df4b", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_multi_step_hmac_md5_hash_file_openssl_test_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "61616161616161616161616161616161" );
            src_len = unhexify( src_str, "b91ce5ac77d33c234e61002ed6" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "42552882f00bd4633ea81135a184b284", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_multi_step_hmac_md5_hash_file_openssl_test_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "61616161616161616161616161616161" );
            src_len = unhexify( src_str, "270fcf11f27c27448457d7049a7edb084a3e554e0b2acf5806982213f0ad516402e4c869c4ff2171e18e3489baa3125d2c3056ebb616296f9b6aa97ef68eeabcdc0b6dde47775004096a241efcf0a90d19b34e898cc7340cdc940f8bdd46e23e352f34bca131d4d67a7c2ddb8d0d68b67f06152a128168e1c341c37e0a66c5018999b7059bcc300beed2c19dd1152d2fe062853293b8f3c8b5" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "a16a842891786d01fe50ba7731db7464", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_multi_step_hmac_md5_hash_file_openssl_test_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161" );
            src_len = unhexify( src_str, "b91ce5ac77d33c234e61002ed6" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "e97f623936f98a7f741c4bd0612fecc2", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_multi_step_hmac_md5_test_vector_rfc2202_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" );
            src_len = unhexify( src_str, "4869205468657265" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "9294727a3638bb1c13f48ef8158bfc9d", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_multi_step_hmac_md5_test_vector_rfc2202_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "4a656665" );
            src_len = unhexify( src_str, "7768617420646f2079612077616e7420666f72206e6f7468696e673f" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "750c783e6ab0b503eaa86e310a5db738", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_multi_step_hmac_md5_test_vector_rfc2202_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" );
            src_len = unhexify( src_str, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "56be34521d144c88dbb8c733f0e8b3f6", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_multi_step_hmac_md5_test_vector_rfc2202_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "0102030405060708090a0b0c0d0e0f10111213141516171819" );
            src_len = unhexify( src_str, "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "697eaf0aca3a3aea3a75164746ffaa79", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_multi_step_hmac_md5_test_vector_rfc2202_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c" );
            src_len = unhexify( src_str, "546573742057697468205472756e636174696f6e" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "56461ef2342edc00f9bab995", 12 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_multi_step_hmac_md5_test_vector_rfc2202_6)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" );
            src_len = unhexify( src_str, "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD5_C

        FCT_TEST_BGN(generic_multi_step_hmac_md5_test_vector_rfc2202_7)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" );
            src_len = unhexify( src_str, "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "6f630fad67cda0ee1fb1f562db3aa53e", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */

#ifdef POLARSSL_MD2_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_md2_hash_file_1)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_1", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "b593c098712d2e21628c8986695451a8" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD2_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_md2_hash_file_2)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_2", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "3c027b7409909a4c4b26bbab69ad9f4f" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD2_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_md2_hash_file_3)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_3", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "6bb43eb285e81f414083a94cdbe2989d" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD2_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_md2_hash_file_4)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md2", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_4", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "8350e5a3e24c153df2275c9f80692773" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD2_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD4_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_md4_hash_file_1)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_1", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "8d19772c176bd27153b9486715e2c0b9" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD4_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_md4_hash_file_2)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_2", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "f2ac53b8542882a5a0007c6f84b4d9fd" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD4_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_md4_hash_file_3)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_3", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "195c15158e2d07881d9a654095ce4a42" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD4_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_md4_hash_file_4)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md4", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_4", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "31d6cfe0d16ae931b73c59d7e0c089c0" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD4_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD5_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_md5_hash_file_1)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_1", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "52bcdc983c9ed64fc148a759b3c7a415" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD5_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_md5_hash_file_2)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_2", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "d17d466f15891df10542207ae78277f0" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD5_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_md5_hash_file_3)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_3", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "d945bcc6200ea95d061a2a818167d920" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_MD5_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_md5_hash_file_4)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "md5", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_4", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "d41d8cd98f00b204e9800998ecf8427e" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_MD5_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_hmac_sha_1_test_vector_fips_198a_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" );
            src_len = unhexify( src_str, "53616d706c65202331" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "4f4ca3d5d68ba7cc0a1208c9c61e9c5da0403c0a", 20 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_hmac_sha_1_test_vector_fips_198a_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "303132333435363738393a3b3c3d3e3f40414243" );
            src_len = unhexify( src_str, "53616d706c65202332" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "0922d3405faa3d194f82a45830737d5cc6c75d24", 20 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_hmac_sha_1_test_vector_fips_198a_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3" );
            src_len = unhexify( src_str, "53616d706c65202333" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "bcf41eab8bb2d802f3d05caf7cb092ecf8d1a3aa", 20 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_hmac_sha_1_test_vector_fips_198a_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0" );
            src_len = unhexify( src_str, "53616d706c65202334" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "9ea886efe268dbecce420c75", 12 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_hmac_sha_1_test_vector_nist_cavs_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "7b10f4124b15c82e" );
            src_len = unhexify( src_str, "27dcb5b1daf60cfd3e2f73d4d64ca9c684f8bf71fc682a46793b1790afa4feb100ca7aaff26f58f0e1d0ed42f1cdad1f474afa2e79d53a0c42892c4d7b327cbe46b295ed8da3b6ecab3d4851687a6f812b79df2f6b20f11f6706f5301790ca99625aad7391d84f78043d2a0a239b1477984c157bbc9276064e7a1a406b0612ca" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "4ead12c2fe3d6ea43acb", 10 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_hmac_sha_1_test_vector_nist_cavs_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "4fe9fb902172a21b" );
            src_len = unhexify( src_str, "4ceb3a7c13659c22fe51134f03dce4c239d181b63c6b0b59d367157fd05cab98384f92dfa482d2d5e78e72eef1b1838af4696026c54233d484ecbbe87f904df5546419f8567eafd232e6c2fcd3ee2b7682c63000524b078dbb2096f585007deae752562df1fe3b01278089e16f3be46e2d0f7cabac2d8e6cc02a2d0ca953425f" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "564428a67be1924b5793", 10 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_hmac_sha_1_test_vector_nist_cavs_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "d1f01455f78c4fb4" );
            src_len = unhexify( src_str, "00d40f67b57914bec456a3e3201ef1464be319a8d188c02e157af4b54f9b5a66d67f898a9bdbb19ff63a80aba6f246d013575721d52eb1b47a65def884011c49b257bcc2817fc853f106e8138ce386d7a5ac3103de0a3fa0ed6bb7af9ff66ebd1cc46fb86e4da0013d20a3c2dcd8fb828a4b70f7f104b41bf3f44682a66497ea" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "56a665a7cdfe610f9fc5", 10 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_hmac_sha_1_test_vector_nist_cavs_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "4e5ef77fdf033a5b" );
            src_len = unhexify( src_str, "e59326464e3201d195e29f2a3446ec1b1c9ff31154e2a4d0e40ed466f1bc855d29f76835624fa0127d29c9b1915939a046f385af7e5d47a23ba91f28bd22f811ea258dbbf3332bcd3543b8285d5df41bd064ffd64a341c22c4edb44f9c8d9e6df0c59dbf4a052a6c83da7478e179a6f3839c6870ff8ca8b9497f9ac1d725fdda" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "981c0a7a8423b63a8fa6", 10 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_hmac_sha_1_test_vector_nist_cavs_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "bcd9ff8aa60be2be" );
            src_len = unhexify( src_str, "51be4d0eb37bab714f92e19e9d70390655b363e8cd346a748245e731f437759cb8206412c8dab2ef1d4f36f880f41ff69d949da4594fdecb65e23cac1329b59e69e29bf875b38c31df6fa546c595f35cc2192aa750679a8a51a65e00e839d73a8d8c598a610d237fbe78955213589d80efcb73b95b8586f96d17b6f51a71c3b8" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "84633f9f5040c8971478", 10 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_hmac_sha_1_test_vector_nist_cavs_6)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "4a661bce6ed86d21" );
            src_len = unhexify( src_str, "5ff6c744f1aab1bc29697d71f67541b8b3cec3c7079183b10a83fb98a9ee251d4bac3e1cb581ca972aaed8efd7c2875a6fb4c991132f67c9742d45e53bc7e8eaa94b35b37a907be61086b426cd11088ac118934e85d968c9667fd69fc6f6ea38c0fe34710b7ece91211b9b7ea00acd31f022aa6726368f9928a1352f122233f1" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "739df59353ac6694e55e", 10 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_hmac_sha_1_test_vector_nist_cavs_7)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "1287e1565a57b547" );
            src_len = unhexify( src_str, "390ffdccc6171c11568d85b8f913e019bf4cd982ca9cd21ea730d41bdf3fcc0bc88ff48ba13a8f23deb2d96ec1033e7b2a58ca72b0c1e17bf03330db25d1e360fa6918009c4294bd1215b5ccd159a8f58bc3dc3d490eb7c3b9f887e8c98dbbb274a75373dcb695a59abd0219529d88518a96f92abc0bbcbda985c388f1fbbcc9" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "d78ddf08077c7d9e2ba6", 10 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_hmac_sha_224_test_vector_nist_cavs_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "e055eb756697ee573fd3214811a9f7fa" );
            src_len = unhexify( src_str, "3875847012ee42fe54a0027bdf38cca7021b83a2ed0503af69ef6c37c637bc1114fba40096c5947d736e19b7af3c68d95a4e3b8b073adbbb80f47e9db8f2d4f0018ddd847fabfdf9dd9b52c93e40458977725f6b7ba15f0816bb895cdf50401268f5d702b7e6a5f9faef57b8768c8a3fc14f9a4b3182b41d940e337d219b29ff" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "40a453133361cc48da11baf616ee", 14 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_hmac_sha_224_test_vector_nist_cavs_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "88e5258b55b1623385eb9632fa7c57d6" );
            src_len = unhexify( src_str, "ada76bb604be14326551701cf30e48a65eee80b44f0b9d4a07b1844543b7844a621097fdc99de57387458ae9354899b620d0617eabcaefa9eef3d413a33628054335ce656c26fa2986e0f111a6351096b283101ec7868871d770b370973c7405983f9756b3005a3eab492cfd0e7eb42e5c2e15fa6be8718c0a50acc4e5717230" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "81c783af538015cef3c60095df53", 14 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_hmac_sha_224_test_vector_nist_cavs_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "85d402d822114d31abf75526e2538705" );
            src_len = unhexify( src_str, "8020d8d98cc2e2298b32879c51c751e1dd5558fe2eabb8f158604297d6d072ce2261a1d6830b7cfe2617b57c7126f99c9476211d6161acd75d266da217ec8174b80484c9dc6f0448a0a036a3fc82e8bf54bdb71549368258d5d41f57978a4c266b92e8783ef66350215573d99be4089144b383ad8f3222bae8f3bf80ffb1bb2b" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "2aa0340ac9deafe3be38129daca0", 14 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_hmac_sha_224_test_vector_nist_cavs_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "545c6eecc5ee46fa17c59f91a94f81ae" );
            src_len = unhexify( src_str, "8fb7f3565593170152ddb2021874784e951977cfdd22f8b72a72a61320a8f2a35697b5e913f717805559b1af1861ee3ed42fb788481e4fd276b17bdbefcae7b4501dc5d20de5b7626dd5efdcd65294db4bdf682c33d9a9255c6435383fa5f1c886326a3acbc6bd50a33ab5b2dbb034ce0112d4e226bbcd57e3731a519aa1d784" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "3eb566eac54c4a3a9ef092469f24", 14 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_hmac_sha_224_test_vector_nist_cavs_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "4466ab4dc438841a9750c7f173dff02e" );
            src_len = unhexify( src_str, "2534c11c78c99cffaec8f722f04adc7045c7324d58ce98e37cfa94b6ed21ed7f58ce55379ef24b72d6d640ee9154f96c614734be9c408e225d7ba4cecc1179cc9f6e1808e1067aa8f244a99bd0c3267594c1887a40d167f8b7cf78db0d19f97b01fc50b8c86def490dfa7a5135002c33e71d77a8cce8ea0f93e0580439a33733" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "59f44a9bbed4875b892d22d6b5ab", 14 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_hmac_sha_224_test_vector_nist_cavs_6)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "0e3dd9bb5e4cf0f09a4c11600af56d8d" );
            src_len = unhexify( src_str, "f4589fa76c328ea25cf8bae582026ba40a59d45a546ff31cf80eb826088f69bb954c452c74586836416dee90a5255bc5d56d3b405b3705a5197045688b32fa984c3a3dfbdc9c2460a0b5e6312a624048bb6f170306535e9b371a3ab134a2642a230ad03d2c688cca80baeaee9a20e1d4c548b1cede29c6a45bf4df2c8c476f1a" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "12175b93e3da4c58217145e4dc0a1cf142fab9319bb501e037b350ba", 28 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_hmac_sha_224_test_vector_nist_cavs_7)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "cda5187b0c5dcb0f8e5a8beed2306584" );
            src_len = unhexify( src_str, "9011ae29b44c49b347487ce972965f16ade3c15be0856ce9c853a9739dba07e4f20d594ddc1dfe21560a65a4e458cfa17745575b915a30c7a9412ff8d1d689db9680dd2428c27588bb0dc92d2cd9445fe8f44b840a197c52c3c4333fff45533945134398df6436513cfab06c924046b8c795a5bd92e8d5f2de85bf306f2eed67" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "4aaba92b40e2a600feab176eb9b292d814864195c03342aad6f67f08", 28 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_hmac_sha_256_test_vector_nist_cavs_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "cdffd34e6b16fdc0" );
            src_len = unhexify( src_str, "d83e78b99ab61709608972b36e76a575603db742269cc5dd4e7d5ca7816e26b65151c92632550cb4c5253c885d5fce53bc47459a1dbd5652786c4aac0145a532f12c05138af04cbb558101a7af5df478834c2146594dd73690d01a4fe72545894335f427ac70204798068cb86c5a600b40b414ede23590b41e1192373df84fe3" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "c6f0dde266cb4a26d41e8259d33499cc", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_hmac_sha_256_test_vector_nist_cavs_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "6d97bb5892245be2" );
            src_len = unhexify( src_str, "13c2b391d59c0252ca5d2302beaaf88c4bcd779bb505ad9a122003dfae4cc123ad2bd036f225c4f040021a6b9fb8bd6f0281cf2e2631a732bdc71693cc42ef6d52b6c6912a9ef77b3274eb85ad7f965ae6ed44ac1721962a884ec7acfb4534b1488b1c0c45afa4dae8da1eb7b0a88a3240365d7e4e7d826abbde9f9203fd99d7" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "31588e241b015319a5ab8c4527296498", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_hmac_sha_256_test_vector_nist_cavs_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "3c7fc8a70b49007a" );
            src_len = unhexify( src_str, "60024e428a39c8b8bb2e9591bad9dc2115dfbfd716b6eb7af30a6eb34560caccbbfa47b710fa8d523aca71e9e5ba10fc1feb1a43556d71f07ea4f33496f093044e8caf1d02b79e46eb1288d5964a7a7494f6b92574c35784eece054c6151281d80822f7d47b8231c35d07f5cb5cf4310ddc844845a01c6bfab514c048eccaf9f" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "1c98c94a32bec9f253c21070f82f8438", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_hmac_sha_256_test_vector_nist_cavs_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "369f33f85b927a07" );
            src_len = unhexify( src_str, "ae8e2a94ca386d448cbacdb0e9040ae3cb297c296363052cc157455da29a0c95897315fc11e3f12b81e2418da1ec280bccbc00e847584ce9d14deeba7b3c9b8dba958b04bba37551f6c9ba9c060be1a4b8cf43aa62e5078b76c6512c5619b71a6a7cf5727180e1ff14f5a1a3c1691bf8b6ebad365c151e58d749d57adb3a4986" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "60b90383286533d309de46593e6ce39fc51fb00a8d88278c", 24 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_hmac_sha_256_test_vector_nist_cavs_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "e5179687582b4dc4" );
            src_len = unhexify( src_str, "ce103bdacdf32f614f6727bcb31ca1c2824a850d00f5585b016fb234fe1ef2cd687f302d3c6b738ed89a24060d65c36675d0d96307c72ef3e8a83bfa8402e226de9d5d1724ba75c4879bf41a4a465ce61887d9f49a34757849b48bae81c27ebed76faae2ad669bca04747d409148d40812776e0ae2c395b3cb9c89981ce72d5c" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "509581f6816df4b8cc9f2cf42b7cc6e6a5a1e375a16f2412", 24 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_hmac_sha_256_test_vector_nist_cavs_6)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "63cec6246aeb1b61" );
            src_len = unhexify( src_str, "c178db908a405fa88aa255b8cad22b4057016585f139ee930388b083d86062fa0b3ea1f23f8a43bd11bee8464bcbd19b5ab9f6a8038d5245516f8274d20c8ee3033a07b908da528fa00343bb595deed500cab9745c4cb6391c23300f0d3584b090b3326c4cfa342620b78f9f5b4f27f7307ed770643ec1764aeae3dcf1a3ec69" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "64f3dd861b7c7d29fce9ae0ce9ed954b5d7141806ee9eec7", 24 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_hmac_sha_384_test_vector_nist_cavs_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "91a7401817386948ca952f9a20ee55dc" );
            src_len = unhexify( src_str, "2fea5b91035d6d501f3a834fa178bff4e64b99a8450432dafd32e4466b0e1e7781166f8a73f7e036b3b0870920f559f47bd1400a1a906e85e0dcf00a6c26862e9148b23806680f285f1fe4f93cdaf924c181a965465739c14f2268c8be8b471847c74b222577a1310bcdc1a85ef1468aa1a3fd4031213c97324b7509c9050a3d" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "6d7be9490058cf413cc09fd043c224c2ec4fa7859b13783000a9a593c9f75838", 32 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_hmac_sha_384_test_vector_nist_cavs_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "d6cac19657061aa90a6da11cd2e9ea47" );
            src_len = unhexify( src_str, "9f482e4655173135dfaa22a11bbbe6af263db48716406c5aec162ba3c4b41cad4f5a91558377521191c7343118beee65982929802913d67b6de5c4bdc3d27299bd722219d5ad2efa5bdb9ff7b229fc4bbc3f60719320cf2e7a51cad1133d21bad2d80919b1836ef825308b7c51c6b7677ac782e2bc30007afba065681cbdd215" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "f3d5f3c008175321aa7b2ea379eaa4f8b9dcc60f895ec8940b8162f80a7dfe9f", 32 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_hmac_sha_384_test_vector_nist_cavs_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "e06366ad149b8442cd4c1abdddd0afde" );
            src_len = unhexify( src_str, "2d140a194c02a5598f69174834679b8371234a0d505491f1bd03e128dd91a8bca2fb812e9d5da71613b5b00952ea78bf450d5b7547dea79135925085c7d3e6f52009c51ca3d88c6c09e9d074b0ee110736e0ec9b478b93efb34d7bf1c41b54decec43eab077a3aa4998ede53f67b4ea36c266745f9643d5360bdc8337c70dabf" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "c19c67eda6fe29f3667bee1c897c333ce7683094ae77e84b4c16378d290895a1", 32 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_hmac_sha_384_test_vector_nist_cavs_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "01ac59f42f8bb91d1bd10fe6990d7a87" );
            src_len = unhexify( src_str, "3caf18c476edd5615f343ac7b7d3a9da9efade755672d5ba4b8ae8a7505539ea2c124ff755ec0457fbe49e43480b3c71e7f4742ec3693aad115d039f90222b030fdc9440313691716d5302005808c07627483b916fdf61983063c2eb1268f2deeef42fc790334456bc6bad256e31fc9066de7cc7e43d1321b1866db45e905622" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "1985fa2163a5943fc5d92f1fe8831215e7e91f0bff5332bc713a072bdb3a8f9e5c5157463a3bfeb36231416e65973e64", 48 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_hmac_sha_384_test_vector_nist_cavs_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "fd74b9d9e102a3a80df1baf0cb35bace" );
            src_len = unhexify( src_str, "1a068917584813d1689ccbd0370c2114d537cdc8cc52bf6db16d5535f8f7d1ad0c850a9fa0cf62373ffbf7642b1f1e8164010d350721d798d9f99e9724830399c2fce26377e83d38845675457865c03d4a07d741a505ef028343eb29fd46d0f761f3792886998c1e5c32ac3bc7e6f08faed194b34f06eff4d5d4a5b42c481e0e" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "a981eaf5de3d78b20ebd4414a4edd0657e3667cd808a0dbc430cf7252f73a5b24efa136039207bd59806897457d74e0c", 48 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_hmac_sha_384_test_vector_nist_cavs_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "9fe794f0e26b669fa5f6883149377c6c" );
            src_len = unhexify( src_str, "6010c9745e8f1d44cfdc99e7e0fd79bc4271944c2d1d84dba589073dfc4ca5eb98c59356f60cd87bef28aeb83a832bde339b2087daf942aa1f67876c5d5ed33924bed4143bc12a2be532ccaf64daa7e2bc3c8872b9823b0533b6f5159135effe8c61545536975d7c3a61ba7365ec35f165bc92b4d19eb9156ade17dfa1bb4161" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "915ae61f8754698c2b6ef9629e93441f8541bd4258a5e05372d19136cfaefc0473b48d96119291b38eb1a3cb1982a986", 48 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_hmac_sha_512_test_vector_nist_cavs_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "c95a17c09940a691ed2d621571b0eb844ede55a9" );
            src_len = unhexify( src_str, "99cd28262e81f34878cdcebf4128e05e2098a7009278a66f4c785784d0e5678f3f2b22f86e982d273b6273a222ec61750b4556d766f1550a7aedfe83faedbc4bdae83fa560d62df17eb914d05fdaa48940551bac81d700f5fca7147295e386e8120d66742ec65c6ee8d89a92217a0f6266d0ddc60bb20ef679ae8299c8502c2f" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "6bc1379d156559ddee2ed420ea5d5c5ff3e454a1059b7ba72c350e77b6e9333c", 32 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_hmac_sha_512_test_vector_nist_cavs_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "3b10b8fa718840d1dea8e9fc317476bcf55875fd" );
            src_len = unhexify( src_str, "f04f5b7073d7d0274e8354433b390306c5607632f5f589c12edb62d55673aff2366d2e6b24de731adf92e654baa30b1cfd4a069788f65ec1b99b015d904d8832110dbd74eae35a81562d14ce4136d820ad0a55ff5489ba678fbbc1c27663ec1349d70e740f0e0ec27cfbe8971819f4789e486b50a2d7271d77e2aaea50de62fd" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "fc3c38c7a17e3ce06db033f1c172866f01a00045db55f2e234f71c82264f2ba2", 32 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_hmac_sha_512_test_vector_nist_cavs_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "4803d311394600dc1e0d8fc8cedeb8bde3fe7c42" );
            src_len = unhexify( src_str, "a10c125dd702a97153ad923ba5e9889cfac1ba169de370debe51f233735aa6effcc9785c4b5c7e48c477dc5c411ae6a959118584e26adc94b42c2b29b046f3cf01c65b24a24bd2e620bdf650a23bb4a72655b1100d7ce9a4dab697c6379754b4396c825de4b9eb73f2e6a6c0d0353bbdeaf706612800e137b858fdb30f3311c6" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "7cd8236c55102e6385f52279506df6fcc388ab75092da21395ce14a82b202ffa", 32 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_hmac_sha_512_test_vector_nist_cavs_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "aeb2f3b977fa6c8e71e07c5a5c74ff58166de092" );
            src_len = unhexify( src_str, "22457355dc76095abd46846b41cfe49a06ce42ac8857b4702fc771508dfb3626e0bfe851df897a07b36811ec433766e4b4166c26301b3493e7440d4554b0ef6ac20f1a530e58fac8aeba4e9ff2d4898d8a28783b49cd269c2965fd7f8e4f2d60cf1e5284f2495145b72382aad90e153a90ecae125ad75336fb128825c23fb8b0" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "fa39bd8fcc3bfa218f9dea5d3b2ce10a7619e31678a56d8a9d927b1fe703b125af445debe9a89a07db6194d27b44d85a", 48 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_hmac_sha_512_test_vector_nist_cavs_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "4285d3d7744da52775bb44ca436a3154f7980309" );
            src_len = unhexify( src_str, "208f0b6f2de2e5aa5df11927ddc6df485edc1193181c484d0f0a434a95418803101d4de9fdb798f93516a6916fa38a8207de1666fe50fe3441c03b112eaaae6954ed063f7ac4e3c1e3f73b20d153fe9e4857f5e91430f0a70ee820529adac2467469fd18adf10e2af0fea27c0abc83c5a9af77c364a466cffce8bab4e2b70bc1" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "fe7603f205b2774fe0f14ecfa3e338e90608a806d11ca459dff5ce36b1b264ecd3af5f0492a7521d8da3102ba20927a5", 48 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_hmac_sha_512_test_vector_nist_cavs_6)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            key_len = unhexify( key_str, "8ab783d5acf32efa0d9c0a21abce955e96630d89" );
            src_len = unhexify( src_str, "17371e013dce839963d54418e97be4bd9fa3cb2a368a5220f5aa1b8aaddfa3bdefc91afe7c717244fd2fb640f5cb9d9bf3e25f7f0c8bc758883b89dcdce6d749d9672fed222277ece3e84b3ec01b96f70c125fcb3cbee6d19b8ef0873f915f173bdb05d81629ba187cc8ac1934b2f75952fb7616ae6bd812946df694bd2763af" );
        
            fct_chk ( md_hmac( md_info, key_str, key_len, src_str, src_len, output ) == 0 );
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "9ac7ca8d1aefc166b046e4cf7602ebe181a0e5055474bff5b342106731da0d7e48e4d87bc0a6f05871574289a1b099f8", 48 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_1_test_vector_fips_198a_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" );
            src_len = unhexify( src_str, "53616d706c65202331" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "4f4ca3d5d68ba7cc0a1208c9c61e9c5da0403c0a", 20 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_1_test_vector_fips_198a_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "303132333435363738393a3b3c3d3e3f40414243" );
            src_len = unhexify( src_str, "53616d706c65202332" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "0922d3405faa3d194f82a45830737d5cc6c75d24", 20 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_1_test_vector_fips_198a_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3" );
            src_len = unhexify( src_str, "53616d706c65202333" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "bcf41eab8bb2d802f3d05caf7cb092ecf8d1a3aa", 20 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_1_test_vector_fips_198a_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0" );
            src_len = unhexify( src_str, "53616d706c65202334" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "9ea886efe268dbecce420c75", 12 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_1_test_vector_nist_cavs_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "7b10f4124b15c82e" );
            src_len = unhexify( src_str, "27dcb5b1daf60cfd3e2f73d4d64ca9c684f8bf71fc682a46793b1790afa4feb100ca7aaff26f58f0e1d0ed42f1cdad1f474afa2e79d53a0c42892c4d7b327cbe46b295ed8da3b6ecab3d4851687a6f812b79df2f6b20f11f6706f5301790ca99625aad7391d84f78043d2a0a239b1477984c157bbc9276064e7a1a406b0612ca" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "4ead12c2fe3d6ea43acb", 10 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_1_test_vector_nist_cavs_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "4fe9fb902172a21b" );
            src_len = unhexify( src_str, "4ceb3a7c13659c22fe51134f03dce4c239d181b63c6b0b59d367157fd05cab98384f92dfa482d2d5e78e72eef1b1838af4696026c54233d484ecbbe87f904df5546419f8567eafd232e6c2fcd3ee2b7682c63000524b078dbb2096f585007deae752562df1fe3b01278089e16f3be46e2d0f7cabac2d8e6cc02a2d0ca953425f" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "564428a67be1924b5793", 10 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_1_test_vector_nist_cavs_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "d1f01455f78c4fb4" );
            src_len = unhexify( src_str, "00d40f67b57914bec456a3e3201ef1464be319a8d188c02e157af4b54f9b5a66d67f898a9bdbb19ff63a80aba6f246d013575721d52eb1b47a65def884011c49b257bcc2817fc853f106e8138ce386d7a5ac3103de0a3fa0ed6bb7af9ff66ebd1cc46fb86e4da0013d20a3c2dcd8fb828a4b70f7f104b41bf3f44682a66497ea" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "56a665a7cdfe610f9fc5", 10 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_1_test_vector_nist_cavs_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "4e5ef77fdf033a5b" );
            src_len = unhexify( src_str, "e59326464e3201d195e29f2a3446ec1b1c9ff31154e2a4d0e40ed466f1bc855d29f76835624fa0127d29c9b1915939a046f385af7e5d47a23ba91f28bd22f811ea258dbbf3332bcd3543b8285d5df41bd064ffd64a341c22c4edb44f9c8d9e6df0c59dbf4a052a6c83da7478e179a6f3839c6870ff8ca8b9497f9ac1d725fdda" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "981c0a7a8423b63a8fa6", 10 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_1_test_vector_nist_cavs_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "bcd9ff8aa60be2be" );
            src_len = unhexify( src_str, "51be4d0eb37bab714f92e19e9d70390655b363e8cd346a748245e731f437759cb8206412c8dab2ef1d4f36f880f41ff69d949da4594fdecb65e23cac1329b59e69e29bf875b38c31df6fa546c595f35cc2192aa750679a8a51a65e00e839d73a8d8c598a610d237fbe78955213589d80efcb73b95b8586f96d17b6f51a71c3b8" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "84633f9f5040c8971478", 10 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_1_test_vector_nist_cavs_6)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "4a661bce6ed86d21" );
            src_len = unhexify( src_str, "5ff6c744f1aab1bc29697d71f67541b8b3cec3c7079183b10a83fb98a9ee251d4bac3e1cb581ca972aaed8efd7c2875a6fb4c991132f67c9742d45e53bc7e8eaa94b35b37a907be61086b426cd11088ac118934e85d968c9667fd69fc6f6ea38c0fe34710b7ece91211b9b7ea00acd31f022aa6726368f9928a1352f122233f1" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "739df59353ac6694e55e", 10 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_1_test_vector_nist_cavs_7)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "1287e1565a57b547" );
            src_len = unhexify( src_str, "390ffdccc6171c11568d85b8f913e019bf4cd982ca9cd21ea730d41bdf3fcc0bc88ff48ba13a8f23deb2d96ec1033e7b2a58ca72b0c1e17bf03330db25d1e360fa6918009c4294bd1215b5ccd159a8f58bc3dc3d490eb7c3b9f887e8c98dbbb274a75373dcb695a59abd0219529d88518a96f92abc0bbcbda985c388f1fbbcc9" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "d78ddf08077c7d9e2ba6", 10 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_224_test_vector_nist_cavs_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "e055eb756697ee573fd3214811a9f7fa" );
            src_len = unhexify( src_str, "3875847012ee42fe54a0027bdf38cca7021b83a2ed0503af69ef6c37c637bc1114fba40096c5947d736e19b7af3c68d95a4e3b8b073adbbb80f47e9db8f2d4f0018ddd847fabfdf9dd9b52c93e40458977725f6b7ba15f0816bb895cdf50401268f5d702b7e6a5f9faef57b8768c8a3fc14f9a4b3182b41d940e337d219b29ff" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "40a453133361cc48da11baf616ee", 14 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_224_test_vector_nist_cavs_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "88e5258b55b1623385eb9632fa7c57d6" );
            src_len = unhexify( src_str, "ada76bb604be14326551701cf30e48a65eee80b44f0b9d4a07b1844543b7844a621097fdc99de57387458ae9354899b620d0617eabcaefa9eef3d413a33628054335ce656c26fa2986e0f111a6351096b283101ec7868871d770b370973c7405983f9756b3005a3eab492cfd0e7eb42e5c2e15fa6be8718c0a50acc4e5717230" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "81c783af538015cef3c60095df53", 14 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_224_test_vector_nist_cavs_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "85d402d822114d31abf75526e2538705" );
            src_len = unhexify( src_str, "8020d8d98cc2e2298b32879c51c751e1dd5558fe2eabb8f158604297d6d072ce2261a1d6830b7cfe2617b57c7126f99c9476211d6161acd75d266da217ec8174b80484c9dc6f0448a0a036a3fc82e8bf54bdb71549368258d5d41f57978a4c266b92e8783ef66350215573d99be4089144b383ad8f3222bae8f3bf80ffb1bb2b" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "2aa0340ac9deafe3be38129daca0", 14 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_224_test_vector_nist_cavs_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "545c6eecc5ee46fa17c59f91a94f81ae" );
            src_len = unhexify( src_str, "8fb7f3565593170152ddb2021874784e951977cfdd22f8b72a72a61320a8f2a35697b5e913f717805559b1af1861ee3ed42fb788481e4fd276b17bdbefcae7b4501dc5d20de5b7626dd5efdcd65294db4bdf682c33d9a9255c6435383fa5f1c886326a3acbc6bd50a33ab5b2dbb034ce0112d4e226bbcd57e3731a519aa1d784" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "3eb566eac54c4a3a9ef092469f24", 14 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_224_test_vector_nist_cavs_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "4466ab4dc438841a9750c7f173dff02e" );
            src_len = unhexify( src_str, "2534c11c78c99cffaec8f722f04adc7045c7324d58ce98e37cfa94b6ed21ed7f58ce55379ef24b72d6d640ee9154f96c614734be9c408e225d7ba4cecc1179cc9f6e1808e1067aa8f244a99bd0c3267594c1887a40d167f8b7cf78db0d19f97b01fc50b8c86def490dfa7a5135002c33e71d77a8cce8ea0f93e0580439a33733" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "59f44a9bbed4875b892d22d6b5ab", 14 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_224_test_vector_nist_cavs_6)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "0e3dd9bb5e4cf0f09a4c11600af56d8d" );
            src_len = unhexify( src_str, "f4589fa76c328ea25cf8bae582026ba40a59d45a546ff31cf80eb826088f69bb954c452c74586836416dee90a5255bc5d56d3b405b3705a5197045688b32fa984c3a3dfbdc9c2460a0b5e6312a624048bb6f170306535e9b371a3ab134a2642a230ad03d2c688cca80baeaee9a20e1d4c548b1cede29c6a45bf4df2c8c476f1a" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "12175b93e3da4c58217145e4dc0a1cf142fab9319bb501e037b350ba", 28 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_224_test_vector_nist_cavs_7)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "cda5187b0c5dcb0f8e5a8beed2306584" );
            src_len = unhexify( src_str, "9011ae29b44c49b347487ce972965f16ade3c15be0856ce9c853a9739dba07e4f20d594ddc1dfe21560a65a4e458cfa17745575b915a30c7a9412ff8d1d689db9680dd2428c27588bb0dc92d2cd9445fe8f44b840a197c52c3c4333fff45533945134398df6436513cfab06c924046b8c795a5bd92e8d5f2de85bf306f2eed67" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "4aaba92b40e2a600feab176eb9b292d814864195c03342aad6f67f08", 28 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_256_test_vector_nist_cavs_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "cdffd34e6b16fdc0" );
            src_len = unhexify( src_str, "d83e78b99ab61709608972b36e76a575603db742269cc5dd4e7d5ca7816e26b65151c92632550cb4c5253c885d5fce53bc47459a1dbd5652786c4aac0145a532f12c05138af04cbb558101a7af5df478834c2146594dd73690d01a4fe72545894335f427ac70204798068cb86c5a600b40b414ede23590b41e1192373df84fe3" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "c6f0dde266cb4a26d41e8259d33499cc", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_256_test_vector_nist_cavs_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "6d97bb5892245be2" );
            src_len = unhexify( src_str, "13c2b391d59c0252ca5d2302beaaf88c4bcd779bb505ad9a122003dfae4cc123ad2bd036f225c4f040021a6b9fb8bd6f0281cf2e2631a732bdc71693cc42ef6d52b6c6912a9ef77b3274eb85ad7f965ae6ed44ac1721962a884ec7acfb4534b1488b1c0c45afa4dae8da1eb7b0a88a3240365d7e4e7d826abbde9f9203fd99d7" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "31588e241b015319a5ab8c4527296498", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_256_test_vector_nist_cavs_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "3c7fc8a70b49007a" );
            src_len = unhexify( src_str, "60024e428a39c8b8bb2e9591bad9dc2115dfbfd716b6eb7af30a6eb34560caccbbfa47b710fa8d523aca71e9e5ba10fc1feb1a43556d71f07ea4f33496f093044e8caf1d02b79e46eb1288d5964a7a7494f6b92574c35784eece054c6151281d80822f7d47b8231c35d07f5cb5cf4310ddc844845a01c6bfab514c048eccaf9f" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "1c98c94a32bec9f253c21070f82f8438", 16 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_256_test_vector_nist_cavs_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "369f33f85b927a07" );
            src_len = unhexify( src_str, "ae8e2a94ca386d448cbacdb0e9040ae3cb297c296363052cc157455da29a0c95897315fc11e3f12b81e2418da1ec280bccbc00e847584ce9d14deeba7b3c9b8dba958b04bba37551f6c9ba9c060be1a4b8cf43aa62e5078b76c6512c5619b71a6a7cf5727180e1ff14f5a1a3c1691bf8b6ebad365c151e58d749d57adb3a4986" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "60b90383286533d309de46593e6ce39fc51fb00a8d88278c", 24 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_256_test_vector_nist_cavs_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "e5179687582b4dc4" );
            src_len = unhexify( src_str, "ce103bdacdf32f614f6727bcb31ca1c2824a850d00f5585b016fb234fe1ef2cd687f302d3c6b738ed89a24060d65c36675d0d96307c72ef3e8a83bfa8402e226de9d5d1724ba75c4879bf41a4a465ce61887d9f49a34757849b48bae81c27ebed76faae2ad669bca04747d409148d40812776e0ae2c395b3cb9c89981ce72d5c" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "509581f6816df4b8cc9f2cf42b7cc6e6a5a1e375a16f2412", 24 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_256_test_vector_nist_cavs_6)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "63cec6246aeb1b61" );
            src_len = unhexify( src_str, "c178db908a405fa88aa255b8cad22b4057016585f139ee930388b083d86062fa0b3ea1f23f8a43bd11bee8464bcbd19b5ab9f6a8038d5245516f8274d20c8ee3033a07b908da528fa00343bb595deed500cab9745c4cb6391c23300f0d3584b090b3326c4cfa342620b78f9f5b4f27f7307ed770643ec1764aeae3dcf1a3ec69" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "64f3dd861b7c7d29fce9ae0ce9ed954b5d7141806ee9eec7", 24 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_384_test_vector_nist_cavs_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "91a7401817386948ca952f9a20ee55dc" );
            src_len = unhexify( src_str, "2fea5b91035d6d501f3a834fa178bff4e64b99a8450432dafd32e4466b0e1e7781166f8a73f7e036b3b0870920f559f47bd1400a1a906e85e0dcf00a6c26862e9148b23806680f285f1fe4f93cdaf924c181a965465739c14f2268c8be8b471847c74b222577a1310bcdc1a85ef1468aa1a3fd4031213c97324b7509c9050a3d" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "6d7be9490058cf413cc09fd043c224c2ec4fa7859b13783000a9a593c9f75838", 32 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_384_test_vector_nist_cavs_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "d6cac19657061aa90a6da11cd2e9ea47" );
            src_len = unhexify( src_str, "9f482e4655173135dfaa22a11bbbe6af263db48716406c5aec162ba3c4b41cad4f5a91558377521191c7343118beee65982929802913d67b6de5c4bdc3d27299bd722219d5ad2efa5bdb9ff7b229fc4bbc3f60719320cf2e7a51cad1133d21bad2d80919b1836ef825308b7c51c6b7677ac782e2bc30007afba065681cbdd215" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "f3d5f3c008175321aa7b2ea379eaa4f8b9dcc60f895ec8940b8162f80a7dfe9f", 32 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_384_test_vector_nist_cavs_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "e06366ad149b8442cd4c1abdddd0afde" );
            src_len = unhexify( src_str, "2d140a194c02a5598f69174834679b8371234a0d505491f1bd03e128dd91a8bca2fb812e9d5da71613b5b00952ea78bf450d5b7547dea79135925085c7d3e6f52009c51ca3d88c6c09e9d074b0ee110736e0ec9b478b93efb34d7bf1c41b54decec43eab077a3aa4998ede53f67b4ea36c266745f9643d5360bdc8337c70dabf" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "c19c67eda6fe29f3667bee1c897c333ce7683094ae77e84b4c16378d290895a1", 32 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_384_test_vector_nist_cavs_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "01ac59f42f8bb91d1bd10fe6990d7a87" );
            src_len = unhexify( src_str, "3caf18c476edd5615f343ac7b7d3a9da9efade755672d5ba4b8ae8a7505539ea2c124ff755ec0457fbe49e43480b3c71e7f4742ec3693aad115d039f90222b030fdc9440313691716d5302005808c07627483b916fdf61983063c2eb1268f2deeef42fc790334456bc6bad256e31fc9066de7cc7e43d1321b1866db45e905622" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "1985fa2163a5943fc5d92f1fe8831215e7e91f0bff5332bc713a072bdb3a8f9e5c5157463a3bfeb36231416e65973e64", 48 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_384_test_vector_nist_cavs_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "fd74b9d9e102a3a80df1baf0cb35bace" );
            src_len = unhexify( src_str, "1a068917584813d1689ccbd0370c2114d537cdc8cc52bf6db16d5535f8f7d1ad0c850a9fa0cf62373ffbf7642b1f1e8164010d350721d798d9f99e9724830399c2fce26377e83d38845675457865c03d4a07d741a505ef028343eb29fd46d0f761f3792886998c1e5c32ac3bc7e6f08faed194b34f06eff4d5d4a5b42c481e0e" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "a981eaf5de3d78b20ebd4414a4edd0657e3667cd808a0dbc430cf7252f73a5b24efa136039207bd59806897457d74e0c", 48 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_384_test_vector_nist_cavs_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "9fe794f0e26b669fa5f6883149377c6c" );
            src_len = unhexify( src_str, "6010c9745e8f1d44cfdc99e7e0fd79bc4271944c2d1d84dba589073dfc4ca5eb98c59356f60cd87bef28aeb83a832bde339b2087daf942aa1f67876c5d5ed33924bed4143bc12a2be532ccaf64daa7e2bc3c8872b9823b0533b6f5159135effe8c61545536975d7c3a61ba7365ec35f165bc92b4d19eb9156ade17dfa1bb4161" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "915ae61f8754698c2b6ef9629e93441f8541bd4258a5e05372d19136cfaefc0473b48d96119291b38eb1a3cb1982a986", 48 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_512_test_vector_nist_cavs_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "c95a17c09940a691ed2d621571b0eb844ede55a9" );
            src_len = unhexify( src_str, "99cd28262e81f34878cdcebf4128e05e2098a7009278a66f4c785784d0e5678f3f2b22f86e982d273b6273a222ec61750b4556d766f1550a7aedfe83faedbc4bdae83fa560d62df17eb914d05fdaa48940551bac81d700f5fca7147295e386e8120d66742ec65c6ee8d89a92217a0f6266d0ddc60bb20ef679ae8299c8502c2f" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "6bc1379d156559ddee2ed420ea5d5c5ff3e454a1059b7ba72c350e77b6e9333c", 32 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_512_test_vector_nist_cavs_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "3b10b8fa718840d1dea8e9fc317476bcf55875fd" );
            src_len = unhexify( src_str, "f04f5b7073d7d0274e8354433b390306c5607632f5f589c12edb62d55673aff2366d2e6b24de731adf92e654baa30b1cfd4a069788f65ec1b99b015d904d8832110dbd74eae35a81562d14ce4136d820ad0a55ff5489ba678fbbc1c27663ec1349d70e740f0e0ec27cfbe8971819f4789e486b50a2d7271d77e2aaea50de62fd" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "fc3c38c7a17e3ce06db033f1c172866f01a00045db55f2e234f71c82264f2ba2", 32 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_512_test_vector_nist_cavs_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "4803d311394600dc1e0d8fc8cedeb8bde3fe7c42" );
            src_len = unhexify( src_str, "a10c125dd702a97153ad923ba5e9889cfac1ba169de370debe51f233735aa6effcc9785c4b5c7e48c477dc5c411ae6a959118584e26adc94b42c2b29b046f3cf01c65b24a24bd2e620bdf650a23bb4a72655b1100d7ce9a4dab697c6379754b4396c825de4b9eb73f2e6a6c0d0353bbdeaf706612800e137b858fdb30f3311c6" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "7cd8236c55102e6385f52279506df6fcc388ab75092da21395ce14a82b202ffa", 32 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_512_test_vector_nist_cavs_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "aeb2f3b977fa6c8e71e07c5a5c74ff58166de092" );
            src_len = unhexify( src_str, "22457355dc76095abd46846b41cfe49a06ce42ac8857b4702fc771508dfb3626e0bfe851df897a07b36811ec433766e4b4166c26301b3493e7440d4554b0ef6ac20f1a530e58fac8aeba4e9ff2d4898d8a28783b49cd269c2965fd7f8e4f2d60cf1e5284f2495145b72382aad90e153a90ecae125ad75336fb128825c23fb8b0" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "fa39bd8fcc3bfa218f9dea5d3b2ce10a7619e31678a56d8a9d927b1fe703b125af445debe9a89a07db6194d27b44d85a", 48 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_512_test_vector_nist_cavs_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "4285d3d7744da52775bb44ca436a3154f7980309" );
            src_len = unhexify( src_str, "208f0b6f2de2e5aa5df11927ddc6df485edc1193181c484d0f0a434a95418803101d4de9fdb798f93516a6916fa38a8207de1666fe50fe3441c03b112eaaae6954ed063f7ac4e3c1e3f73b20d153fe9e4857f5e91430f0a70ee820529adac2467469fd18adf10e2af0fea27c0abc83c5a9af77c364a466cffce8bab4e2b70bc1" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "fe7603f205b2774fe0f14ecfa3e338e90608a806d11ca459dff5ce36b1b264ecd3af5f0492a7521d8da3102ba20927a5", 48 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_hmac_sha_512_test_vector_nist_cavs_6)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char key_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int key_len, src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(key_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            key_len = unhexify( key_str, "8ab783d5acf32efa0d9c0a21abce955e96630d89" );
            src_len = unhexify( src_str, "17371e013dce839963d54418e97be4bd9fa3cb2a368a5220f5aa1b8aaddfa3bdefc91afe7c717244fd2fb640f5cb9d9bf3e25f7f0c8bc758883b89dcdce6d749d9672fed222277ece3e84b3ec01b96f70c125fcb3cbee6d19b8ef0873f915f173bdb05d81629ba187cc8ac1934b2f75952fb7616ae6bd812946df694bd2763af" );
        
            fct_chk ( 0 == md_hmac_starts( &ctx, key_str, key_len ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_hmac_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_hmac_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strncmp( (char *) hash_str, "9ac7ca8d1aefc166b046e4cf7602ebe181a0e5055474bff5b342106731da0d7e48e4d87bc0a6f05871574289a1b099f8", 48 * 2 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_sha_1_test_vector_nist_cavs_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "da39a3ee5e6b4b0d3255bfef95601890afd80709" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_sha_1_test_vector_nist_cavs_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "a8" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "99f2aa95e36f95c2acb0eaf23998f030638f3f15" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_sha_1_test_vector_nist_cavs_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "3000" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "f944dcd635f9801f7ac90a407fbc479964dec024" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_sha_1_test_vector_nist_cavs_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "42749e" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "a444319e9b6cc1e8464c511ec0969c37d6bb2619" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_sha_1_test_vector_nist_cavs_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "9fc3fe08" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "16a0ff84fcc156fd5d3ca3a744f20a232d172253" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_sha_1_test_vector_nist_cavs_6)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "b5c1c6f1af" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "fec9deebfcdedaf66dda525e1be43597a73a1f93" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_sha_1_test_vector_nist_cavs_7)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "ec29561244ede706b6eb30a1c371d74450a105c3f9735f7fa9fe38cf67f304a5736a106e92e17139a6813b1c81a4f3d3fb9546ab4296fa9f722826c066869edacd73b2548035185813e22634a9da44000d95a281ff9f264ecce0a931222162d021cca28db5f3c2aa24945ab1e31cb413ae29810fd794cad5dfaf29ec43cb38d198fe4ae1da2359780221405bd6712a5305da4b1b737fce7cd21c0eb7728d08235a9011" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "970111c4e77bcc88cc20459c02b69b4aa8f58217" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_sha_1_test_vector_nist_cavs_8)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "5fc2c3f6a7e79dc94be526e5166a238899d54927ce470018fbfd668fd9dd97cbf64e2c91584d01da63be3cc9fdff8adfefc3ac728e1e335b9cdc87f069172e323d094b47fa1e652afe4d6aa147a9f46fda33cacb65f3aa12234746b9007a8c85fe982afed7815221e43dba553d8fe8a022cdac1b99eeeea359e5a9d2e72e382dffa6d19f359f4f27dc3434cd27daeeda8e38594873398678065fbb23665aba9309d946135da0e4a4afdadff14db18e85e71dd93c3bf9faf7f25c8194c4269b1ee3d9934097ab990025d9c3aaf63d5109f52335dd3959d38ae485050e4bbb6235574fc0102be8f7a306d6e8de6ba6becf80f37415b57f9898a5824e77414197422be3d36a6080" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "0423dc76a8791107d14e13f5265b343f24cc0f19" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_sha_1_test_vector_nist_cavs_9)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "0f865f46a8f3aed2da18482aa09a8f390dc9da07d51d1bd10fe0bf5f3928d5927d08733d32075535a6d1c8ac1b2dc6ba0f2f633dc1af68e3f0fa3d85e6c60cb7b56c239dc1519a007ea536a07b518ecca02a6c31b46b76f021620ef3fc6976804018380e5ab9c558ebfc5cb1c9ed2d974722bf8ab6398f1f2b82fa5083f85c16a5767a3a07271d67743f00850ce8ec428c7f22f1cf01f99895c0c844845b06a06cecb0c6cf83eb55a1d4ebc44c2c13f6f7aa5e0e08abfd84e7864279057abc471ee4a45dbbb5774afa24e51791a0eada11093b88681fe30baa3b2e94113dc63342c51ca5d1a6096d0897b626e42cb91761058008f746f35465465540ad8c6b8b60f7e1461b3ce9e6529625984cb8c7d46f07f735be067588a0117f23e34ff57800e2bbe9a1605fde6087fb15d22c5d3ac47566b8c448b0cee40373e5ba6eaa21abee71366afbb27dbbd300477d70c371e7b8963812f5ed4fb784fb2f3bd1d3afe883cdd47ef32beaea" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "6692a71d73e00f27df976bc56df4970650d90e45" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_sha_1_test_vector_nist_cavs_10)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "8236153781bd2f1b81ffe0def1beb46f5a70191142926651503f1b3bb1016acdb9e7f7acced8dd168226f118ff664a01a8800116fd023587bfba52a2558393476f5fc69ce9c65001f23e70476d2cc81c97ea19caeb194e224339bcb23f77a83feac5096f9b3090c51a6ee6d204b735aa71d7e996d380b80822e4dfd43683af9c7442498cacbea64842dfda238cb099927c6efae07fdf7b23a4e4456e0152b24853fe0d5de4179974b2b9d4a1cdbefcbc01d8d311b5dda059136176ea698ab82acf20dd490be47130b1235cb48f8a6710473cfc923e222d94b582f9ae36d4ca2a32d141b8e8cc36638845fbc499bce17698c3fecae2572dbbd470552430d7ef30c238c2124478f1f780483839b4fb73d63a9460206824a5b6b65315b21e3c2f24c97ee7c0e78faad3df549c7ca8ef241876d9aafe9a309f6da352bec2caaa92ee8dca392899ba67dfed90aef33d41fc2494b765cb3e2422c8e595dabbfaca217757453fb322a13203f425f6073a9903e2dc5818ee1da737afc345f0057744e3a56e1681c949eb12273a3bfc20699e423b96e44bd1ff62e50a848a890809bfe1611c6787d3d741103308f849a790f9c015098286dbacfc34c1718b2c2b77e32194a75dda37954a320fa68764027852855a7e5b5274eb1e2cbcd27161d98b59ad245822015f48af82a45c0ed59be94f9af03d9736048570d6e3ef63b1770bc98dfb77de84b1bb1708d872b625d9ab9b06c18e5dbbf34399391f0f8aa26ec0dac7ff4cb8ec97b52bcb942fa6db2385dcd1b3b9d567aaeb425d567b0ebe267235651a1ed9bf78fd93d3c1dd077fe340bb04b00529c58f45124b717c168d07e9826e33376988bc5cf62845c2009980a4dfa69fbc7e5a0b1bb20a5958ca967aec68eb31dd8fccca9afcd30a26bab26279f1bf6724ff" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "11863b483809ef88413ca9b0084ac4a5390640af" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_sha_224_test_vector_nist_cavs_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_sha_224_test_vector_nist_cavs_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "ff" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "e33f9d75e6ae1369dbabf81b96b4591ae46bba30b591a6b6c62542b5" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_sha_224_test_vector_nist_cavs_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "984c" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "2fa9df9157d9e027cfbc4c6a9df32e1adc0cbe2328ec2a63c5ae934e" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_sha_224_test_vector_nist_cavs_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "50efd0" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "b5a9820413c2bf8211fbbf5df1337043b32fa4eafaf61a0c8e9ccede" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_sha_224_test_vector_nist_cavs_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "e5e09924" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "fd19e74690d291467ce59f077df311638f1c3a46e510d0e49a67062d" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_sha_224_test_vector_nist_cavs_6)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "21ebecb914" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "78f4a71c21c694499ce1c7866611b14ace70d905012c356323c7c713" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_sha_224_test_vector_nist_cavs_7)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "fc488947c1a7a589726b15436b4f3d9556262f98fc6422fc5cdf20f0fad7fe427a3491c86d101ffe6b7514f06268f65b2d269b0f69ad9a97847eff1c16a2438775eb7be6847ccf11cb8b2e8dcd6640b095b49c0693fe3cf4a66e2d9b7ad68bff14f3ad69abf49d0aba36cbe0535202deb6599a47225ef05beb351335cd7bc0f480d691198c7e71305ffd53b39d33242bb79cfd98bfd69e137b5d18b2b89ac9ace01c8dbdcf2533cce3682ecc52118de0c1062ec2126c2e657d6ea3d9e2398e705d4b0b1f1ceecb266dffc4f31bf42744fb1e938dc22a889919ee1e73f463f7871fed720519e32186264b7ef2a0e5d9a18e6c95c0781894f77967f048951dec3b4d892a38710b1e3436d3c29088eb8b3da1789c25db3d3bc6c26081206e7155d210a89b80ca6ea877c41ff9947c0f25625dcb118294a163501f6239c326661a958fd12da4cd15a899f8b88cc723589056eaec5aa04a4cf5dbb6f480f9660423ccf38c486e210707e0fb25e1f126ceb2616f63e147a647dab0af9ebe89d65458bf636154a46e4cab95f5ee62da2c7974cd14b90d3e4f99f81733e85b3c1d5da2b508d9b90f5eed7eff0d9c7649de62bee00375454fee4a39576a5bbfdae428e7f8097bdf7797f167686cb68407e49079e4611ff3402b6384ba7b7e522bd2bb11ce8fd02ea4c1604d163ac4f6dde50b8b1f593f7edaadeac0868ed97df690200680c25f0f5d85431a529e4f339089dcdeda105e4ee51dead704cdf5a605c55fb055c9b0e86b8ba1b564c0dea3eb790a595cb103cb292268b07c5e59371e1a7ef597cd4b22977a820694c9f9aeb55d9de3ef62b75d6e656e3336698d960a3787bf8cf5b926a7faeef52ae128bcb5dc9e66d94b016c7b8e034879171a2d91c381f57e6a815b63b5ee6a6d2ff435b49f14c963966960194430d78f8f87627a67757fb3532b289550894da6dce4817a4e07f4d56877a1102ffcc8befa5c9f8fca6a4574d93ff70376c8861e0f8108cf907fce77ecb49728f86f034f80224b9695682e0824462f76cdb1fd1af151337b0d85419047a7aa284791718a4860cd586f7824b95bc837b6fd4f9be5aade68456e20356aa4d943dac36bf8b67b9e8f9d01a00fcda74b798bafa746c661b010f75b59904b29d0c8041504811c4065f82cf2ead58d2f595cbd8bc3e7043f4d94577b373b7cfe16a36fe564f505c03b70cfeb5e5f411c79481338aa67e86b3f5a2e77c21e454c333ae3da943ab723ab5f4c940395319534a5575f64acba0d0ecc43f60221ed3badf7289c9b3a7b903a2d6c94e15fa4c310dc4fa7faa0c24f405160a1002dbef20e4105d481db982f7243f79400a6e4cd9753c4b9732a47575f504b20c328fe9add7f432a4f075829da07b53b695037dc51737d3cd731934df333cd1a53fcf65aa31baa450ca501a6fae26e322347e618c5a444d92e9fec5a8261ae38b98fee5be77c02cec09ddccd5b3de92036" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "1302149d1e197c41813b054c942329d420e366530f5517b470e964fe" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_sha_256_test_vector_nist_cavs_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_sha_256_test_vector_nist_cavs_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "bd" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_sha_256_test_vector_nist_cavs_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "5fd4" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "7c4fbf484498d21b487b9d61de8914b2eadaf2698712936d47c3ada2558f6788" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_sha_256_test_vector_nist_cavs_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "b0bd69" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "4096804221093ddccfbf46831490ea63e9e99414858f8d75ff7f642c7ca61803" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_sha_256_test_vector_nist_cavs_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "c98c8e55" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "7abc22c0ae5af26ce93dbb94433a0e0b2e119d014f8e7f65bd56c61ccccd9504" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_sha_256_test_vector_nist_cavs_6)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "81a723d966" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "7516fb8bb11350df2bf386bc3c33bd0f52cb4c67c6e4745e0488e62c2aea2605" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_sha_256_test_vector_nist_cavs_7)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "8390cf0be07661cc7669aac54ce09a37733a629d45f5d983ef201f9b2d13800e555d9b1097fec3b783d7a50dcb5e2b644b96a1e9463f177cf34906bf388f366db5c2deee04a30e283f764a97c3b377a034fefc22c259214faa99babaff160ab0aaa7e2ccb0ce09c6b32fe08cbc474694375aba703fadbfa31cf685b30a11c57f3cf4edd321e57d3ae6ebb1133c8260e75b9224fa47a2bb205249add2e2e62f817491482ae152322be0900355cdcc8d42a98f82e961a0dc6f537b7b410eff105f59673bfb787bf042aa071f7af68d944d27371c64160fe9382772372516c230c1f45c0d6b6cca7f274b394da9402d3eafdf733994ec58ab22d71829a98399574d4b5908a447a5a681cb0dd50a31145311d92c22a16de1ead66a5499f2dceb4cae694772ce90762ef8336afec653aa9b1a1c4820b221136dfce80dce2ba920d88a530c9410d0a4e0358a3a11052e58dd73b0b179ef8f56fe3b5a2d117a73a0c38a1392b6938e9782e0d86456ee4884e3c39d4d75813f13633bc79baa07c0d2d555afbf207f52b7dca126d015aa2b9873b3eb065e90b9b065a5373fe1fb1b20d594327d19fba56cb81e7b6696605ffa56eba3c27a438697cc21b201fd7e09f18deea1b3ea2f0d1edc02df0e20396a145412cd6b13c32d2e605641c948b714aec30c0649dc44143511f35ab0fd5dd64c34d06fe86f3836dfe9edeb7f08cfc3bd40956826356242191f99f53473f32b0cc0cf9321d6c92a112e8db90b86ee9e87cc32d0343db01e32ce9eb782cb24efbbbeb440fe929e8f2bf8dfb1550a3a2e742e8b455a3e5730e9e6a7a9824d17acc0f72a7f67eae0f0970f8bde46dcdefaed3047cf807e7f00a42e5fd11d40f5e98533d7574425b7d2bc3b3845c443008b58980e768e464e17cc6f6b3939eee52f713963d07d8c4abf02448ef0b889c9671e2f8a436ddeeffcca7176e9bf9d1005ecd377f2fa67c23ed1f137e60bf46018a8bd613d038e883704fc26e798969df35ec7bbc6a4fe46d8910bd82fa3cded265d0a3b6d399e4251e4d8233daa21b5812fded6536198ff13aa5a1cd46a5b9a17a4ddc1d9f85544d1d1cc16f3df858038c8e071a11a7e157a85a6a8dc47e88d75e7009a8b26fdb73f33a2a70f1e0c259f8f9533b9b8f9af9288b7274f21baeec78d396f8bacdcc22471207d9b4efccd3fedc5c5a2214ff5e51c553f35e21ae696fe51e8df733a8e06f50f419e599e9f9e4b37ce643fc810faaa47989771509d69a110ac916261427026369a21263ac4460fb4f708f8ae28599856db7cb6a43ac8e03d64a9609807e76c5f312b9d1863bfa304e8953647648b4f4ab0ed995e" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "4109cdbec3240ad74cc6c37f39300f70fede16e21efc77f7865998714aad0b5e" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_sha_384_test_vector_nist_cavs_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_sha_384_test_vector_nist_cavs_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "ab" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "fb94d5be118865f6fcbc978b825da82cff188faec2f66cb84b2537d74b4938469854b0ca89e66fa2e182834736629f3d" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_sha_384_test_vector_nist_cavs_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "7c27" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "3d80be467df86d63abb9ea1d3f9cb39cd19890e7f2c53a6200bedc5006842b35e820dc4e0ca90ca9b97ab23ef07080fc" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_sha_384_test_vector_nist_cavs_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "31f5ca" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "78d54b943421fdf7ba90a7fb9637c2073aa480454bd841d39ff72f4511fc21fb67797b652c0c823229342873d3bef955" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_sha_384_test_vector_nist_cavs_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "7bdee3f8" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "8bdafba0777ee446c3431c2d7b1fbb631089f71d2ca417abc1d230e1aba64ec2f1c187474a6f4077d372c14ad407f99a" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_sha_384_test_vector_nist_cavs_6)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "8f05604915" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "504e414bf1db1060f14c8c799e25b1e0c4dcf1504ebbd129998f0ae283e6de86e0d3c7e879c73ec3b1836c3ee89c2649" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_sha_384_test_vector_nist_cavs_7)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "665da6eda214" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "4c022f112010908848312f8b8f1072625fd5c105399d562ea1d56130619a7eac8dfc3748fd05ee37e4b690be9daa9980" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_sha_384_test_vector_nist_cavs_8)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "7f46ce506d593c4ed53c82edeb602037e0485befbee03f7f930fe532d18ff2a3f5fd6076672c8145a1bf40dd94f7abab47c9ae71c234213d2ad1069c2dac0b0ba15257ae672b8245960ae55bd50315c0097daa3a318745788d70d14706910809ca6e396237fe4934fa46f9ce782d66606d8bd6b2d283b1160513ce9c24e9f084b97891f99d4cdefc169a029e431ca772ba1bba426fce6f01d8e286014e5acc66b799e4db62bd4783322f8a32ff78e0de3957df50ce10871f4e0680df4e8ca3960af9bc6f4efa8eb3962d18f474eb178c3265cc46b8f2ff5ab1a7449fea297dfcfabfa01f28abbb7289bb354b691b5664ec6d098af51be19947ec5ba7ebd66380d1141953ba78d4aa5401679fa7b0a44db1981f864d3535c45afe4c61183d5b0ad51fae71ca07e34240283959f7530a32c70d95a088e501c230059f333b0670825009e7e22103ef22935830df1fac8ef877f5f3426dd54f7d1128dd871ad9a7d088f94c0e8712013295b8d69ae7623b880978c2d3c6ad26dc478f8dc47f5c0adcc618665dc3dc205a9071b2f2191e16cac5bd89bb59148fc719633752303aa08e518dbc389f0a5482caaa4c507b8729a6f3edd061efb39026cecc6399f51971cf7381d605e144a5928c8c2d1ad7467b05da2f202f4f3234e1aff19a0198a28685721c3d2d52311c721e3fdcbaf30214cdc3acff8c433880e104fb63f2df7ce69a97857819ba7ac00ac8eae1969764fde8f68cf8e0916d7e0c151147d4944f99f42ae50f30e1c79a42d2b6c5188d133d3cbbf69094027b354b295ccd0f7dc5a87d73638bd98ebfb00383ca0fa69cb8dcb35a12510e5e07ad8789047d0b63841a1bb928737e8b0a0c33254f47aa8bfbe3341a09c2b76dbcefa67e30df300d34f7b8465c4f869e51b6bcfe6cf68b238359a645036bf7f63f02924e087ce7457e483b6025a859903cb484574aa3b12cf946f32127d537c33bee3141b5db96d10a148c50ae045f287210757710d6846e04b202f79e87dd9a56bc6da15f84a77a7f63935e1dee00309cd276a8e7176cb04da6bb0e9009534438732cb42d008008853d38d19beba46e61006e30f7efd1bc7c2906b024e4ff898a1b58c448d68b43c6ab63f34f85b3ac6aa4475867e51b583844cb23829f4b30f4bdd817d88e2ef3e7b4fc0a624395b05ec5e8686082b24d29fef2b0d3c29e031d5f94f504b1d3df9361eb5ffbadb242e66c39a8094cfe62f85f639f3fd65fc8ae0c74a8f4c6e1d070b9183a434c722caaa0225f8bcd68614d6f0738ed62f8484ec96077d155c08e26c46be262a73e3551698bd70d8d5610cf37c4c306eed04ba6a040a9c3e6d7e15e8acda17f477c2484cf5c56b813313927be8387b1024f995e98fc87f1029091c01424bdc2b296c2eadb7d25b3e762a2fd0c2dcd1727ddf91db97c5984305265f3695a7f5472f2d72c94d68c27914f14f82aa8dd5fe4e2348b0ca967a3f98626a091552f5d0ffa2bf10350d23c996256c01fdeffb2c2c612519869f877e4929c6e95ff15040f1485e22ed14119880232fef3b57b3848f15b1766a5552879df8f06" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "cba9e3eb12a6f83db11e8a6ff40d1049854ee094416bc527fea931d8585428a8ed6242ce81f6769b36e2123a5c23483e" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_sha_512_test_vector_nist_cavs_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_sha_512_test_vector_nist_cavs_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "8f" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "e4cd2d19931b5aad9c920f45f56f6ce34e3d38c6d319a6e11d0588ab8b838576d6ce6d68eea7c830de66e2bd96458bfa7aafbcbec981d4ed040498c3dd95f22a" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_sha_512_test_vector_nist_cavs_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "e724" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "7dbb520221a70287b23dbcf62bfc1b73136d858e86266732a7fffa875ecaa2c1b8f673b5c065d360c563a7b9539349f5f59bef8c0c593f9587e3cd50bb26a231" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_sha_512_test_vector_nist_cavs_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "de4c90" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "33ce98281045a5c4c9df0363d8196f1d7dfcd5ee46ac89776fd8a4344c12f123a66788af5bd41ceff1941aa5637654b4064c88c14e00465ab79a2fc6c97e1014" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_sha_512_test_vector_nist_cavs_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "a801e94b" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "dadb1b5a27f9fece8d86adb2a51879beb1787ff28f4e8ce162cad7fee0f942efcabbf738bc6f797fc7cc79a3a75048cd4c82ca0757a324695bfb19a557e56e2f" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_sha_512_test_vector_nist_cavs_6)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "94390d3502" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "b6175c4c4cccf69e0ce5f0312010886ea6b34d43673f942ae42483f9cbb7da817de4e11b5d58e25a3d9bd721a22cdffe1c40411cc45df1911fa5506129b69297" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_sha_512_test_vector_nist_cavs_7)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "49297dd63e5f" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "1fcc1e6f6870859d11649f5e5336a9cd16329c029baf04d5a6edf257889a2e9522b497dd656bb402da461307c4ee382e2e89380c8e6e6e7697f1e439f650fa94" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_sha_512_test_vector_nist_cavs_8)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
        
            src_len = unhexify( src_str, "990d1ae71a62d7bda9bfdaa1762a68d296eee72a4cd946f287a898fbabc002ea941fd8d4d991030b4d27a637cce501a834bb95eab1b7889a3e784c7968e67cbf552006b206b68f76d9191327524fcc251aeb56af483d10b4e0c6c5e599ee8c0fe4faeca8293844a8547c6a9a90d093f2526873a19ad4a5e776794c68c742fb834793d2dfcb7fea46c63af4b70fd11cb6e41834e72ee40edb067b292a794990c288d5007e73f349fb383af6a756b8301ad6e5e0aa8cd614399bb3a452376b1575afa6bdaeaafc286cb064bb91edef97c632b6c1113d107fa93a0905098a105043c2f05397f702514439a08a9e5ddc196100721d45c8fc17d2ed659376f8a00bd5cb9a0860e26d8a29d8d6aaf52de97e9346033d6db501a35dbbaf97c20b830cd2d18c2532f3a59cc497ee64c0e57d8d060e5069b28d86edf1adcf59144b221ce3ddaef134b3124fbc7dd000240eff0f5f5f41e83cd7f5bb37c9ae21953fe302b0f6e8b68fa91c6ab99265c64b2fd9cd4942be04321bb5d6d71932376c6f2f88e02422ba6a5e2cb765df93fd5dd0728c6abdaf03bce22e0678a544e2c3636f741b6f4447ee58a8fc656b43ef817932176adbfc2e04b2c812c273cd6cbfa4098f0be036a34221fa02643f5ee2e0b38135f2a18ecd2f16ebc45f8eb31b8ab967a1567ee016904188910861ca1fa205c7adaa194b286893ffe2f4fbe0384c2aef72a4522aeafd3ebc71f9db71eeeef86c48394a1c86d5b36c352cc33a0a2c800bc99e62fd65b3a2fd69e0b53996ec13d8ce483ce9319efd9a85acefabdb5342226febb83fd1daf4b24265f50c61c6de74077ef89b6fecf9f29a1f871af1e9f89b2d345cda7499bd45c42fa5d195a1e1a6ba84851889e730da3b2b916e96152ae0c92154b49719841db7e7cc707ba8a5d7b101eb4ac7b629bb327817910fff61580b59aab78182d1a2e33473d05b00b170b29e331870826cfe45af206aa7d0246bbd8566ca7cfb2d3c10bfa1db7dd48dd786036469ce7282093d78b5e1a5b0fc81a54c8ed4ceac1e5305305e78284ac276f5d7862727aff246e17addde50c670028d572cbfc0be2e4f8b2eb28fa68ad7b4c6c2a239c460441bfb5ea049f23b08563b4e47729a59e5986a61a6093dbd54f8c36ebe87edae01f251cb060ad1364ce677d7e8d5a4a4ca966a7241cc360bc2acb280e5f9e9c1b032ad6a180a35e0c5180b9d16d026c865b252098cc1d99ba7375ca31c7702c0d943d5e3dd2f6861fa55bd46d94b67ed3e52eccd8dd06d968e01897d6de97ed3058d91dd" );
            fct_chk ( 0 == md( md_info, src_str, src_len, output ) );
        
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "8e4bc6f8b8c60fe4d68c61d9b159c8693c3151c46749af58da228442d927f23359bd6ccd6c2ec8fa3f00a86cecbfa728e1ad60b821ed22fcd309ba91a4138bc9" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_multi_step_sha_1_test_vector_nist_cavs_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "da39a3ee5e6b4b0d3255bfef95601890afd80709" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_multi_step_sha_1_test_vector_nist_cavs_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "a8" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "99f2aa95e36f95c2acb0eaf23998f030638f3f15" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_multi_step_sha_1_test_vector_nist_cavs_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "3000" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "f944dcd635f9801f7ac90a407fbc479964dec024" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_multi_step_sha_1_test_vector_nist_cavs_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "42749e" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "a444319e9b6cc1e8464c511ec0969c37d6bb2619" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_multi_step_sha_1_test_vector_nist_cavs_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "9fc3fe08" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "16a0ff84fcc156fd5d3ca3a744f20a232d172253" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_multi_step_sha_1_test_vector_nist_cavs_6)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "b5c1c6f1af" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "fec9deebfcdedaf66dda525e1be43597a73a1f93" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_multi_step_sha_1_test_vector_nist_cavs_7)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "ec29561244ede706b6eb30a1c371d74450a105c3f9735f7fa9fe38cf67f304a5736a106e92e17139a6813b1c81a4f3d3fb9546ab4296fa9f722826c066869edacd73b2548035185813e22634a9da44000d95a281ff9f264ecce0a931222162d021cca28db5f3c2aa24945ab1e31cb413ae29810fd794cad5dfaf29ec43cb38d198fe4ae1da2359780221405bd6712a5305da4b1b737fce7cd21c0eb7728d08235a9011" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "970111c4e77bcc88cc20459c02b69b4aa8f58217" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_multi_step_sha_1_test_vector_nist_cavs_8)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "5fc2c3f6a7e79dc94be526e5166a238899d54927ce470018fbfd668fd9dd97cbf64e2c91584d01da63be3cc9fdff8adfefc3ac728e1e335b9cdc87f069172e323d094b47fa1e652afe4d6aa147a9f46fda33cacb65f3aa12234746b9007a8c85fe982afed7815221e43dba553d8fe8a022cdac1b99eeeea359e5a9d2e72e382dffa6d19f359f4f27dc3434cd27daeeda8e38594873398678065fbb23665aba9309d946135da0e4a4afdadff14db18e85e71dd93c3bf9faf7f25c8194c4269b1ee3d9934097ab990025d9c3aaf63d5109f52335dd3959d38ae485050e4bbb6235574fc0102be8f7a306d6e8de6ba6becf80f37415b57f9898a5824e77414197422be3d36a6080" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "0423dc76a8791107d14e13f5265b343f24cc0f19" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_multi_step_sha_1_test_vector_nist_cavs_9)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "0f865f46a8f3aed2da18482aa09a8f390dc9da07d51d1bd10fe0bf5f3928d5927d08733d32075535a6d1c8ac1b2dc6ba0f2f633dc1af68e3f0fa3d85e6c60cb7b56c239dc1519a007ea536a07b518ecca02a6c31b46b76f021620ef3fc6976804018380e5ab9c558ebfc5cb1c9ed2d974722bf8ab6398f1f2b82fa5083f85c16a5767a3a07271d67743f00850ce8ec428c7f22f1cf01f99895c0c844845b06a06cecb0c6cf83eb55a1d4ebc44c2c13f6f7aa5e0e08abfd84e7864279057abc471ee4a45dbbb5774afa24e51791a0eada11093b88681fe30baa3b2e94113dc63342c51ca5d1a6096d0897b626e42cb91761058008f746f35465465540ad8c6b8b60f7e1461b3ce9e6529625984cb8c7d46f07f735be067588a0117f23e34ff57800e2bbe9a1605fde6087fb15d22c5d3ac47566b8c448b0cee40373e5ba6eaa21abee71366afbb27dbbd300477d70c371e7b8963812f5ed4fb784fb2f3bd1d3afe883cdd47ef32beaea" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "6692a71d73e00f27df976bc56df4970650d90e45" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA1_C

        FCT_TEST_BGN(generic_multi_step_sha_1_test_vector_nist_cavs_10)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "8236153781bd2f1b81ffe0def1beb46f5a70191142926651503f1b3bb1016acdb9e7f7acced8dd168226f118ff664a01a8800116fd023587bfba52a2558393476f5fc69ce9c65001f23e70476d2cc81c97ea19caeb194e224339bcb23f77a83feac5096f9b3090c51a6ee6d204b735aa71d7e996d380b80822e4dfd43683af9c7442498cacbea64842dfda238cb099927c6efae07fdf7b23a4e4456e0152b24853fe0d5de4179974b2b9d4a1cdbefcbc01d8d311b5dda059136176ea698ab82acf20dd490be47130b1235cb48f8a6710473cfc923e222d94b582f9ae36d4ca2a32d141b8e8cc36638845fbc499bce17698c3fecae2572dbbd470552430d7ef30c238c2124478f1f780483839b4fb73d63a9460206824a5b6b65315b21e3c2f24c97ee7c0e78faad3df549c7ca8ef241876d9aafe9a309f6da352bec2caaa92ee8dca392899ba67dfed90aef33d41fc2494b765cb3e2422c8e595dabbfaca217757453fb322a13203f425f6073a9903e2dc5818ee1da737afc345f0057744e3a56e1681c949eb12273a3bfc20699e423b96e44bd1ff62e50a848a890809bfe1611c6787d3d741103308f849a790f9c015098286dbacfc34c1718b2c2b77e32194a75dda37954a320fa68764027852855a7e5b5274eb1e2cbcd27161d98b59ad245822015f48af82a45c0ed59be94f9af03d9736048570d6e3ef63b1770bc98dfb77de84b1bb1708d872b625d9ab9b06c18e5dbbf34399391f0f8aa26ec0dac7ff4cb8ec97b52bcb942fa6db2385dcd1b3b9d567aaeb425d567b0ebe267235651a1ed9bf78fd93d3c1dd077fe340bb04b00529c58f45124b717c168d07e9826e33376988bc5cf62845c2009980a4dfa69fbc7e5a0b1bb20a5958ca967aec68eb31dd8fccca9afcd30a26bab26279f1bf6724ff" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "11863b483809ef88413ca9b0084ac4a5390640af" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_sha_224_test_vector_nist_cavs_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_sha_224_test_vector_nist_cavs_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "ff" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "e33f9d75e6ae1369dbabf81b96b4591ae46bba30b591a6b6c62542b5" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_sha_224_test_vector_nist_cavs_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "984c" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "2fa9df9157d9e027cfbc4c6a9df32e1adc0cbe2328ec2a63c5ae934e" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_sha_224_test_vector_nist_cavs_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "50efd0" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "b5a9820413c2bf8211fbbf5df1337043b32fa4eafaf61a0c8e9ccede" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_sha_224_test_vector_nist_cavs_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "e5e09924" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "fd19e74690d291467ce59f077df311638f1c3a46e510d0e49a67062d" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_sha_224_test_vector_nist_cavs_6)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "21ebecb914" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "78f4a71c21c694499ce1c7866611b14ace70d905012c356323c7c713" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_sha_224_test_vector_nist_cavs_7)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "fc488947c1a7a589726b15436b4f3d9556262f98fc6422fc5cdf20f0fad7fe427a3491c86d101ffe6b7514f06268f65b2d269b0f69ad9a97847eff1c16a2438775eb7be6847ccf11cb8b2e8dcd6640b095b49c0693fe3cf4a66e2d9b7ad68bff14f3ad69abf49d0aba36cbe0535202deb6599a47225ef05beb351335cd7bc0f480d691198c7e71305ffd53b39d33242bb79cfd98bfd69e137b5d18b2b89ac9ace01c8dbdcf2533cce3682ecc52118de0c1062ec2126c2e657d6ea3d9e2398e705d4b0b1f1ceecb266dffc4f31bf42744fb1e938dc22a889919ee1e73f463f7871fed720519e32186264b7ef2a0e5d9a18e6c95c0781894f77967f048951dec3b4d892a38710b1e3436d3c29088eb8b3da1789c25db3d3bc6c26081206e7155d210a89b80ca6ea877c41ff9947c0f25625dcb118294a163501f6239c326661a958fd12da4cd15a899f8b88cc723589056eaec5aa04a4cf5dbb6f480f9660423ccf38c486e210707e0fb25e1f126ceb2616f63e147a647dab0af9ebe89d65458bf636154a46e4cab95f5ee62da2c7974cd14b90d3e4f99f81733e85b3c1d5da2b508d9b90f5eed7eff0d9c7649de62bee00375454fee4a39576a5bbfdae428e7f8097bdf7797f167686cb68407e49079e4611ff3402b6384ba7b7e522bd2bb11ce8fd02ea4c1604d163ac4f6dde50b8b1f593f7edaadeac0868ed97df690200680c25f0f5d85431a529e4f339089dcdeda105e4ee51dead704cdf5a605c55fb055c9b0e86b8ba1b564c0dea3eb790a595cb103cb292268b07c5e59371e1a7ef597cd4b22977a820694c9f9aeb55d9de3ef62b75d6e656e3336698d960a3787bf8cf5b926a7faeef52ae128bcb5dc9e66d94b016c7b8e034879171a2d91c381f57e6a815b63b5ee6a6d2ff435b49f14c963966960194430d78f8f87627a67757fb3532b289550894da6dce4817a4e07f4d56877a1102ffcc8befa5c9f8fca6a4574d93ff70376c8861e0f8108cf907fce77ecb49728f86f034f80224b9695682e0824462f76cdb1fd1af151337b0d85419047a7aa284791718a4860cd586f7824b95bc837b6fd4f9be5aade68456e20356aa4d943dac36bf8b67b9e8f9d01a00fcda74b798bafa746c661b010f75b59904b29d0c8041504811c4065f82cf2ead58d2f595cbd8bc3e7043f4d94577b373b7cfe16a36fe564f505c03b70cfeb5e5f411c79481338aa67e86b3f5a2e77c21e454c333ae3da943ab723ab5f4c940395319534a5575f64acba0d0ecc43f60221ed3badf7289c9b3a7b903a2d6c94e15fa4c310dc4fa7faa0c24f405160a1002dbef20e4105d481db982f7243f79400a6e4cd9753c4b9732a47575f504b20c328fe9add7f432a4f075829da07b53b695037dc51737d3cd731934df333cd1a53fcf65aa31baa450ca501a6fae26e322347e618c5a444d92e9fec5a8261ae38b98fee5be77c02cec09ddccd5b3de92036" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "1302149d1e197c41813b054c942329d420e366530f5517b470e964fe" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_sha_256_test_vector_nist_cavs_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_sha_256_test_vector_nist_cavs_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "bd" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_sha_256_test_vector_nist_cavs_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "5fd4" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "7c4fbf484498d21b487b9d61de8914b2eadaf2698712936d47c3ada2558f6788" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_sha_256_test_vector_nist_cavs_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "b0bd69" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "4096804221093ddccfbf46831490ea63e9e99414858f8d75ff7f642c7ca61803" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_sha_256_test_vector_nist_cavs_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "c98c8e55" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "7abc22c0ae5af26ce93dbb94433a0e0b2e119d014f8e7f65bd56c61ccccd9504" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_sha_256_test_vector_nist_cavs_6)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "81a723d966" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "7516fb8bb11350df2bf386bc3c33bd0f52cb4c67c6e4745e0488e62c2aea2605" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA2_C

        FCT_TEST_BGN(generic_multi_step_sha_256_test_vector_nist_cavs_7)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "8390cf0be07661cc7669aac54ce09a37733a629d45f5d983ef201f9b2d13800e555d9b1097fec3b783d7a50dcb5e2b644b96a1e9463f177cf34906bf388f366db5c2deee04a30e283f764a97c3b377a034fefc22c259214faa99babaff160ab0aaa7e2ccb0ce09c6b32fe08cbc474694375aba703fadbfa31cf685b30a11c57f3cf4edd321e57d3ae6ebb1133c8260e75b9224fa47a2bb205249add2e2e62f817491482ae152322be0900355cdcc8d42a98f82e961a0dc6f537b7b410eff105f59673bfb787bf042aa071f7af68d944d27371c64160fe9382772372516c230c1f45c0d6b6cca7f274b394da9402d3eafdf733994ec58ab22d71829a98399574d4b5908a447a5a681cb0dd50a31145311d92c22a16de1ead66a5499f2dceb4cae694772ce90762ef8336afec653aa9b1a1c4820b221136dfce80dce2ba920d88a530c9410d0a4e0358a3a11052e58dd73b0b179ef8f56fe3b5a2d117a73a0c38a1392b6938e9782e0d86456ee4884e3c39d4d75813f13633bc79baa07c0d2d555afbf207f52b7dca126d015aa2b9873b3eb065e90b9b065a5373fe1fb1b20d594327d19fba56cb81e7b6696605ffa56eba3c27a438697cc21b201fd7e09f18deea1b3ea2f0d1edc02df0e20396a145412cd6b13c32d2e605641c948b714aec30c0649dc44143511f35ab0fd5dd64c34d06fe86f3836dfe9edeb7f08cfc3bd40956826356242191f99f53473f32b0cc0cf9321d6c92a112e8db90b86ee9e87cc32d0343db01e32ce9eb782cb24efbbbeb440fe929e8f2bf8dfb1550a3a2e742e8b455a3e5730e9e6a7a9824d17acc0f72a7f67eae0f0970f8bde46dcdefaed3047cf807e7f00a42e5fd11d40f5e98533d7574425b7d2bc3b3845c443008b58980e768e464e17cc6f6b3939eee52f713963d07d8c4abf02448ef0b889c9671e2f8a436ddeeffcca7176e9bf9d1005ecd377f2fa67c23ed1f137e60bf46018a8bd613d038e883704fc26e798969df35ec7bbc6a4fe46d8910bd82fa3cded265d0a3b6d399e4251e4d8233daa21b5812fded6536198ff13aa5a1cd46a5b9a17a4ddc1d9f85544d1d1cc16f3df858038c8e071a11a7e157a85a6a8dc47e88d75e7009a8b26fdb73f33a2a70f1e0c259f8f9533b9b8f9af9288b7274f21baeec78d396f8bacdcc22471207d9b4efccd3fedc5c5a2214ff5e51c553f35e21ae696fe51e8df733a8e06f50f419e599e9f9e4b37ce643fc810faaa47989771509d69a110ac916261427026369a21263ac4460fb4f708f8ae28599856db7cb6a43ac8e03d64a9609807e76c5f312b9d1863bfa304e8953647648b4f4ab0ed995e" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "4109cdbec3240ad74cc6c37f39300f70fede16e21efc77f7865998714aad0b5e" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_sha_384_test_vector_nist_cavs_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_sha_384_test_vector_nist_cavs_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "ab" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "fb94d5be118865f6fcbc978b825da82cff188faec2f66cb84b2537d74b4938469854b0ca89e66fa2e182834736629f3d" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_sha_384_test_vector_nist_cavs_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "7c27" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "3d80be467df86d63abb9ea1d3f9cb39cd19890e7f2c53a6200bedc5006842b35e820dc4e0ca90ca9b97ab23ef07080fc" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_sha_384_test_vector_nist_cavs_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "31f5ca" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "78d54b943421fdf7ba90a7fb9637c2073aa480454bd841d39ff72f4511fc21fb67797b652c0c823229342873d3bef955" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_sha_384_test_vector_nist_cavs_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "7bdee3f8" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "8bdafba0777ee446c3431c2d7b1fbb631089f71d2ca417abc1d230e1aba64ec2f1c187474a6f4077d372c14ad407f99a" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_sha_384_test_vector_nist_cavs_6)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "8f05604915" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "504e414bf1db1060f14c8c799e25b1e0c4dcf1504ebbd129998f0ae283e6de86e0d3c7e879c73ec3b1836c3ee89c2649" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_sha_384_test_vector_nist_cavs_7)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "665da6eda214" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "4c022f112010908848312f8b8f1072625fd5c105399d562ea1d56130619a7eac8dfc3748fd05ee37e4b690be9daa9980" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_sha_384_test_vector_nist_cavs_8)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "7f46ce506d593c4ed53c82edeb602037e0485befbee03f7f930fe532d18ff2a3f5fd6076672c8145a1bf40dd94f7abab47c9ae71c234213d2ad1069c2dac0b0ba15257ae672b8245960ae55bd50315c0097daa3a318745788d70d14706910809ca6e396237fe4934fa46f9ce782d66606d8bd6b2d283b1160513ce9c24e9f084b97891f99d4cdefc169a029e431ca772ba1bba426fce6f01d8e286014e5acc66b799e4db62bd4783322f8a32ff78e0de3957df50ce10871f4e0680df4e8ca3960af9bc6f4efa8eb3962d18f474eb178c3265cc46b8f2ff5ab1a7449fea297dfcfabfa01f28abbb7289bb354b691b5664ec6d098af51be19947ec5ba7ebd66380d1141953ba78d4aa5401679fa7b0a44db1981f864d3535c45afe4c61183d5b0ad51fae71ca07e34240283959f7530a32c70d95a088e501c230059f333b0670825009e7e22103ef22935830df1fac8ef877f5f3426dd54f7d1128dd871ad9a7d088f94c0e8712013295b8d69ae7623b880978c2d3c6ad26dc478f8dc47f5c0adcc618665dc3dc205a9071b2f2191e16cac5bd89bb59148fc719633752303aa08e518dbc389f0a5482caaa4c507b8729a6f3edd061efb39026cecc6399f51971cf7381d605e144a5928c8c2d1ad7467b05da2f202f4f3234e1aff19a0198a28685721c3d2d52311c721e3fdcbaf30214cdc3acff8c433880e104fb63f2df7ce69a97857819ba7ac00ac8eae1969764fde8f68cf8e0916d7e0c151147d4944f99f42ae50f30e1c79a42d2b6c5188d133d3cbbf69094027b354b295ccd0f7dc5a87d73638bd98ebfb00383ca0fa69cb8dcb35a12510e5e07ad8789047d0b63841a1bb928737e8b0a0c33254f47aa8bfbe3341a09c2b76dbcefa67e30df300d34f7b8465c4f869e51b6bcfe6cf68b238359a645036bf7f63f02924e087ce7457e483b6025a859903cb484574aa3b12cf946f32127d537c33bee3141b5db96d10a148c50ae045f287210757710d6846e04b202f79e87dd9a56bc6da15f84a77a7f63935e1dee00309cd276a8e7176cb04da6bb0e9009534438732cb42d008008853d38d19beba46e61006e30f7efd1bc7c2906b024e4ff898a1b58c448d68b43c6ab63f34f85b3ac6aa4475867e51b583844cb23829f4b30f4bdd817d88e2ef3e7b4fc0a624395b05ec5e8686082b24d29fef2b0d3c29e031d5f94f504b1d3df9361eb5ffbadb242e66c39a8094cfe62f85f639f3fd65fc8ae0c74a8f4c6e1d070b9183a434c722caaa0225f8bcd68614d6f0738ed62f8484ec96077d155c08e26c46be262a73e3551698bd70d8d5610cf37c4c306eed04ba6a040a9c3e6d7e15e8acda17f477c2484cf5c56b813313927be8387b1024f995e98fc87f1029091c01424bdc2b296c2eadb7d25b3e762a2fd0c2dcd1727ddf91db97c5984305265f3695a7f5472f2d72c94d68c27914f14f82aa8dd5fe4e2348b0ca967a3f98626a091552f5d0ffa2bf10350d23c996256c01fdeffb2c2c612519869f877e4929c6e95ff15040f1485e22ed14119880232fef3b57b3848f15b1766a5552879df8f06" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "cba9e3eb12a6f83db11e8a6ff40d1049854ee094416bc527fea931d8585428a8ed6242ce81f6769b36e2123a5c23483e" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_sha_512_test_vector_nist_cavs_1)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_sha_512_test_vector_nist_cavs_2)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "8f" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "e4cd2d19931b5aad9c920f45f56f6ce34e3d38c6d319a6e11d0588ab8b838576d6ce6d68eea7c830de66e2bd96458bfa7aafbcbec981d4ed040498c3dd95f22a" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_sha_512_test_vector_nist_cavs_3)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "e724" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "7dbb520221a70287b23dbcf62bfc1b73136d858e86266732a7fffa875ecaa2c1b8f673b5c065d360c563a7b9539349f5f59bef8c0c593f9587e3cd50bb26a231" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_sha_512_test_vector_nist_cavs_4)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "de4c90" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "33ce98281045a5c4c9df0363d8196f1d7dfcd5ee46ac89776fd8a4344c12f123a66788af5bd41ceff1941aa5637654b4064c88c14e00465ab79a2fc6c97e1014" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_sha_512_test_vector_nist_cavs_5)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "a801e94b" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "dadb1b5a27f9fece8d86adb2a51879beb1787ff28f4e8ce162cad7fee0f942efcabbf738bc6f797fc7cc79a3a75048cd4c82ca0757a324695bfb19a557e56e2f" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_sha_512_test_vector_nist_cavs_6)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "94390d3502" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "b6175c4c4cccf69e0ce5f0312010886ea6b34d43673f942ae42483f9cbb7da817de4e11b5d58e25a3d9bd721a22cdffe1c40411cc45df1911fa5506129b69297" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_sha_512_test_vector_nist_cavs_7)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "49297dd63e5f" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "1fcc1e6f6870859d11649f5e5336a9cd16329c029baf04d5a6edf257889a2e9522b497dd656bb402da461307c4ee382e2e89380c8e6e6e7697f1e439f650fa94" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA4_C

        FCT_TEST_BGN(generic_multi_step_sha_512_test_vector_nist_cavs_8)
        {
            char md_name[100];
            unsigned char src_str[10000];
            unsigned char hash_str[10000];
            unsigned char output[100];
            int src_len;
            const md_info_t *md_info = NULL;
            md_context_t ctx = MD_CONTEXT_T_INIT;
        
            memset(md_name, 0x00, 100);
            memset(src_str, 0x00, 10000);
            memset(hash_str, 0x00, 10000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string(md_name);
            fct_chk( md_info != NULL );
            fct_chk ( 0 == md_init_ctx( &ctx, md_info ) );
        
            src_len = unhexify( src_str, "990d1ae71a62d7bda9bfdaa1762a68d296eee72a4cd946f287a898fbabc002ea941fd8d4d991030b4d27a637cce501a834bb95eab1b7889a3e784c7968e67cbf552006b206b68f76d9191327524fcc251aeb56af483d10b4e0c6c5e599ee8c0fe4faeca8293844a8547c6a9a90d093f2526873a19ad4a5e776794c68c742fb834793d2dfcb7fea46c63af4b70fd11cb6e41834e72ee40edb067b292a794990c288d5007e73f349fb383af6a756b8301ad6e5e0aa8cd614399bb3a452376b1575afa6bdaeaafc286cb064bb91edef97c632b6c1113d107fa93a0905098a105043c2f05397f702514439a08a9e5ddc196100721d45c8fc17d2ed659376f8a00bd5cb9a0860e26d8a29d8d6aaf52de97e9346033d6db501a35dbbaf97c20b830cd2d18c2532f3a59cc497ee64c0e57d8d060e5069b28d86edf1adcf59144b221ce3ddaef134b3124fbc7dd000240eff0f5f5f41e83cd7f5bb37c9ae21953fe302b0f6e8b68fa91c6ab99265c64b2fd9cd4942be04321bb5d6d71932376c6f2f88e02422ba6a5e2cb765df93fd5dd0728c6abdaf03bce22e0678a544e2c3636f741b6f4447ee58a8fc656b43ef817932176adbfc2e04b2c812c273cd6cbfa4098f0be036a34221fa02643f5ee2e0b38135f2a18ecd2f16ebc45f8eb31b8ab967a1567ee016904188910861ca1fa205c7adaa194b286893ffe2f4fbe0384c2aef72a4522aeafd3ebc71f9db71eeeef86c48394a1c86d5b36c352cc33a0a2c800bc99e62fd65b3a2fd69e0b53996ec13d8ce483ce9319efd9a85acefabdb5342226febb83fd1daf4b24265f50c61c6de74077ef89b6fecf9f29a1f871af1e9f89b2d345cda7499bd45c42fa5d195a1e1a6ba84851889e730da3b2b916e96152ae0c92154b49719841db7e7cc707ba8a5d7b101eb4ac7b629bb327817910fff61580b59aab78182d1a2e33473d05b00b170b29e331870826cfe45af206aa7d0246bbd8566ca7cfb2d3c10bfa1db7dd48dd786036469ce7282093d78b5e1a5b0fc81a54c8ed4ceac1e5305305e78284ac276f5d7862727aff246e17addde50c670028d572cbfc0be2e4f8b2eb28fa68ad7b4c6c2a239c460441bfb5ea049f23b08563b4e47729a59e5986a61a6093dbd54f8c36ebe87edae01f251cb060ad1364ce677d7e8d5a4a4ca966a7241cc360bc2acb280e5f9e9c1b032ad6a180a35e0c5180b9d16d026c865b252098cc1d99ba7375ca31c7702c0d943d5e3dd2f6861fa55bd46d94b67ed3e52eccd8dd06d968e01897d6de97ed3058d91dd" );
            
            fct_chk ( 0 == md_starts( &ctx ) );
            fct_chk ( ctx.md_ctx != NULL );
            fct_chk ( 0 == md_update( &ctx, src_str, src_len ) );
            fct_chk ( 0 == md_finish( &ctx, output ) );
            fct_chk ( 0 == md_free_ctx( &ctx ) );
            
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "8e4bc6f8b8c60fe4d68c61d9b159c8693c3151c46749af58da228442d927f23359bd6ccd6c2ec8fa3f00a86cecbfa728e1ad60b821ed22fcd309ba91a4138bc9" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */

#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_sha1_hash_file_1)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_1", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "d21c965b1e768bd7a6aa6869f5f821901d255f9f" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_sha1_hash_file_2)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_2", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "353f34271f2aef49d23a8913d4a6bd82b2cecdc6" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_sha1_hash_file_3)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_3", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "93640ed592076328096270c756db2fba9c486b35" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_sha1_hash_file_4)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha1", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_4", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "da39a3ee5e6b4b0d3255bfef95601890afd80709" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA2_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_sha_224_hash_file_1)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_1", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "8606da018870f0c16834a21bc3385704cb1683b9dbab04c5ddb90a48" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA2_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_sha_224_hash_file_2)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_2", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "733b2ab97b6f63f2e29b9a2089756d81e14c93fe4cc9615c0d5e8a03" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA2_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_sha_224_hash_file_3)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_3", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "e1df95867580e2cc2100e9565bf9c2e42c24fe5250c19efe33d1c4fe" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA2_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_sha_224_hash_file_4)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha224", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_4", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA2_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_sha_256_hash_file_1)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_1", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "975d0c620d3936886f8a3665e585a3e84aa0501f4225bf53029710242823e391" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA2_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_sha_256_hash_file_2)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_2", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "11fcbf1baa36ca45745f10cc5467aee86f066f80ba2c46806d876bf783022ad2" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA2_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_sha_256_hash_file_3)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_3", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "9ae4b369f9f4f03b86505b46a5469542e00aaff7cf7417a71af6d6d0aba3b70c" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA2_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_sha_256_hash_file_4)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha256", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_4", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA2_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA4_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_sha_384_hash_file_1)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_1", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "e0a3e6259d6378001b54ef82f5dd087009c5fad86d8db226a9fe1d14ecbe33a6fc916e3a4b16f5f286424de15d5a8e0e" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA4_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_sha_384_hash_file_2)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_2", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "eff727afc8495c92e2f370f97a317f93c3350324b0646b0f0e264708b3c97d3d332d3c5390e1e47130f5c92f1ef4b9cf" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA4_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_sha_384_hash_file_3)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_3", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "6fc10ebda96a1ccf61777cac72f6034f92533d42052a4bf9f9d929c672973c71e5aeb1213268043c21527ac0f7f349c4" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA4_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_sha_384_hash_file_4)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha384", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_4", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA4_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_sha_512_hash_file_1)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_1", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "d8207a2e1ff2b424f2c4163fe1b723c9bd42e464061eb411e8df730bcd24a7ab3956a6f3ff044a52eb2d262f9e4ca6b524092b544ab78f14d6f9c4cc8ddf335a" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA4_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_sha_512_hash_file_2)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_2", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "ecbb7f0ed8a702b49f16ad3088bcc06ea93451912a7187db15f64d93517b09630b039293aed418d4a00695777b758b1f381548c2fd7b92ce5ed996b32c8734e7" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA4_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_sha_512_hash_file_3)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_3", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "7ccc9b2da71ffde9966c3ce44d7f20945fccf33b1fade4da152b021f1afcc7293382944aa6c09eac67af25f22026758e2bf6bed86ae2a43592677ee50f8eea41" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_SHA4_C
#ifdef POLARSSL_FS_IO

        FCT_TEST_BGN(generic_sha_512_hash_file_4)
        {
            char md_name[100];
            unsigned char hash_str[1000];
            unsigned char output[100];
            const md_info_t *md_info = NULL;
        
            memset(md_name, 0x00, 100);
            memset(hash_str, 0x00, 1000);
            memset(output, 0x00, 100);
        
            strncpy( (char *) md_name, "sha512", 100 );
            md_info = md_info_from_string( md_name );
            fct_chk( md_info != NULL );
        
            md_file( md_info, "data_files/hash_file_4", output);
            hexify( hash_str, output, md_get_size(md_info) );
        
            fct_chk( strcmp( (char *) hash_str, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SHA4_C */
#endif /* POLARSSL_FS_IO */

    }
    FCT_SUITE_END();

#endif /* POLARSSL_MD_C */

}
FCT_END();

