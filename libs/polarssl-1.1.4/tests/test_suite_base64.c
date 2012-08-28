#include "fct.h"

#include <polarssl/base64.h>

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
#ifdef POLARSSL_BASE64_C


    FCT_SUITE_BGN(test_suite_base64)
    {

        FCT_TEST_BGN(test_case_base64_encode_1)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            size_t len = 1000;
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
        
            strcpy( (char *) src_str, "" );
            fct_chk( base64_encode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_encode_2)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            size_t len = 1000;
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
        
            strcpy( (char *) src_str, "f" );
            fct_chk( base64_encode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "Zg==" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_encode_3)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            size_t len = 1000;
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
        
            strcpy( (char *) src_str, "fo" );
            fct_chk( base64_encode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "Zm8=" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_encode_4)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            size_t len = 1000;
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
        
            strcpy( (char *) src_str, "foo" );
            fct_chk( base64_encode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "Zm9v" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_encode_5)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            size_t len = 1000;
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
        
            strcpy( (char *) src_str, "foob" );
            fct_chk( base64_encode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "Zm9vYg==" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_encode_6)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            size_t len = 1000;
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
        
            strcpy( (char *) src_str, "fooba" );
            fct_chk( base64_encode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "Zm9vYmE=" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_encode_7)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            size_t len = 1000;
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
        
            strcpy( (char *) src_str, "foobar" );
            fct_chk( base64_encode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "Zm9vYmFy" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_decode_1)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            size_t len = 1000;
            int res; 
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            
            strcpy( (char *) src_str, "" );
            fct_chk( res = base64_decode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_decode_2)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            size_t len = 1000;
            int res; 
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            
            strcpy( (char *) src_str, "Zg==" );
            fct_chk( res = base64_decode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "f" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_decode_3)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            size_t len = 1000;
            int res; 
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            
            strcpy( (char *) src_str, "Zm8=" );
            fct_chk( res = base64_decode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "fo" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_decode_4)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            size_t len = 1000;
            int res; 
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            
            strcpy( (char *) src_str, "Zm9v" );
            fct_chk( res = base64_decode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "foo" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_decode_5)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            size_t len = 1000;
            int res; 
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            
            strcpy( (char *) src_str, "Zm9vYg==" );
            fct_chk( res = base64_decode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "foob" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_decode_6)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            size_t len = 1000;
            int res; 
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            
            strcpy( (char *) src_str, "Zm9vYmE=" );
            fct_chk( res = base64_decode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "fooba" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(test_case_base64_decode_7)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            size_t len = 1000;
            int res; 
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            
            strcpy( (char *) src_str, "Zm9vYmFy" );
            fct_chk( res = base64_decode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "foobar" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base64_encode_buffer_size_just_right)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            size_t len = 9;
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
        
            strcpy( (char *) src_str, "foobar" );
            fct_chk( base64_encode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == 0 );
            if( 0 == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "Zm9vYmFy" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base64_encode_buffer_size_too_small)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            size_t len = 8;
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
        
            strcpy( (char *) src_str, "foobar" );
            fct_chk( base64_encode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == POLARSSL_ERR_BASE64_BUFFER_TOO_SMALL );
            if( POLARSSL_ERR_BASE64_BUFFER_TOO_SMALL == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base64_decode_illegal_character)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            size_t len = 1000;
            int res; 
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            
            strcpy( (char *) src_str, "zm#=" );
            fct_chk( res = base64_decode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == POLARSSL_ERR_BASE64_INVALID_CHARACTER );
            if( POLARSSL_ERR_BASE64_INVALID_CHARACTER == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base64_decode_too_much_equal_signs)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            size_t len = 1000;
            int res; 
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            
            strcpy( (char *) src_str, "zm===" );
            fct_chk( res = base64_decode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == POLARSSL_ERR_BASE64_INVALID_CHARACTER );
            if( POLARSSL_ERR_BASE64_INVALID_CHARACTER == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "" ) == 0 );
            }
        }
        FCT_TEST_END();


        FCT_TEST_BGN(base64_decode_invalid_char_after_equal_signs)
        {
            unsigned char src_str[1000];
            unsigned char dst_str[1000];
            size_t len = 1000;
            int res; 
        
            memset(src_str, 0x00, 1000);
            memset(dst_str, 0x00, 1000);
            
            strcpy( (char *) src_str, "zm=masd" );
            fct_chk( res = base64_decode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == POLARSSL_ERR_BASE64_INVALID_CHARACTER );
            if( POLARSSL_ERR_BASE64_INVALID_CHARACTER == 0 )
            {
                fct_chk( strcmp( (char *) dst_str, "" ) == 0 );
            }
        }
        FCT_TEST_END();

#ifdef POLARSSL_SELF_TEST

        FCT_TEST_BGN(base64_selftest)
        {
            fct_chk( base64_self_test( 0 ) == 0 );
        }
        FCT_TEST_END();
#endif /* POLARSSL_SELF_TEST */

    }
    FCT_SUITE_END();

#endif /* POLARSSL_BASE64_C */

}
FCT_END();

