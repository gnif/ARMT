#include "fct.h"

#include <polarssl/ctr_drbg.h>

int test_offset;
int entropy_func( void *data, unsigned char *buf, size_t len )
{
    unsigned char *p = (unsigned char *) data;
    memcpy( buf, p + test_offset, len );
    test_offset += 32;
    return( 0 );
}

int ctr_drbg_init_entropy_len(
        ctr_drbg_context *ctx,
        int (*f_entropy)(void *, unsigned char *, size_t),
        void *p_entropy,
        const unsigned char *custom,
        size_t len,
        size_t entropy_len );

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
#ifdef POLARSSL_CTR_DRBG_C


    FCT_SUITE_BGN(test_suite_ctr_drbg)
    {

        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue25612800_0)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "c18081a65d44021619b3f180b1c920026a546f0c7081498b6ea662526d51b1cb583bfad5375ffbc9ff46d219c7223e95459d82e1e7229f633169d26b57474fa337c9981c0bfb91314d55b9e91c5a5ee49392cfc52312d5562c4a6effdc10d068" );
            add_init_len = unhexify( add_init, "d254fcff021e69d229c9cfad85fa486c" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "34011656b429008f3563ecb5f2590723" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue25612800_1)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "a7f38c750bd6ff41c4e79f5b7dd3024d58ca3f1f4c096486c4a73c4f74a2410c4c9c5143eb8c09df842ba4427f385bbf65c350b0bf2c87242c7a23c8c2e0e419e44e500c250f6bc0dc25ec0ce929c4ad5ffb7a87950c618f8cee1af4831b4b8e" );
            add_init_len = unhexify( add_init, "7be87545266dadd1d73546c0927afc8d" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "d5b1da77f36ce58510b75dfde71dbd5d" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue25612800_2)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "d20a0e5cdb714f01b48e00bae51909f345af05de13217e5d55fc6c2d705aea550420d9a458594d825b71e16b36130020cf5948fe813462061c1a222d1ff0e1e4b3d21ae8eee31d3260330d668d24ef3c8941b8720e8591b7deec4bd35a3a1f1a" );
            add_init_len = unhexify( add_init, "3771416b162f4d9c5f48a05b7aa73938" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "3cbd7d53ac1772c959311419adad836e" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue25612800_3)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "4df54a483b4510ed76049faae14b962fbb16459d1f6b4f4dbeca85deded6018361223c893f9442719c51eb5695e1304a1c2be8c05d0846b6510a9525a28831a8efcbd82aa50540d7e7864e2b8a42d44380cdc6e02eebb48d0b5a840b7cdd6e04" );
            add_init_len = unhexify( add_init, "f2bad8f7dab3f5886faa1cf6e1f52c87" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "0062d822bc549bea292c37846340789b" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue25612800_4)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "89defd4445061c080e4762afac194b9f79c4bb1ed88c961af41d9d37bd388a1d45c82ca46f404348a2ae5e22ce00aa35ebc7c5051d8800890d44d25284489efcbd1f5e2b16e403f6921f71bbdfcf7b9aeddef65bc92fbd1cb9e4ea389aee5179" );
            add_init_len = unhexify( add_init, "1c5760aa0fd4ce308735b28682b67246" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "3baf81155548afca67d57c503d00a5b4" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue25612800_5)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "2713d74affed98e3433559e17d240288bb1a1790904cd7754cad97007e205a157b8ddca704a3624413f2ec8361ccd85442fb0b7cc60a247f0fd102cef44677321514ea4186d0203ab7387925d0222800ce2078c4588bc50cdfccbc04fbecd593" );
            add_init_len = unhexify( add_init, "b72b9451a5e866e226978623d36b3491" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "047a50890c282e26bfede4c0904f5369" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue25612800_6)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "b160465448894c7d5ee1963bb3e1a2f3f75fcd167ffa332c41c4c91c1830b7c07413bd580302958aa6fa81588ad2b3173698a4afafda468acb368dbbd524207196b9a3be37ac21ba7a072b4c8223492ee18b48551524d5c3449c5c8d3517212e" );
            add_init_len = unhexify( add_init, "91b955a3e7eccd7f07290cba4464baff" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "af2c062fedb98ee599ae1f47fc202071" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue25612800_7)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "38dfbfb52c185acf74de00b5a50f0cd9688286747ab340cfe9ad30d38b390fd2443bfd7ea93941d8262ae0f66b0eab4ff64ba59a2ff940c3c26fda103e0d798dbcaa1318e842143975673af8408b5af48dfbaa56ca4f9ddc87100028b4a95549" );
            add_init_len = unhexify( add_init, "d08114670c4f6016a4cf9d2da3e3a674" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "55030fef65c679ecaffb0dc070bfd4d2" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue25612800_8)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "88fb2a8020e604ea64a620f4704078857062cc97e24604c30de4c70cbf5e5bea0f0db79d16f4db636a2d6cd992c5890389a40cfe93967eac609e5b9f66788944285758547c7136ef2ee3b38724ed340d61763d0d5991ece4924bb72483b96945" );
            add_init_len = unhexify( add_init, "e2af9abe8770e33798a5f05b22057d24" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "a44f0cfa383916811fffb2e0cfc9bfc3" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue25612800_9)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "340def3420b608420d81b4ea8252a3d86d3e1dd7597e6063ed923a73a7b8e981e6079f7f0c42deb9f4ef11d2f3581abadf44b06d882afdc47896777ce8dafd85ec040f7873d0e25c4be709c614a28b708e547266ac8f07f5fdb450d63bc0c999" );
            add_init_len = unhexify( add_init, "ae30f1642753c5cb6e118d7ff5d59f1d" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "c7e7670145573581842bd1f3e0c6e90b" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue25612800_10)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "21d6c822706d1af09e4d233c0ebac7f4ec60c7be2500dd41a85a19b2dc5c7da27f8a82164bd2a644218cb5ac283c547da1064784413eed5ecf32fadd00357abaae81225ac8d0391ead533362cff56798825445d639b0b45e0312aa7047c00b4d" );
            add_init_len = unhexify( add_init, "711ecfe467d6f83bcc82e566729669af" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "d3a0d2c457f5e9d1328a9e1d22b6eaf6" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue25612800_11)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "4ee32f0aeadb3936e17f1aa3b18c10f773def5f83500c2ba96f84408a2521c1258f6be9aa5cee528746629aa2b8118ac41dd98ef1b3de31d26b8c2ad3442081203f5ef21df409df3381fbf2e064fbaec64d731dc93b3218e34bb3b03bfd88373" );
            add_init_len = unhexify( add_init, "f9b22152bc0eff1ebf0bfafeea40aecf" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "86009b14c4906a409abe6ca9b0718cbe" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue25612800_12)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "fa81535670275e8ab74121377cf88a4742dd0d7a99cf06eb9c2b4fe2b03423dbe441201144c22a9fc0ca49f5ef614987a2271cc1089d10ee01b25163c090a1f263797e4f130920cdc3b890a078e8abbb070ded2e8fd717f4389f06ff2c10d180" );
            add_init_len = unhexify( add_init, "5174e76e904ff1471367ccace9c66ed9" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "18d6fcd35457d2678175df36df5e215d" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue25612800_13)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "930c290a797b85d58b52d0d92356436977b2f636f07d5a80c987fb7eea6b750cceb9eb87860547ab4029865a6810fc5c3663c4e369f290994461d2e9c7160a8b5985853bd9088b3e969f988fe6923b3994040eeee09ad353b969d58938237cfe" );
            add_init_len = unhexify( add_init, "73c372f60519e8eca371eaa13fb54f88" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "f62c7cfbe74555744790bcc7930e03c3" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue25612800_14)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "7065d128ddb2fc6ea31f4110b6c0934ed112c51d74a4a0741a0843d8befac22902a01353322674c3d58935144a0f8f171a99dbeab71272ff7518c46cc7ebb573adbf95bff8ec68eeba5e8ec1221655aed8420086bda89c7de34f217dce73ccab" );
            add_init_len = unhexify( add_init, "75ba8ddeef24f9f5b00b426a362c4f02" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "700761857ea2763e8739b8f6f6481d1c" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561280256_0)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "82c80d922c47bbec0f664dd623e22a11a3b84d308351e45e30ee286e89547d22c43e17b3ca0fa08f77eef1001ba696932e9ee890e7aac4661c138e5b5ce36773d3120c35f8c94e0a78ffbf407a63ca435392e17c07461522fdc1f63f037aacff" );
            add_init_len = unhexify( add_init, "14051b57277bc3d3bbae51bdecfb9f5d" );
            add1_len = unhexify( add1, "b70e7c1c4b8e0f1770e05b29a93f9d7a6540f23ab84136b05b161d85e5f19251" );
            add2_len = unhexify( add2, "5a737c128bd69f927f8f3ad68f93f6356d5f4ec0e36b6b50ced43dcd5c44dbc2" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "a4e6c754194a09614994b36ecce33b55" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561280256_1)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "952f3f179cbbda27ebd30f4fc31bf96baccb2adbaa9c090bc0f37044a44e85b3bc668cd3533faaf56b5da9242844d65733f7ac1f55c38b175749b88e18d19672b7bdab54e0ababdd4519fb07e0c25578f64ad40d0beb0a26275d5e2f4906aa70" );
            add_init_len = unhexify( add_init, "4526b268128ea35f8558b4e1d08388f2" );
            add1_len = unhexify( add1, "6b167c7cebea2e585ab974b60c4d305a113102ca8c3dc87651665728c4c675ad" );
            add2_len = unhexify( add2, "a038f1ca1f420eae449791f13be4901bfb91e41e052e02635b1f1817bd8969b1" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "745ec376282e20fd1f9151f7040ed94a" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561280256_2)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "75fd042bfd994de2c92e5aa505945ec93bd7cf366d86a356723fca3c9479ee17fb59c6ca8ba89784d43f06cdad113e5081e02427ee0714439d88dc1a6257fc91d99c1a15e92527847ab10883cc8f471cad8cf0882f5b6d33a846a00dee154012" );
            add_init_len = unhexify( add_init, "c1aafa90f394e0ba9a528032dc6780d3" );
            add1_len = unhexify( add1, "c704164ce80a400cb2f54d1b2d7efa20f32b699fa881bfc7b56cfd7c4bee1ea6" );
            add2_len = unhexify( add2, "f3baff4b6f42c8e75b70c2a72a027b14a99ae49a5a47c7af0f538843c94e1a69" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "7af9113cd607cdb4c6534f401fe4e96c" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561280256_3)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "0c3c6dd706076d6484478347559b495d7ee898c39cde06027bc99f7bf69ce1140ca04602265e1308af6dd6446a1cf151749b22a99e8a05d30cc3ccd00e663bc1bc37e08ee62834fcc52a4bc8c1d6442544187484f81dc729417d5bedfcab5a54" );
            add_init_len = unhexify( add_init, "e6e726b72e7b264a36ec0cd60d4578b5" );
            add1_len = unhexify( add1, "d84b978483c0bd8f8c231d92ea88ac21e6e667215804b15725a7ed32f7fc5dd7" );
            add2_len = unhexify( add2, "9a8971f6c559f7f197c73a94a92f957d1919ad305f4167c56fe729d50e5754a5" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "e16ee5bceca30f1fbcadb5de2d7cfc42" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561280256_4)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "a08ce39f2f671e1f934821a8db9070f39a734a7a20e70307fccca17db15bb4e8a421600df11d1a6e7806a14826739322c8043649ea707180f1d00dea752c2c36398030519465864c4d38163f5b0dd5be07dbc0ae29693ad4a67ca69f28414634" );
            add_init_len = unhexify( add_init, "0272d86db283244eb7ee0ed8c8054b89" );
            add1_len = unhexify( add1, "aa97055cf46ba26465dfb3ef1cf93191625c352768b2d8e34459499a27502e50" );
            add2_len = unhexify( add2, "dddd0007eb29fdf942220e920ca0637db4b91cbf898efd2696576ff6bfacb9d1" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "9db0057e39ca6e0f16e79b4f8a0ed5c7" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561280256_5)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "89af36a1c53f730c1b818b26aa510627b17e6f9da51c8e53930de883b7cc7a3e8c3c463c910646ac3ff08f05bca8e340daf9a322d133ae453fdf7e6860a27ff4495c89875431ba9de3e4f3247cda8c62acc86f7066448f639d8ba8b5249337f8" );
            add_init_len = unhexify( add_init, "4ad8f72a0d0e28a758722b20e3017d7e" );
            add1_len = unhexify( add1, "9d060b7ed63bdb59263c75ebe6a54bf3a4ac9c9926ca8fb49caa905a2651eead" );
            add2_len = unhexify( add2, "016099232dc44bb7cdb492f4955ab1aabc5dc0b5731447cea2eb1d92e41482d1" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "4b658e95adae4bf0c418fded4431c27f" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561280256_6)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "dc8c60dd42c85fed86cb32af035bbde5737526eb07991397c853256f2f0cb311bce70e1c5e32fc3510402d7d7e3de36fa5e584234daf391bc53cc651e001ab7fcf760679b3c82057f9d09bfdcab8e158d4daa63b20c0e1102f7a06bf5a2788dd" );
            add_init_len = unhexify( add_init, "aa19b944c2e1b9d27933bc87322bdf14" );
            add1_len = unhexify( add1, "6b98fec5f7de8098ff9df80f62473c73831edace832a767abf5965ea8bf789ba" );
            add2_len = unhexify( add2, "cc998bd5752f9c96ec35d9658cc8b3833dd6ab80c7accd6777c06c2cf7c01e59" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "fc58833e0e27f7705e4937dd2aadb238" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561280256_7)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "513fb96b6164ece801e52855aad28cb80131e7872d8432d27a974fb62d8d0100bb7ebcb8f5c066e230377a8847d6798c3d8090469b9719a80ac956ac33186b00eb8ca64c5530421f93932bc7c98ee92651e85dab562483bdb189676802726647" );
            add_init_len = unhexify( add_init, "10c8c17a25041e2ef0d3cc80671e4cfe" );
            add1_len = unhexify( add1, "240f36a0a598fe2116ffa682824f25acc35132f137f5221bc0ff05b501f5fd97" );
            add2_len = unhexify( add2, "22a5eb5aa00309a762ab60a8c2647eebe1083f8905104b5d375ed1661b4c8478" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "145a16109ec39b0615a9916d07f0854e" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561280256_8)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "df8bc70e45fe14abb02c1b9a9754c37497fc2f67709edd854196fc4d074b12797ce7cb292f14cb1d6904abf32bf229299db5ccf5a791a3b8cd3e40a64f38f6b57df759a863e09d7676d2f3ff2762cdab221151000dba32a67f38cab93d5b7a55" );
            add_init_len = unhexify( add_init, "cea0c3c12be683c0f27693650a6a3d7d" );
            add1_len = unhexify( add1, "bf2ac545d94e318066ff88f39791a8385e1a8539e99ac4fa5a6b97a4caead9d4" );
            add2_len = unhexify( add2, "846efef8672d256c63aa05a61de86a1bbc6950de8bfb9808d1c1066aef7f7d70" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "8d8f0389d41adcac8ca7b61fc02409c3" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561280256_9)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "51930fb7095edef3fc20aca2a24127f03d3c4b983329e013ad8a35016f581dd7b2d11bafbf971c1fdefd95a0024195e6e90a60ec39b1a8dbe0cb0c3aabf9cf56b662efc722b2dffa6c3be651f199cbc3da2315b4d55aeafd1492283889e1c34f" );
            add_init_len = unhexify( add_init, "1b782af2545352631983dc89945ffc37" );
            add1_len = unhexify( add1, "1b6295986f6fb55dc4c4c19a3dba41066fdc0297d50fb14e9501ba4378d662ed" );
            add2_len = unhexify( add2, "6e66ff63fc457014550b85210a18f00beab765f9e12aa16818f29d1449620d28" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "78dfcb662736a831efaa592153a9aff9" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561280256_10)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "d37403db6f84a7ba162e1cc351fe2e44d674ae8606280c9dac3e3975f30cbe1c9925e502a9804b91aada5cc97b259b90ccb5b8103394d9a28f0709fc9b5ffe9d73ad3672e02064ea68cebe3face5d823ee605c46c173db591135f564558dab4c" );
            add_init_len = unhexify( add_init, "6580f6df5c8de7c4a105c11ed44435c2" );
            add1_len = unhexify( add1, "97486a5e6ce6c6cf9d3f9a313d346cbc34b2bd54db80c5f8d74d6f6939f89519" );
            add2_len = unhexify( add2, "8377fcb52556f9974f1aa325d6e141d7b81355bd160abbc86e0007571b3c1904" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "77031d3474303470dca9336b1692c504" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561280256_11)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "a0de51b8efa44b8245dba31d78f7840b2b7abced4e265b4cd9628eabc6ebbccb0f118dd8cc958b36dc959e22c4a03dafa212eeedec7d25ee6c5961187bee83b1ed3a75c7bdd9d0713b16cc67e68231f4cb274c8f3dfcc7e5d288c426a0d43b8f" );
            add_init_len = unhexify( add_init, "f5303f148d6d6faca90aa88b07ab2ba9" );
            add1_len = unhexify( add1, "8d1fddc11dbad007e9b14679a5599e5e8a836197f14d010f3329d164c02d46d6" );
            add2_len = unhexify( add2, "9ceb6570568455d42a7397f8ca8b8af7a961a33a73770544cca563c04bc919ca" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "9882f0bd1f6129a78b51d108e752b2d9" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561280256_12)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "dbdbef9d217e9051025c321b628c1cc823d508ffdd13fc4edbe8677658a57ef5b64395a6b7d62c0e93dc0956ee0217ec48ae054f1d4680023cc1b2af666efa9e1458cf6b0dae72eef2392e93687bd1fb5f366bb2cdd12937ad09724e39db4189" );
            add_init_len = unhexify( add_init, "5a799c58985aa2898cc8fe8e5bc4a9f8" );
            add1_len = unhexify( add1, "8c179b35739e75719e74f7c3e038bc06eb3e212d6ade85275cfebf12b2dce2a2" );
            add2_len = unhexify( add2, "af617f2e228adde3edaf52a7e5979476dbb9cd2956a1737d93a16563bbbb4888" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "49a04f3b4ef052747c7f4e77c91603e8" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561280256_13)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "bf22b182d39622e941017285adbdfe446c3d1a72601d0e5a15674f3b1b260170b1b2ab6b588a0267d86776a5d4ce80e132d7135a581af75ea6de65153680e28ce35ce78d0917b4932000d62260149e5a3ae72bc250548390b664f53c697dac45" );
            add_init_len = unhexify( add_init, "8f5b51983a8156a529f559ac3afebbf0" );
            add1_len = unhexify( add1, "4cbb5b2d6e666d5dd3dd99b951ea435cae5a75d2e1eb41a48c775829b860e98b" );
            add2_len = unhexify( add2, "a4b4171c2592516404434932ad0a8ee67bd776a03479b507c406405b3d8962bc" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "cab49631733f06e3fb3e0898e5ad22e7" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561280256_14)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "1e50fada1e76a0d243e6f64c36a173ddc1f47a1dab834f5cd492568792958d5be22cce3110c8e8958b47f07b5c63f86b254942361d4d553e47d36103f47cd7f0bbee27d2e238b1d85671afe8284ee1fd2a431a5f69b2df73e95341c3a2e4fe4b" );
            add_init_len = unhexify( add_init, "9f305a77cbaec1ab408cfc0eb89c6cbb" );
            add1_len = unhexify( add1, "c254f3b40e773eb09053b226820f68cafa3458ad403ad36f715245a854752a93" );
            add2_len = unhexify( add2, "699e177b7be3353c45ce7b7a0d573b00087d700a9f2c1cd2e370e05d4ddadc86" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "bb6b02b25a496f29245315f58a16febc" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561282560_0)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "545a783ae97d827ed0b81d9752ad0f7e965f511b1f5dae0f872e9ec37cfe63af86c1d15e153887989b605773b16ad5505e65f617cfa8ef46547c4c3f9d0c4fd0b6e1cff5ca0f1929266fe43ba8f45ad664cfe5e90903a9cb722b42ae8989c148" );
            add_init_len = unhexify( add_init, "e09f65dcffc0d3a4d84bacc41617a4e46ce5184eca011049ab657566f728e4aa28315ffac166ebe50e1269b01c95b3a2" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "1e77d7cc18775fef9a3d3e00903da01b" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561282560_1)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "dde6c0850fe642602eb222ca7371213c598cef8c3e71e0593ea8edb54e1bed130b9b0aebe0893093b950c52f56eb9b338aa4bd01dae030515726ece1bf751660b4a3602da6400e4b94edebba646b5c3d4e64ceea1c4f14b7a19f0142783247df" );
            add_init_len = unhexify( add_init, "056cd44c8847d89da05fbef95e9660d589046b0c02f9b42c17fd8b069f831c73cd896005ec080113589b6f07be6e42ea" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "a790ab939e63555d02ea1e9696051725" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561282560_2)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "6fe09520e26f5abece0fceadc54913c650a9f55725af45a9a5f373d09b9970b8706b9041d0189a204f6a4eb527dfa86584a3bee3265b809c3932ae5e7228194a3cf7592fc9301c833b45a53be32b9caec9f0f91ba86519f12b0b235f68419c1e" );
            add_init_len = unhexify( add_init, "73c72c7dfe138ef4b9817d41b9722b3940762b59bda26b3f6bb8b30583e01d088a29726b71d36ffeebdb387010cb1bb6" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "798d997f46ff7cc4206994085340325e" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561282560_3)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "532960c23c8c8b2146576dde52fadc985134914abf42ca1c5f47206937fda41289ae5d9f935dc4ce45f77cad230a4f345599e3bae4071188324483a0b93593c96d8b6ac6c0d8b52f8795c44171f0d8cd0b1e85dc75ce8abe65d5f25460166ba0" );
            add_init_len = unhexify( add_init, "cdba7c7033c34852b7bc1a6b33edab36f41d563bd0395d1001c02ffc0c42ec8595ed2b5ddabc923372e3b6bb457833fa" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "9d48160aca60f1a82baaa8a7d804a3d8" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561282560_4)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "9216c9a833f81953792260a688eb7c3dfc85565ae6a6033203741a763db056247808e0ecd5ba1fc4549c3a757eba535adc786e810ddaae9a2714d31f5154f2c3ee81108669f1239f4f4efd6e18aabfa2d88f0ac25f4740108f6cfebffeb2d857" );
            add_init_len = unhexify( add_init, "02cef01aca992f60aa12db4b2c441689e4972a6f9deaf3663082afed642c1502b67b42d490af1c52c7e6eaf459882eca" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "d6378bcf43be1ad42da83780c1dab314" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561282560_5)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "80d4741e4e646748bb65e1289f1f9b3c21bffec4d0a666b301f199d76b4a83464583057079b069946b03d6ac81ebf9e6fa8d4081120f18bf58286a0c4de7576f36f3c7c353126f481a065ac28bdf28e13cd0c1e7911db6343c47d613f1750dc6" );
            add_init_len = unhexify( add_init, "d7d80084e9d1fbb9315c3bce1510dbf22cf11fa54177d913a3b04b64cb30957395bd6f3d7e3d866d1be41b29db9ed81d" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "9165a92ed92248b2d237d9f46d39bde8" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561282560_6)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "52df6336f93781115c2a77bd8f99cb717871fe14707947a21f6093dd9205bc378acf61329f8831369b4b1af0a9edfb25d74f5863f26859ad9c920767b113c47ed2690053bf9a2f7c7a67a8d680e08865720b9e9f7b6ae697e3c93e66f24b6ddc" );
            add_init_len = unhexify( add_init, "df5a68d3bede467fd69716f5f8fbac297594b8573921afb864ba76aaa6dd89e83b89e359a5a0dd1aac9b4acb9573d218" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "c542cf248a163bbceee7b9f1453bd90b" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561282560_7)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "aa560af2132cbd0624a69c7a7e733cd59a4f2d4e61d2b830087bd88f30fa792c7e4d3168fa86a10f7619d5b9dcf4f7bb08b350ba6a6bfc0fdfb7ee7aca07260c9a11abe49963c36efaefa94d2978ed09472bf93cc873d0f24c000762bb1402cd" );
            add_init_len = unhexify( add_init, "2945527372ff71edfa5776f55f7e4a247544aa6de974e81b2eba5552843ab6dfa248695f4f3225a43d4bf3672c3a6b2e" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "33af0134eeca279dce5e69c2cda3f3f4" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561282560_8)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "2d42b00248d95d9378a2aece40d636bc1ab22edaaa64daa34335195a9efa4c1b58f13ac184ca2be52e15c3a977abde2aa505243fc106c4ea6f0671fe0f209b106ea8965645af73d8ebb8a80251db2967149c701cfe1d157cc189b03bf1bff1ac" );
            add_init_len = unhexify( add_init, "b30cb767125674f6099a5cf7cb2e4f5b6c1cd1e32ffc1e393b1c5698b52b37f971f12521a7c1ffaaf3233d5391bc4c86" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "1e10eff9ceebc7e5f66e5213cb07fca4" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561282560_9)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "a1ff68a85e437475b1b518821dbaac1730071a4ddd3255361778194fb0cfe3293e38df81527d8b8da15d03acb26467b6b53d7952441b79f95b633f4a979d998fd0417b9193023288b657d30c0cb2dada264addf9d13f1f8ed10b74e2dd2b56b3" );
            add_init_len = unhexify( add_init, "c962a2da4524f08adcdd5ceddc04e669ad6154aee06164645e80c832506b98f9919451c7ec1d3a6a9704f83def8f6e2d" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "58990069b72b7557c234d5caf4334853" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561282560_10)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "207267911c12125cb3012230e4fafd257777ccbfb91653f77e4c1287574f9b79d81af7fb304790349dd457983cc99b48d5f4677ccd979fcc6e545cbf5b5c8b98102c9a89ae354349dbdee31a362d47c7cdae128034c0f4c3e71e298fe1af33c6" );
            add_init_len = unhexify( add_init, "a3cc1fe561d03a055e8eedaa0e713be490c4bd4c6839a5b98c2ac0139bf215bdc46783d2a3e6b9d15d9b7a8bfe15104b" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "ffd1d259acd79111a6fb508181272831" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561282560_11)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "3b9aec9f8bf8495004c5e4e731e5c347988e787caf003f001e68584e3510a6abdedffa15895702c2d57c304300f4f0af80a89bcc36b3cea2f08a0740236b80cfd2ea6e5cfe4144bc4ae09270fb6bc58c313dbaaedc16d643fc0565171f963222" );
            add_init_len = unhexify( add_init, "ecf186071b81e0ed384d4ebfb5bf261b4054e2e6072b51d21dfb6817adc51ff1c8956ff3612767538cdc8d73fade78b3" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "a2d917f5ec39a090b55d51713006e49d" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561282560_12)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "6b1e9d45c2ec598de7527b6414a339f26192fc4e3f5eff4b3a3e2a80ee0f2e9743031804d1be12b3c7ff6fbc222db1d97226890addeef0e1579a860e2279292c2f769416b7068f582f6ffc192ae4c4f1eeb41d5f77f0a612b059c47aef8e3d8e" );
            add_init_len = unhexify( add_init, "3fcedba86089709aa638d00713150df781d4a93e85f155338e90ff537bcbf017f37a2d62259f5d8cc40ddfb041592539" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "aa414799c51957de97c0070fb00eb919" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561282560_13)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "6d170cf472ea07da6146a7087ed15d3f5b6ad72b8c99e46bae3b89e49a6e63467199ee16096516c2362dbd181bf5343a29fd0932d72eeb019fc3bfea3a3b01ffc2b985e341cfb6479d9dc71e2197b5cffc402587182e5fe93b5a8cf75eac2e42" );
            add_init_len = unhexify( add_init, "f4c45fb8f58b7ebf73a0cd81c6a26686977558d4b8bf1cedfc6bd3754de6aaed5008fd72208437c54d8feb9a16ce3224" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "f557f627688fe63c119cf0f25274aa74" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue2561282560_14)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "c08a6f9797ea668cd14ba6338cb5d23c0921e637e66a96259f78e33e45aafd035edb44394cb459453b9b48beac1e32d3b6f281473cda42fb6fd6c6b9858e7a4143d81bfc2faf4ef4b632c473be50a87b982815be589a91ca750dc875a0808b89" );
            add_init_len = unhexify( add_init, "7120742a7807b66c5a9b50995d5494a5b9451bb795393c0d8a30ae665879269408f8297d49ab87410a7f16a65a54b1cb" );
            add1_len = unhexify( add1, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "521973eac38e81de4e41ccc35db6193d" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue256128256256_0)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "6168fc1af0b5956b85099b743f1378493b85ec93133ba94f96ab2ce4c88fdd6a0b23afdff162d7d34397f87704a84220bdf60fc1172f9f54bb561786680ebaa9bf6c592a0d440fae9a5e0373d8a6e1cf25613824869e53e8a4df56f406079c0f" );
            add_init_len = unhexify( add_init, "add2bbbab76589c3216c55332b36ffa46ecae72072d3845a32d34b2472c4632b9d12240c23268e8316370bd1064f686d" );
            add1_len = unhexify( add1, "7e084abbe3217cc923d2f8b07398ba847423ab068ae222d37bce9bd24a76b8de" );
            add2_len = unhexify( add2, "946bc99fab8dc5ec71881d008c8968e4c8077736176d7978c7064e99042829c3" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "224ab4b8b6ee7db19ec9f9a0d9e29700" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue256128256256_1)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "4db8e8a27fe7a0378e37d4cc01b6a465d34be91f48c52fdc1023ef2ea1241082f522805bc8777fda6c10e3d441b58f648edcd7d4df3df8c8a398d7b005c4fd6f41c9b033bd38fc5f577069251529b58273f6a9175feb3978798fdeb78a043232" );
            add_init_len = unhexify( add_init, "8964ebde61f0c4e23f8e91244ae9682ed0b17e424edd4c025b461a2d209a538583f29465df3f89cf04f703b771ff5c90" );
            add1_len = unhexify( add1, "5eb3fb44784f181852d80fcf7c2e3b8414ae797f7b9b013b59cf86b9d3a19006" );
            add2_len = unhexify( add2, "3eec358f7f9e789e4ad5a78dd73987addbf3ae5b06d826cec2d54425289dc9af" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "9a66c015d2550e3f78c44b901075fabb" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue256128256256_2)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "7338521e8e127e70da259b37f5f5cdf83079bdb4024234b8ceecfba8d8c3f1c8510ff91f3bd08f2c54f11b534048a320a15ba0fccec8da34d4ef7f49ade4847814c859831907992d0adab27046324d4d9a853eb986b8de25b34ea74eb3d11048" );
            add_init_len = unhexify( add_init, "98784aa794df5400890e6803f06d886aeb0833b1fea28a5f7952397aa21092ceafdb9194079f3609bc68233147c778e7" );
            add1_len = unhexify( add1, "b14c5314aac11cb43f45730e474b84fbf5d1480d94d0699b80e3570f6636aa72" );
            add2_len = unhexify( add2, "d6208912348236feee1d258092283dd9db75899769dd109cc2f0f26d88dcc6bf" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "5ec75fdd1ed3a742328e11344784b681" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue256128256256_3)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "c4da56f4239fde0bc49b1d852cb36c80205f9e99e5995a80be04bbbba15f25b8d054c397a34cff1326a71f0acc4f7942795cabc3fa46339dc54b4bf7f11c095af8503004d97c485acec8815d1404674592c896ecfabefcbf222f4fe5a3ced0af" );
            add_init_len = unhexify( add_init, "fe9b7df306c4ccd02afd6142c6650418325617945147de436a55e78aa45866116d6678e013a0e2c5a13e0d01fbd84039" );
            add1_len = unhexify( add1, "086d09a6ee20c69bf5c054ebc6250f06097c8da1a932fb3d4b1fb5f40af6268a" );
            add2_len = unhexify( add2, "44e64b14c49ebb75c536329bb41ab198848849ca121c960db99f7b26330b1f6d" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "7aa3a7e159d194399fc8ef9eb531a704" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue256128256256_4)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "a6b5dd5f1bad95331caae5852be50a26267af655c98feb8b66c45a8ae2ddfca270ab0d8023e43e6e22a7b5904d63482f045e85556b9c105cde0f3eb7b1fff1026086c80b195196803b5f664362b659578894d6551fb7c4566eec02202fdc298f" );
            add_init_len = unhexify( add_init, "c0d47ee2328185df2c299d270e11fee26df753a5b4f899fdc0dff79eb50748232f9f79cf3f5e9bd4a26a48e743843b02" );
            add1_len = unhexify( add1, "3b575d028046e7f6005dfcdfcdcf03ff77a9cacd2516bcdff7f3601a9a951317" );
            add2_len = unhexify( add2, "f13b58daed46f5bf3c62b518ab5c508dd2bc3e33d132939049421ff29c31c4f0" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "8469dfa89453d1481abedd6cc62e4e44" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue256128256256_5)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "7e3dca20a7a977b6616a684e309015cf6a37edd0d85819fe91d074c915b0c9540a8aa486f58685b064851d6164150b1c1b0e2e545c6358d28b2f5263b2fd12c503d271ab6de76d4fa4c604cae469335840328008d8ce5545586b9ea6b21da4f9" );
            add_init_len = unhexify( add_init, "a0db812a939fbf3942b00be018cff4578b9fb62629c766a50f3518fe634100b1cbc4244ae843fe32125c53b653705457" );
            add1_len = unhexify( add1, "554b297bc32866a52884fabfc6d837690de30467b8f9158b258869e6f4ed0831" );
            add2_len = unhexify( add2, "4f688cba5908e0699b33b508847f7dac32f233e6f02cf093efdacae74259f3b6" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "9696dd6ed5875cdef4a918a6686455a8" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue256128256256_6)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "efcf7536f32932526fe82b3a2333508404727878723fc09cbd902581d82463cf6acf1ddf4217ea6404469193e8db0e7e8c864ae655b49c6a095f80f1ab16985453f0fb729c119d8a3b820034626a93b1f70eb99b6cd8c990dda34a1c6a4b6eea" );
            add_init_len = unhexify( add_init, "ff6cd20443a32c9e938f2a617bbb969ba54040b12723b0d452a669b584ba16ffaacbe38af62b5a62e0c67d165d022344" );
            add1_len = unhexify( add1, "8d412208091b987ee0781ff679c50dbab9ef389156f570f27aaf3e699bdade48" );
            add2_len = unhexify( add2, "501381ce5e7718c92ee73e9c247965dd5f0bbde013c4b5e625e9af8907e40566" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "4f323934adb8a2096f17d5c4d7444078" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue256128256256_7)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "bfb0931b05a3fe232614e1b1c3060b3b07fb75d23ac10190a47a7245a6ecad5f3834e6727b75acc37e9d512d01a4a9cef6cb17eb97e4d1d7c1df572296972f0437a89c19894f721cbe085cf3b89767291a82b999bf3925357d860f181a3681ce" );
            add_init_len = unhexify( add_init, "bd14779153ed9696d3e5143c50b2050b6acd3ea2f8b670ef0e5f4bedf01705727bf9e64ae859214abe6ef497163f0236" );
            add1_len = unhexify( add1, "0b5dc1cdfc40cfdc225798da773411dc9a8779316ceb18d1e8f13809466c6366" );
            add2_len = unhexify( add2, "843eb7297570e536b5760c3158adb27c0c426c77d798c08314f53b59aa72d08b" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "1e703f3122455a40536c39f9ea3ceaa6" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue256128256256_8)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "a5b15cb1e039d7bbe2db80a32d4f402c7d3c59a45b05255401d1122770dbdb9894841964d5cadc9ae9af007d63e870d0510078885ca402bd222f16d2d27892e23292b65cf370b15d5e5a739ddd13e3e27f7c2e2b945f8e21897c3bbf05d8b043" );
            add_init_len = unhexify( add_init, "64b155fd4b8634663a7e8a602e2b9fe2477be74692643ccfd0b316a025ea6f1fc0dfd0833248cb011082be36cba3c5d1" );
            add1_len = unhexify( add1, "aea2fe995be77dfdca6ebaa1c05ba4c84d0e6b9a87905c398a3dfe08aeb26d38" );
            add2_len = unhexify( add2, "f4e9e7eb0eea4e2d419de6ad2909d36ec06c79097884bf98981e86dedae366ba" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "4a28955dc97936b1c0aed0751a1afed5" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue256128256256_9)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "d4e0347c2158b882eb1e165f7f2aa1324d6606fe259ca730b2a3367435cb93b89108e49bd97355215063f63e78e8926b264c8a97571fd4d55882364915b7bd544254c25c2b67cdd979737c7811bcdeef5b052d8fe05a89b3291ef669d5579a61" );
            add_init_len = unhexify( add_init, "e6c08e8b8d8e418477087911610096f7e0422083a376a77198e9c60fb2dc8c14aff33d7835878b65322f1561738b1ebb" );
            add1_len = unhexify( add1, "6607541177bc0c5f278c11cb2dcb187fc9f2c9a9e8eefa657ba92dee12d84b07" );
            add2_len = unhexify( add2, "7a439c8593b927867cfa853949e592baea0eeb394b0e2fe9ab0876243b7e11e2" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "420888122f2e0334757c4af87bbc28a4" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue256128256256_10)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "a21cf567362fed0edddfd0b1c2d85ff6d2db5484fca8bf90a82da2ab76efcac9286e417628496f37effda150ef4912125aac68aac72e6f900a70192d4ef0b4cc4e9419c93ffb245965ae30c5f8abe20f732d76080bde5a1c6b3f075eb35622d1" );
            add_init_len = unhexify( add_init, "4413ff775c9b7d9a3003e0b727e34554e0f615471d52aeb4a059777b372d60332a1a4bcaf906e598581bc5a369b2c933" );
            add1_len = unhexify( add1, "b924d145fc3ecd76f000f12638ef0a49a5d4cf887aa93fc9e5c536febc454f2d" );
            add2_len = unhexify( add2, "73dbb40b257e6598744f9107c8e7ff51a080407fc9e80d39d9a4db94f167c116" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "84457ea753771ad7c97ce9c03ab08f43" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue256128256256_11)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "c5a63c886af7ed7496473a6ae2f27f056c7e61c9aca8c5d095af11b2efe1a6b43344f92b37c7b6977ddbef1273e9511d9305fcbe7f32bc6a62f28d34841350362d2717dd00467224a35985b9fecc2739acd198743849dbfa97f458e2e7d6b1dc" );
            add_init_len = unhexify( add_init, "5e409d56afb6940f9ffa45e0f92ef4972acedd3557b8e0f5418e302f2720ae5289294176045ad3096ea68db634cf5597" );
            add1_len = unhexify( add1, "7fda133a23e929b17548a05013ff9c7085c5af9c979057b8f961ba7514509ff3" );
            add2_len = unhexify( add2, "bd061292b6bc3d3e71ed01af091f0169f70f23862efccd9e76345ff607dff3ec" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "75b35dab3ad5e35c10ee39529a7f840f" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue256128256256_12)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "0a6155ff422ff6ae9814f81bf353bd3454d0c9892f9f3d730dcd8c87626f813cbe1dff1922fe73e4a319be53f4ec05e965c27f239b1e51869069a7e7cdd916fc1fd6f640bfe4b761a8040f8db37fb5ee7508e7d226c7695fb2a8bd791fe49ef2" );
            add_init_len = unhexify( add_init, "ed2a52169791d7c7d332cf258ea4847c359335f9a6839ee767a8f76800ba28e94858cc9b7f526e62a93603fa2b1caa6b" );
            add1_len = unhexify( add1, "14073a1b4f07f3b594fa43d0c8781b8089dd2d9b8ad266e0321aaa6b71a0d058" );
            add2_len = unhexify( add2, "4247fc6886e8657b84369cf14469b42aa371d57d27093ee724f87bf20fa9e4e6" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "f2aea2bc23e7c70f4ee2f7b60c59d24d" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue256128256256_13)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "223d49f99a56cfcf2eb8cca39a8a82ee306c6272d521257f3d7d2a87699111e442fc55a399994d57373141f2207d43a8bbc1e086d67343b7dc2a891853c860fe43fb6be32cf035aca582bf5590cb5001b09b4976ea617fa7bd56da81fdef2df9" );
            add_init_len = unhexify( add_init, "f0d3a46501da7ab23d8688725f53f4289ce3bfa627646fe301533ec585f866caafb8131e95460566270f68cd25e1f153" );
            add1_len = unhexify( add1, "7d12673cad5ad5003400fb94547e2b987e934acf6b930c0e7aec72634bfb8388" );
            add2_len = unhexify( add2, "e8583b9983b3ac589a6bb7a8405edfc05d7aa5874a8643f9ac30a3d8945a9f96" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "ce72c0ea0e76be6bc82331c9bddd7ffb" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dftrue256128256256_14)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "cdac62b5e4ccee8609b1f4b7a8733e69068c71219b6292ecb318b9d3479516807af280cfa20e455d5e96eb6794a3b963957f3c099fd1e1199706d36a06011836af890f3b7b15cda6346a06fdd0f194de40bfbec12b021b02eeabaa34d35b30a3" );
            add_init_len = unhexify( add_init, "1e4644df1d01f9a0f31d1d0c67bc9fb9a1ee2223fbfb25520d3881cde2b183b73fe1a8cc5f17796cf22aaaed57607420" );
            add1_len = unhexify( add1, "8169251ea55cce534c6efd0e8a2956d32ed73be71d12477cea8e0f1ab8251b50" );
            add2_len = unhexify( add2, "865d14cb37dd160a3f02f56ac32738f9e350da9e789a1f280ee7b7961ec918a7" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
            ctr_drbg_set_prediction_resistance( &ctx, CTR_DRBG_PR_ON );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "ff11ba8349daa9b9c87cf6ab4c2adfd7" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_0)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "5a194d5e2b31581454def675fb7958fec7db873e5689fc9d03217c68d8033820f9e65e04d856f3a9c44a4cbdc1d00846f5983d771c1b137e4e0f9d8ef409f92e" );
            add_init_len = unhexify( add_init, "1b54b8ff0642bff521f15c1c0b665f3f" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "a054303d8a7ea9889d903e077c6f218f" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_1)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "93b7055d7888ae234bfb431e379069d00ae810fbd48f2e06c204beae3b0bfaf091d1d0e853525ead0e7f79abb0f0bf68064576339c3585cfd6d9b55d4f39278d" );
            add_init_len = unhexify( add_init, "90bc3b555b9d6b6aeb1774a583f98cad" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "aaf27fc2bf64b0320dd3564bb9b03377" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_2)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "58364ceefad37581c518b7d42ac4f9aae22befd84cbc986c08d1fb20d3bd2400a899bafd470278fad8f0a50f8490af29f938471b4075654fda577dad20fa01ca" );
            add_init_len = unhexify( add_init, "4a2a7dcbde58b8b3c3f4697beb67bba2" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "20c5117a8aca72ee5ab91468daf44f29" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_3)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "2f044b8651e1c9d99317084cc6c4fa1f502dd62466a57d4b88bc0d703cabc562708201ac19cdb5cf918fae29c009fb1a2cf42fd714cc9a53ca5acb715482456a" );
            add_init_len = unhexify( add_init, "911faab1347ae2b3093a607c8bc77bfe" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "aae0c0ac97f53d222b83578a2b3dd05d" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_4)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "77d0f0efbc7ca794a51dff96e85b8e7dfd4875fbfb6e5593ae17908bfbddc313e051cb7d659c838180d834fdd987ae3c7f605aaa1b3a936575384b002a35dd98" );
            add_init_len = unhexify( add_init, "f959f1bc100ae30088017fae51289d8e" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "5d80bc3fffa42b89ccb390e8447e33e5" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_5)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "6bb14dc34f669759f8fa5453c4899eb5ac4e33a69e35e89b19a46dbd0888429d1367f7f3191e911b3b355b6e3b2426e242ef4140ddcc9676371101209662f253" );
            add_init_len = unhexify( add_init, "45a8bb33062783eede09b05a35bd44dd" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "0dfa9955a13a9c57a3546a04108b8e9e" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_6)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "b3d01bcb1ec747fdb7feb5a7de92807afa4338aba1c81ce1eb50955e125af46b19aed891366ec0f70b079037a5aeb33f07f4c894fdcda3ff41e2867ace1aa05c" );
            add_init_len = unhexify( add_init, "0ada129f9948073d628c11274cec3f69" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "f34710c9ebf9d5aaa5f797fd85a1c413" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_7)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "98482e58e44b8e4a6b09fa02c05fcc491da03a479a7fad13a83b6080d30b3b255e01a43568a9d6dd5cecf99b0ce9fd594d69eff8fa88159b2da24c33ba81a14d" );
            add_init_len = unhexify( add_init, "052a5ad4cd38de90e5d3c2fc430fa51e" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "3f55144eec263aed50f9c9a641538e55" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_8)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "6238d448015e86aa16af62cdc287f1c17b78a79809fa00b8c655e06715cd2b935bf4df966e3ec1f14b28cc1d080f882a7215e258430c91a4a0a2aa98d7cd8053" );
            add_init_len = unhexify( add_init, "004cd2f28f083d1cee68975d5cbbbe4f" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "b137119dbbd9d752a8dfceec05b884b6" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_9)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "50d3c4ecb1d6e95aebb87e9e8a5c869c11fb945dfad2e45ee90fb61931fcedd47d6005aa5df24bb9efc11bbb96bb21065d44e2532a1e17493f974a4bf8f8b580" );
            add_init_len = unhexify( add_init, "f985b3ea2d8b15db26a71895a2ff57cd" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "eb419628fbc441ae6a03e26aeecb34a6" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_10)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "d27cbeac39a6c899938197f0e61dc90be3a3a20fa5c5e1f7a76adde00598e59555c1e9fd102d4b52e1ae9fb004be8944bad85c58e341d1bee014057da98eb3bc" );
            add_init_len = unhexify( add_init, "100f196991b6e96f8b96a3456f6e2baf" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "e3e09d0ed827e4f24a20553fd1087c9d" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_11)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "16f9f5354d624c5ab1f82c750e05f51f2a2eeca7e5b774fd96148ddba3b38d34ba7f1472567c52087252480d305ad1c69e4aac8472a154ae03511d0e8aac905a" );
            add_init_len = unhexify( add_init, "88f55d9ba8fef7828483298321133fec" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "07cd821012ef03f16d8510c23b86baf3" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_12)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "70afbc83bf9ff09535d6f0ddc51278ad7909f11e6f198b59132c9e269deb41ba901c62346283e293b8714fd3241ae870f974ff33c35f9aff05144be039d24e50" );
            add_init_len = unhexify( add_init, "126479abd70b25acd891e1c4c92044f9" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "0f90df350741d88552a5b03b6488e9fb" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_13)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "5e5a9e1e3cb80738c238464ede1b6b6a321261a3b006a98a79265ad1f635573bba48dccf17b12f6868478252f556b77c3ec57a3bf6bb6599429453db2d050352" );
            add_init_len = unhexify( add_init, "a45f2fca553089fe04e7832059dc7976" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "6eb85ae2406c43814b687f74f4e942bc" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_14)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "31cfe60e5ed12ff37d7f2270963def598726320c02b910b5c6c795e2209b4b4a95866c64cb097af1d6404d1e6182edf9600e1855345375b201801d6f4c4e4b32" );
            add_init_len = unhexify( add_init, "52dbb43241002415966eaec2615aba27" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "2a270f5ef815665ddd07527c48719ab1" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_0)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "f84d395b1734eac4600dbc36f6b1e1599bc7f2608dc8ecb3a55369d7b1b122a09f5ac9c16d9a2be37d2ff70a9bba732fc3785b23ff4ade3c8404da3f09f95a8f" );
            add_init_len = unhexify( add_init, "176200bb44808b5400b24e1b5f56cf73" );
            add1_len = unhexify( add1, "aef28c9169e9af74c73432d4aa6f5dff9ea4a53433de2ecb9bf380a8868c86e1" );
            add_reseed_len = unhexify( add_reseed, "0626ae19763c5313b627a8d65cf1cfba46dfd6773242738b9b81fde8d566ade1" );
            add2_len = unhexify( add2, "63c160ed6a6c1fffd0586f52fa488a9055533930b36d4fa5ea3467cda9ffe198" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "e8f91633725d786081625fb99336a993" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_1)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "50755cc0178c68ae70befd7744f6f1e3f6a59b3bbe484a744436079c7fae8d83c4965516fb952c63e1d0561d92cccc56037465815c9e549c9adce4a064877128" );
            add_init_len = unhexify( add_init, "19c3d16197ac93bf58c4110c9e864804" );
            add1_len = unhexify( add1, "5cb82d2c297404f3db1909480c597dd081d94ca282ba9370786a50f3cbab6a9b" );
            add_reseed_len = unhexify( add_reseed, "96d130faf1a971920c2bf57bcd6c02d5a4af7d3c840706081e4a50e55f38bf96" );
            add2_len = unhexify( add2, "1b0d04f179690a30d501e8f6f82201dbab6d972ece2a0edfb5ca66a8c9bcf47d" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "4628b26492e5cb3b21956d4160f0b911" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_2)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "e50c31ebbb735c4a53fc0535647ae1fff7a5ac4fa4068ba90f1fa03ca4ddedecd5b1898d5e38185054b0de7e348034b57067a82a478b0057e0c46de4a7280cd9" );
            add_init_len = unhexify( add_init, "4b1edd0f53bf4e012def80efd740140b" );
            add1_len = unhexify( add1, "e7154ec1f7ac369d0bd41238f603b5315314d1dc82f71191de9e74364226eb09" );
            add_reseed_len = unhexify( add_reseed, "9444238bd27c45128a25d55e0734d3adafecccb2c24abdaa50ac2ca479c3830b" );
            add2_len = unhexify( add2, "ab2488c8b7e819d8ce5ec1ffb77efc770453970d6b852b496426d5db05c03947" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "a488a87c04eb1c7586b8141ed45e7761" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_3)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "5e029c173dc28ab19851a8db008efbcf862f4187fca84e4e6f5ba686e3005dba5b95c5a0bcf78fb35ada347af58ec0aca09ed4799cd8a734739f3c425273e441" );
            add_init_len = unhexify( add_init, "1f89c914649ae8a234c0e9230f3460f9" );
            add1_len = unhexify( add1, "b51f5fd5888552af0e9b667c2750c79106ce37c00c850afbe3776746d8c3bce1" );
            add_reseed_len = unhexify( add_reseed, "9b132a2cbffb8407aa06954ae6ebee265f986666757b5453601207e0cbb4871b" );
            add2_len = unhexify( add2, "f1c435e2ebf083a222218ee4602263872a2d3e097b536a8cc32a5a2220b8065f" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "a065cc203881254ca81bd9595515e705" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_4)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "b66c882ae02c5215ed3bcd9e9a40934b09bf48a15fe7558c9d9ceb0ebec63625ea18f7c3ab341d9f7edd8e1d8816edecb34dbd71ae02771327b5ebc74613dadd" );
            add_init_len = unhexify( add_init, "0ef2be2d00a16051404fc2a0faa74fdc" );
            add1_len = unhexify( add1, "1ebe9893957a5c4a707793906d31bb201e88d88a22abd6baa6461fc61def7ffb" );
            add_reseed_len = unhexify( add_reseed, "f81e26744834413cb95af8d438d0050c7c968f929a33e35ee5c6715a0a520950" );
            add2_len = unhexify( add2, "687a848b2b6c715a0e613b3f3bb16cf2f056543eb9dd6b8aee8de8aa6fd8a1e6" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "a6c4a7e99d08cc847ac0b8c8bcf22ec0" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_5)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "ad153fd266d9f73b21f4e5e88d3d13ba8325abdec427d5d8f671cfccdbd3510e9774d59a14d9b5472b217b7bcf355436a51965d2dff7c4ac586ab812f20d326e" );
            add_init_len = unhexify( add_init, "eb2439d156c4f51fb1943c26f27de8af" );
            add1_len = unhexify( add1, "e24bd6b69a40fa0a02cefbbaa282f8f63a80e154be338d1b913418d4ff7a810d" );
            add_reseed_len = unhexify( add_reseed, "fd40baf11d7cdd77641a2b46916cb0c12980e02612ef59fb6fe7dabbbe7a85c0" );
            add2_len = unhexify( add2, "a40019e3b85d7d5775e793dd4c09b2bdc8253694b1dcb73e63a18b066a7f7d0c" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "7cd8d2710147a0b7f053bb271edf07b5" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_6)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "b249d2d9b269b58c5355710aaae98be12d8fb2e79046b4e6deeec28adad7e789999847e20de11f7c3277216374f117e3e006bdf99bb8631aa4c4c542cd482840" );
            add_init_len = unhexify( add_init, "b23796d88ee5ae75ff2ba4fbbd5e2de8" );
            add1_len = unhexify( add1, "79f0214b6b0c5ffb21b1d521498b71d22c67be4607c16300ab8dde3b52498097" );
            add_reseed_len = unhexify( add_reseed, "582be1e080264b3e68ec184347a5b6db1e8be1811578206e14ad84029fe39f71" );
            add2_len = unhexify( add2, "f5e9c3356810793f461f889d8c5003b1c0b20a284cb348301ce7b2dd7a1c7dd7" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "1aa8cf54994be6b329e9eb897007abf0" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_7)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "3f1e90d88870a0bd03364036b655495e3e7d51bf67fb64ba0cbf003430af5585f5936b84ab3b8a55c02b8b6c54bea09cf2d77691858c5818991383add5f0c644" );
            add_init_len = unhexify( add_init, "081db0b1620a56afd87c2fd2bebb1db3" );
            add1_len = unhexify( add1, "5b98bc83ae8bed5c49cb71689dc39fee38d5d08bdfa2a01cee9d61e9f3d1e115" );
            add_reseed_len = unhexify( add_reseed, "aad3e58fdd98aa60fc2cae0df3fc734fff01a07f29f69c5ffeb96d299200d0d8" );
            add2_len = unhexify( add2, "bad9039ebb7c3a44061353542a2b1c1a89b3e9b493e9f59e438bfc80de3d1836" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "8d01e3dc48b28f016fc34655c54be81f" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_8)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "b0e9b2192adc8912653d90a634d5d40c53ca4383290a8764bdf92667f859d833c3e72ad0ff41e07fe257b1ead11649be655c58a5df233114e7eda2558b7214d7" );
            add_init_len = unhexify( add_init, "a8427443d9c34abcdcca061a2bbcff52" );
            add1_len = unhexify( add1, "c6cad9fb17ada437d195d1f8b6a7fa463e20050e94024170d2ffc34b80a50108" );
            add_reseed_len = unhexify( add_reseed, "be461a9c1a72ebaf28ee732219e3ca54cbee36921daaa946917a7c63279a6b0e" );
            add2_len = unhexify( add2, "b6d110d6b746d7ccf7a48a4337ba341d52508d0336d017ae20377977163c1a20" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "16ccd63dbf7b24b6b427126b863f7c86" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_9)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "89900b0febf6b4e19ab8fc5babb4122a8aad86d658d0c2f98988c99fbd8530ff4ad365bd5fddaa15f96537bd72deb5384405b610e6ebae83e848307051fd6c82" );
            add_init_len = unhexify( add_init, "86bd02976e6c50656372b8c212cf0a7a" );
            add1_len = unhexify( add1, "41bf3794ee54647a48a2588fdfdea686f1af6792e957d42f181f2631b207ac0c" );
            add_reseed_len = unhexify( add_reseed, "c4478afbea4eecb225448f069b02a74c2a222698c68e37eb144aff9e457f9610" );
            add2_len = unhexify( add2, "41a99e0d3f5b767f9bedcb2f878a5d99d42856bed29042d568b04e347624bf7f" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "863337529aac9ab1e9f7f8187ea7aa7d" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_10)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "3e831b7715ce202c95ec85337e2c0061d972169955bd96fbe1f758508c0336b3226260ea5e66f943b538eb115ffe4d5e534cbe58262a610528641629bc12fc75" );
            add_init_len = unhexify( add_init, "e809ef8d4c3d82575833d51ac69481b2" );
            add1_len = unhexify( add1, "4d40c6a961168445c1691fea02ebd693cb4b3f74b03d45a350c65f0aaccb118b" );
            add_reseed_len = unhexify( add_reseed, "b07dc50e6ca7544ed6fdebd8f00ed5fa9b1f2213b477de8568eb92dddaabfe3f" );
            add2_len = unhexify( add2, "cbac982aa9f1830d0dc7373d9907670f561642adb1888f66b4150d3487bf0b8d" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "2814be767d79778ebb82a096976f30db" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_11)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "6a3fd23e7dc934e6de6eb4cc846c0dc3cf35ea4be3f561c34666aed1bbd6331004afba5a5b83fff1e7b8a957fbee7cd9f8142326c796ca129ec9fbacf295b882" );
            add_init_len = unhexify( add_init, "ad71caa50420d213b25f5558e0dc1170" );
            add1_len = unhexify( add1, "3042dd041b89aaa61f185fdda706c77667515c037f2a88c6d47f23ddadc828ae" );
            add_reseed_len = unhexify( add_reseed, "9b1e3f72aaab66b202f17c5cc075cfba7242817b2b38c19fe8924ca325b826ea" );
            add2_len = unhexify( add2, "8660b503329aaea56acdb73ca83763299bac0f30264702cb9d52cbaf3d71d69d" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "c204a3174784d82b664e9a1c0a13ffa6" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_12)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "baf8750e07194fc7172c736e0fdea0a632810d45602dff17ce37adf106d652f87e31b6bd24d21481c86444d8109586118672a6f93731b7438a3f0f39648b83a3" );
            add_init_len = unhexify( add_init, "5fd6606b08e7e625af788814bef7f263" );
            add1_len = unhexify( add1, "3c37193d40e79ce8d569d8aa7ef80aabaa294f1b6d5a8341805f5ac67a6abf42" );
            add_reseed_len = unhexify( add_reseed, "c7033b3b68be178d120379e7366980d076c73280e629dd6e82f5af1af258931b" );
            add2_len = unhexify( add2, "452218a426a58463940785a67cb34799a1787f39d376c9e56e4a3f2215785dad" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "561e16a8b297e458c4ec39ba43f0b67e" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_13)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "6697f889fcf6dae16881dc1e540e5c07f9461d409acee31842b04f93c00efbba670dfbf6040c1c2e29ad89064eae283fd6d431832f356e492bc5b2049f229892" );
            add_init_len = unhexify( add_init, "08def734914ecf74b9eccb5dfaa045b8" );
            add1_len = unhexify( add1, "a6ac87af21efd3508990aac51d36243d46237b3755a0e68680adb59e19e8ae23" );
            add_reseed_len = unhexify( add_reseed, "0052152872b21615775431eb51889a264fed6ca44fa0436b72a419b91f92604c" );
            add2_len = unhexify( add2, "ebadf71565d9a8cc2621403c36e6411e7bed67193a843b90ccf2f7aa9f229ca2" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "c83fa5df210b63f4bf4a0aca63650aab" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_14)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "719d1afcb6dc8ca26cba6a7c10f59cf82345b2a0c631a7879812d6f2d2663b49f9e92daecb81ff7c0790205d66694526477d6de54a269f542cb5e77fe4bc8db3" );
            add_init_len = unhexify( add_init, "6437862e93060def199029ff2182f1e5" );
            add1_len = unhexify( add1, "5c961db0ac2ea8caf62c9acc44465dcfb4d721fcb2cd3e1c76cdcb61bfaa7e75" );
            add_reseed_len = unhexify( add_reseed, "24eabd392d37493e306705d0b287be11a4d72dd4b9577ac4098ef0dae69b0000" );
            add2_len = unhexify( add2, "9e4f05c1b85613e97958bc3863e521331b2bd78fdf2585f84607bf2238e82415" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "21aaae76dc97c9bf7cf858054839653e" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_0)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "7f88c3805ae0857c5cbb085a5d6259d26fb3a88dfe7084172ec959066f26296a800953ce19a24785b6acef451c4ce4c2dfb565cbe057f21b054a28633afbdd97" );
            add_init_len = unhexify( add_init, "cd7a1981c1b7079c1c38f5aeee86db22207cb9faed8c576b1724ca7817aa6abfb26c42a019eb4c2f4064f0587ea2b952" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "76c1cdb0b95af271b52ac3b0c9289146" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_1)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "6f61703f92d3192cd982b2e52a8683e0d62918d51b12e084deae06c4a8e08ecfb3d2d30a980a70b083710bc45d9d407966b52829cf3813cc970b859aa4c871fe" );
            add_init_len = unhexify( add_init, "0ccdac2fd65a86bf8f8e9ddcabffb9d29a935139f627c165a815b23137eeee94cbb21be86ac5117379177d37728db6fd" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "e6c73e159d73c2ba8950cd77acb39c10" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_2)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "c662ed723e7041877542fdcf629533d4a74393eb4dae4f3ec06d2d1c0d37ed7f519609a8485cb8deb578ae4cbb45c98ef7f2f2e677363e89fb3744286db6bfc1" );
            add_init_len = unhexify( add_init, "fbbcc4abfd671296de3e0dcf409a139e35deae126c1941bf1afcc8d3da3a2d65f54a6d317bb6d683a3a77f6266b007ff" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "9d934d34417c6d0858f4a3faacbe759e" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_3)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "c57a5686486ebacc2422236b19110c754795a869a8157901cf71303de1adc6af16a952190a395d6c20e155e690f41922f6f721dc8e93da81afb844f68714cba7" );
            add_init_len = unhexify( add_init, "1b824790b6b22b246bcc1bcfbbb61a76045476672f917b72e79cca358e650eb29ed49fb0a5739e097f5f5336d46fc619" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "13e7bf23d88f3bb5a5106a8227c8c456" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_4)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "6a0873634094be7028b885c345cd5016295eec5e524f069de6510ae8ac843dba2cc05c10baa8aad75eac8e8d1a8570f4d2a3cf718914a199deb3edf8c993a822" );
            add_init_len = unhexify( add_init, "2ea7861e374232cb8ceecbbd9a18fc1f63c31f833fe394f1e19c8ef61092a56f28342fa5b591f7b951583d50c12ef081" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "c008f46a242ae0babad17268c9e0839a" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_5)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "f2059f7fb797e8e22de14dac783c56942a33d092c1ab68a762528ae8d74b7ad0690694ede462edbd6527550677b6d080d80cdabe51c963d5d6830a4ae04c993f" );
            add_init_len = unhexify( add_init, "39caa986b82b5303d98e07b211ddc5ce89a67506095cad1aeed63b8bfe0d9c3d3c906f0c05cfb6b26bab4af7d03c9e1a" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "202d3b2870be8f29b518f2e3e52f1564" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_6)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "0a03b7d026fab3773e9724dacb436197954b770eca3060535f2f8152aa136942915304dede1de0f5e89bd91d8e92531b5e39373013628fea4ee7622b9255d179" );
            add_init_len = unhexify( add_init, "a4e25102c1b04bafd66bfe1ce4a4b340797f776f54a2b3afe351eede44e75c28e3525155f837e7974269d398048c83c3" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "be21cab637218ddffa3510c86271db7f" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_7)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "d88312da6acbe792d087012c0bf3c83f363fa6b7a9dd45c3501009fb47b4cfcfeb7b31386155fe3b967f46e2898a00ecf51ec38b6e420852bef0a16081d778cc" );
            add_init_len = unhexify( add_init, "6de33a116425ebfe01f0a0124ad3fad382ca28473f5fc53885639788f9b1a470ab523b649bad87e76dee768f6abacb55" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "2c285bfd758f0156e782bb4467f6832c" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_8)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "6a7873ccb7afb140e923acbec8256fa78232f40c0c8ba3dcbcf7074d26d6d18a7e78fffda328f097706b6d358048ee6a4728c92a6f62b3f2730a753b7bf5ec1f" );
            add_init_len = unhexify( add_init, "b8ab42fd3f6306426602cae0c48eb02ffa7053940389900c17846e1d9726251762095383f2ec3406b3381d94a6d53dd8" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "13504a2b09474f90d2e9ef40d1f2d0d5" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_9)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "31ba5f801aeaac790f2480fbd2373a76ba1685ebebc5ae7cd4844733ec3cfb112634b3899104dcc16050e1206f8b3fb787d43d54de2c804fd3d8eb98e512bb00" );
            add_init_len = unhexify( add_init, "042b524444b9903c1ecb80af21eef0e884115561a15a1ab2f9f3a322edcbf14174f54d315196a632940c2c6f56612c09" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "0a0484c14e7868178e68d6d5c5f57c5c" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_10)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "46dc837620872a5ffa642399213b4eebfb28ca069c5eaaf2a636f5bd647de365c11402b10ecd7780c56d464f56b653e17af8550b90a54adb38173a0b2f9e2ea7" );
            add_init_len = unhexify( add_init, "632758f92efaca39615862177c267906ab0424230d481ee0a5aa1a5f66697d3918d4aab3f310b72a7f2d71c0a96b9247" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "90432ce3f7b580961abecde259aa5af6" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_11)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "76e92e9f00fc7d0c525c48739a8b3601c51f8f5996117a7e07497afee36829636e714dbcb84c8f8d57e0850a361a5bdfc21084a1c30fb7797ce6280e057309b7" );
            add_init_len = unhexify( add_init, "7b389118af3d0f8336b41cf58c2d810f0e5f9940703fd56a46c10a315fb09aafd7670c9e96ffa61e0cb750cb2aa6a7fe" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "7243964051082c0617e200fcbbe7ff45" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_12)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "c9aa4739011c60f8e99db0580b3cad4269874d1dda1c81ffa872f01669e8f75215aaad1ccc301c12f90cd240bf99ad42bb06965afb0aa2bd3fcb681c710aa375" );
            add_init_len = unhexify( add_init, "e50d38434e9dfe3601e7ea1765d9fe777d467d9918974b5599ec19f42d7054b70ff6db63a3403d2fd09333eda17a5e76" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "28499495c94c6ceec1bd494e364ad97c" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_13)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "b06960a92d32a9e9658d9800de87a3800f3595e173fdc46bef22966264953672e2d7c638cc7b1cada747026726baf6cea4c64ba956be8bb1d1801158bee5e5d4" );
            add_init_len = unhexify( add_init, "3253cb074d610db602b0a0d2836df1f20c3ee162d80b90b31660bb86ef3f0789fa857af4f45a5897bdd73c2295f879b6" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "b6608d6e5fcb4591a718f9149b79f8f1" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_14)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "0e0105b12af35ac87cb23cf9ca8fb6a44307c3dcdc5bc890eb5253f4034c1533392a1760c98ba30d7751af93dd865d4bd66fbbeb215d7ff239b700527247775d" );
            add_init_len = unhexify( add_init, "83e4733566f90c8d69e6bcbe9fb52521ff3e26f806d9b7b86e9344cca0305dbf106de855240f1d35492cc6d651b8b6ae" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "68d64d1522c09a859b9b85b528d0d912" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_0)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "a53e371017439193591e475087aaddd5c1c386cdca0ddb68e002d80fdc401a47dd40e5987b2716731568d276bf0c6715757903d3dede914642ddd467c879c81e" );
            add_init_len = unhexify( add_init, "a94da55afdc50ce51c9a3b8a4c4484408b52a24a93c34ea71e1ca705eb829ba65de4d4e07fa3d86b37845ff1c7d5f6d2" );
            add1_len = unhexify( add1, "20f422edf85ca16a01cfbe5f8d6c947fae12a857db2aa9bfc7b36581808d0d46" );
            add_reseed_len = unhexify( add_reseed, "7fd81fbd2ab51c115d834e99f65ca54020ed388ed59ee07593fe125e5d73fb75" );
            add2_len = unhexify( add2, "cd2cff14693e4c9efdfe260de986004930bab1c65057772a62392c3b74ebc90d" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "4f78beb94d978ce9d097feadfafd355e" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_1)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "78d7d65c457218a63e2eb1eba287f121c5466728ac4f963aeaabf593b9d72b6376daea6436e55415ad097dee10c40a1ff61fca1c30b8ab51ed11ff090d19ef9a" );
            add_init_len = unhexify( add_init, "e8649d4f86b3de85fe39ff04d7afe6e4dd00770931330b27e975a7b1e7b5206ee2f247d50401a372c3a27197fec5da46" );
            add1_len = unhexify( add1, "cc57adc98b2540664403ad6fd50c9042f0bf0e0b54ed33584ee189e072d0fb8f" );
            add_reseed_len = unhexify( add_reseed, "ab2f99e2d983aa8dd05336a090584f4f84d485a4763e00ced42ddda72483cd84" );
            add2_len = unhexify( add2, "0ecd7680e2e9f0250a43e28f2f8936d7ef16f45d79c0fa3f69e4fafce4aeb362" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "08e38625611bb0fb844f43439550bd7a" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_2)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "c78ff6b9fc91cbce246c9fcc2366d5f7dd6d99fb1325d8997f36819232d5fcd12ccafdcbefd01409d90acd0e0ffb7427c820b2d729fe7e845e6a6168fc1af0b5" );
            add_init_len = unhexify( add_init, "6c79e1556889b3c074fc083a120d73784b888c5acb877899f17ce52e424b84178d144441aa9f328c730a951b02b048df" );
            add1_len = unhexify( add1, "60cba10826de22c5e85d06357de63d6b2ff0719694dafca6ab33283f3a4aacdd" );
            add_reseed_len = unhexify( add_reseed, "8943c22fb68b30811790a99b9cbb056e1a2c329185a199c76ba5aeceb2fcd769" );
            add2_len = unhexify( add2, "70671a50e8387bf232989d904c19215c7535ad2d0c5dec30a744c8d2706be6ec" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "f6b94b671cae8dfa8387719bfd75ee84" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_3)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "21a21c9314b37d4ade4a50a5d85995e0be07e358ed9bca19daa867a8d47847105dca7a424f32f715adb8fea5d3a41cfe388872a42ab18aa5cbcd7bde4adc3f8b" );
            add_init_len = unhexify( add_init, "f5ab77b2a8e370548b88febfd79772144cd5fc8d78062582addd4ff1e5c10094b390e66b3c4efb087510de1b9d25703f" );
            add1_len = unhexify( add1, "023d582569a7ff1405e44cf09ceebb9d3254eef72286e4b87e6577a8ab091a06" );
            add_reseed_len = unhexify( add_reseed, "39597519872d49fbd186704241ba1dc10b1f84f9296fb61d597dbd655a18f997" );
            add2_len = unhexify( add2, "3091c9fe96109b41da63aa5fa00d716b5fa20e96d4f3e0f9c97666a706fa56f1" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "1fb57058b3ba8751df5a99f018798983" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_4)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "192054dddac02157a35eb7f75ae8ebdb43d6b969e33942fb16ff06cd6d8a602506c41e4e743b8230e8239b71b31b2d5e3614e3a65d79e91d5b9fc9d2a66f8553" );
            add_init_len = unhexify( add_init, "f0b79e292d0e393e78b6d6117e06d2e725823fe35bde1146502967a78d99d6bca564f0e2f324272f968be5baab4aeb29" );
            add1_len = unhexify( add1, "b12241e90d80f129004287c5b9911a70f7159794e6f9c1023b3b68da9237e8b7" );
            add_reseed_len = unhexify( add_reseed, "59e9c3c0f90e91f22c35a3be0c65f16157c569c7e3c78a545d9840f648c60069" );
            add2_len = unhexify( add2, "089a59af69f47ddb4191bd27720bb4c29216f738c48c0e14d2b8afd68de63c17" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "15287156e544617529e7eede4aa9c70e" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_5)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "ef081af1f62400a3d193969d689a40234998afb646d99a7c4b9cbbf47e650cda93a90e754a16fffa25fc2a2edab09720b4520c47309ec4f6d9f76f0162af6cae" );
            add_init_len = unhexify( add_init, "e3f33843aecb35d01001ff92ab9a0f1a5431ba9de3e4f3247cda8c62acc86f7066448f639d8ba8b5249337f8c353bbbd" );
            add1_len = unhexify( add1, "e7cc55b72862544a8661b5034e15587b1e5a45eb5dc744f5fa1db9b267f1c3ff" );
            add_reseed_len = unhexify( add_reseed, "882d30c888eb8e344b1d17057074606fe232ceb42eb71055264ede7bb638f2a2" );
            add2_len = unhexify( add2, "9ce65e95c1e735fe950e52c324e7551403d0ef70ad865bd31fef1e22b129fdd6" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "205e3a53367c4a5183be74bb875fa717" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_6)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "fae3d554d12a14e29de1b622922f27559559ca1518c9f800375a37a212e8b9a653cc3700223e9404d5bf781d15fccf638050a1394592caba001cfc65d61ef90b" );
            add_init_len = unhexify( add_init, "f30a18d597d8591a22dee908de95c5af74884b025f39b4f6707d28447d9d0a3114a57bc2d9eed8e621ec75e8ce389a16" );
            add1_len = unhexify( add1, "54240edd89016ed27e3bb3977a206836f5ef1fba0f000af95337d79caca9cf71" );
            add_reseed_len = unhexify( add_reseed, "250611e51852d933ff1a177b509c05e3228cb9f46dfb7b26848a68aad2ce4779" );
            add2_len = unhexify( add2, "f8b602d89fa1a0bfb31d0bd49246b458200a1adb28b64a68f7c197f335d69706" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "7b63bfb325bafe7d9ef342cd14ea40a4" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_7)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "8e60115b4af9c8e5606223792539e9ba87e9ef46cd16fcc09046db1ef8d3c036241cae5d61141711818e9e861dbd833632069ebf5af1bd6d4e513f059ab1efd3" );
            add_init_len = unhexify( add_init, "c8dbc3d39beb612811c52e2b46ef76d2b7bd5d3a90ceddf9fb864fe6f44e36687d88158d61014e192f9a3cd474338e13" );
            add1_len = unhexify( add1, "9b56eba0838457f736fc5efa2cfbe698908340f07d4680e279d21dd530fdc8c8" );
            add_reseed_len = unhexify( add_reseed, "62c47ece469a7a409e4b2b76d1c793aaf11654e177cc8bf63faff3e6c5a5395c" );
            add2_len = unhexify( add2, "4251597013d0c949c53bbd945477b78aa91baa95f1ff757c3a039ccc4e1f4789" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "af2f37160940f0cc27d144a043ddf79b" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_8)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "95da91f4185b254322ef0fc852473a9b9e4c274b242ded8a4eae6f1e2badde0664cf57f2128aa3dc83e436f7e80928a01d93bf25011eedf0190d0bf3619cd555" );
            add_init_len = unhexify( add_init, "a37f9ed6c4e8f74ff16046b0678ef7bd24fcdca247b771ea1ce1fd48e3f5d2067e38aaf64ec59f1f49d96fa85e60ef03" );
            add1_len = unhexify( add1, "b4a22f5598f79d34f0b9600763c081b0200ba489da7028ad0283828545c6d594" );
            add_reseed_len = unhexify( add_reseed, "fa3edc0962b20a9d9e1d0afcad907c8097c21d7a65c0e47c63d65cea94bf43bd" );
            add2_len = unhexify( add2, "49ba791a227e9e391e04225ad67f43f64754daac0b0bb4c6db77320943231ec3" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "32f313ded225289793c14a71d1d32c9f" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_9)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "f22dd3517350176e35e1b7ecc8c00bea4747f0ac17bda1b1ddf8cdf7be53ff8c326268366e89cf3b023a9646177a0dcca902f0c98bf3840c9cbdf5c0494bee3c" );
            add_init_len = unhexify( add_init, "87f85b9c19eba1d953b6613cf555c21bc74428d9a8fee15e6cd717e240506f3e80860423973a66c61820d4ce1c6bb77d" );
            add1_len = unhexify( add1, "611caa00f93d4456fd2abb90de4dbcd934afbf1a56c2c4633b704c998f649960" );
            add_reseed_len = unhexify( add_reseed, "cba68367dc2fc92250e23e2b1a547fb3231b2beaab5e5a2ee39c5c74c9bab5f5" );
            add2_len = unhexify( add2, "f4895c9653b44a96152b893b7c94db80057fb67824d61c5c4186b9d8f16d3d98" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "a05de6531a1aa1b2ba3faea8ad6ac209" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_10)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "bba34e6f4ee27e5d4e885e59f8bbb0dc7353a8912e66637d7515a66e5398d9a8cbd328fed32f71bdd34c73cdf97e0d211be6dabfb0144e1011fd136cf01ea4e4" );
            add_init_len = unhexify( add_init, "9670deb707caabc888a3b0df7270942934732e02be728a4bedb5fc9ca4d675b2f3b47c7132c364ce6292cef7c19b60c7" );
            add1_len = unhexify( add1, "9f55da36babd6ea42082f5f5d4330f023440bb864f8ad5498a29cf89757eaeab" );
            add_reseed_len = unhexify( add_reseed, "8013a309058c91c80f4d966f98bce1d4291003ad547e915777a3fce8ae2eaf77" );
            add2_len = unhexify( add2, "c83106272d44e832e94c7096c9c11f6342e12ec06d5db336424af73d12451406" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "bc8d4d00609662c1163dca930901821d" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_11)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "ed0e524ed2990ef348dbb15b3f964b12ad3109978d6952ae193b21e94510a47406926620798e71a0ffcbdd2e54ec45509d784a8bfc9d59cb733f9f11fc474b5e" );
            add_init_len = unhexify( add_init, "6d984c8ab923a7e118447fd53ad287b8f01d1e6112cff12bfb338ecd3ed16bafdd634677c600bdd68f852a946f45c3d9" );
            add1_len = unhexify( add1, "0a3a32260d04dd7a82fb0873ecae7db5e5a4b6a51b09f4bf8a989e1afacbda3b" );
            add_reseed_len = unhexify( add_reseed, "3cbcabb83aab5a3e54836bbf12d3a7862a18e2dffeeb8bdd5770936d61fd839a" );
            add2_len = unhexify( add2, "f63b30a3efc0273eba03bf3cf90b1e4ac20b00e53a317dbf77b0fe70960e7c60" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "ab9af144e8fad6a978a636ad84e0469e" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_12)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "2882d4a30b22659b87ad2d71db1d7cf093ffca80079a4ef21660de9223940969afec70b0384a54b1de9bcca6b43fb182e58d8dfcad82b0df99a8929201476ae9" );
            add_init_len = unhexify( add_init, "2c59520d6f8ce946dcc5222f4fc80ba83f38df9dce2861412eebb1614245331626e7fb93eedbad33a12e94c276deff0a" );
            add1_len = unhexify( add1, "d3c17a2d9c5da051b2d1825120814eaee07dfca65ab4df01195c8b1fcea0ed41" );
            add_reseed_len = unhexify( add_reseed, "dcc39555b87f31973ae085f83eaf497441d22ab6d87b69e47296b0ab51733687" );
            add2_len = unhexify( add2, "9a8a1b4ccf8230e3d3a1be79e60ae06c393fe6b1ca245281825317468ca114c7" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "fba523a09c587ecad4e7e7fd81e5ca39" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_13)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "8ae9a5903da32a38b7c6fed92dd0c6a035ca5104a3528d71a3eacc2f1681379724991a0053e8dac65e35f3deee0435e99f86364577c8ebdba321872973dc9790" );
            add_init_len = unhexify( add_init, "1c1207f50b645aaed5c16fe36f6aae83af4924e6b98a7e2a2533a584c1bac123f8b6f0e05109e0132950ae97b389001a" );
            add1_len = unhexify( add1, "568bfee681d7f9be23a175a3cbf441b513829a9cbdf0706c145fdcd7803ce099" );
            add_reseed_len = unhexify( add_reseed, "e32cb5fec72c068894aaeabfc1b8d5e0de0b5acdf287a82e130a46e846770dc2" );
            add2_len = unhexify( add2, "d4418c333687a1c15cac7d4021f7d8823a114bb98f92c8a6dccc59ff8ad51c1f" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "194e3018377cef71610794006b95def5" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_14)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "98a0db985544c33990aee0f69655dba7198e6720ce56ff9d4662e26f0c6b4ee7ab599932c05295f6c5a4011085c5b2c861a5a8ae4f572ce614ff2dafc0fddb34" );
            add_init_len = unhexify( add_init, "28254014c5d6ebf9bd9e5f3946fc98e55fe351deee8fc70333e4f20f1f7719a522b3ea9a4424afe68208d1cc6c128c47" );
            add1_len = unhexify( add1, "64215cbe384f1f4cf548078ffd51f91eee9a8bae5aacdd19ca16bcaaf354f8ad" );
            add_reseed_len = unhexify( add_reseed, "2e21df638dabe24aebf62d97e25f701f781d12d0064f2f5a4a44d320c90b7260" );
            add2_len = unhexify( add2, "7f936274f74a466cbf69dbfe46db79f3c349377df683cb461f2da3b842ad438e" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "25c469cc8407b82f42e34f11db3d8462" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_0)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "fea104f90c5881df7ad1c863307bad22c98770ecd0d717513a2807682582e3e18e81d7935c8a7bacddd5176e7ca4911b9f8f5b1d9c349152fa215393eb006384" );
            add_init_len = unhexify( add_init, "e26c8a13dae5c2da81023f27ab10b878" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "fd87337c305a0a8ef8eef797601732c2" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_1)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "1d723cbc2ff2c115160e7240340adbf31c717696d0fdfecf3ec21150fca00cde477d37e2abbe32f399a505b74d82e502fbff94cecac87e87127d1397d3d76532" );
            add_init_len = unhexify( add_init, "8d7dda20a9807804bfc37bd7472d3b0c" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "7221761b913b1f50125abca6c3b2f229" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_2)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "0820fc21cecba6b2fe053a269a34e6a7637dedaf55ef46d266f672ca7cfd9cc21cd807e2b7f6a1c640b4f059952ae6da7282c5c32959fed39f734a5e88a408d2" );
            add_init_len = unhexify( add_init, "c02e3b6fd4fea7ec517a232f48aaa8cb" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "667d4dbefe938d6a662440a17965a334" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_3)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "ef0aae3f9c425253205215e5bf0ad70f141ad8cc72a332247cfe989601ca4fc52ba48b82db4d00fe1f279979b5aed1ae2ec2b02d2c921ee2d9cb89e3a900b97d" );
            add_init_len = unhexify( add_init, "9aee0326f9b16f88a4114e8d49b8e282" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "651ad783fe3def80a8456552e405b98d" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_4)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "a9262ed5b54880cc8ecd4119cce9afe3de8875d403f7ca6b8ed8c88559470b29e644fddd83e127c5f938bc8a425db169c33c5c2d0b0c5133c8f87bbc0b0a7d79" );
            add_init_len = unhexify( add_init, "1e7a4961d1cd2fd30f571b92a763c2c5" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "1124c509ca52693977cf461b0f0a0da9" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_5)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "554cf6fad1c376ad6148cd40b53105c16e2f5dd5fa564865b26faa8c318150bfb2294e711735df5eb86ff4b4e778531793bad42403d93a80d05c5421229a53da" );
            add_init_len = unhexify( add_init, "ae0b0d2e84f48c632f031356cdea60ac" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "1212e5d3070b1cdf52c0217866481c58" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_6)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "7cffe2bef0d42374f7263a386b67fba991e59cefd73590cbcde3a4dc635a5a328f1a8e5edd3ada75854f251ee9f2de6cd247f64c6ca4f6c983805aa0fe9d3106" );
            add_init_len = unhexify( add_init, "16b8c7495d43cd2ff5f65ad2ab48ecef" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "d3869a9c5004b8a6ae8d8f0f461b602b" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_7)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "59759bb91b3c4feb18c0f086269ec52e097b67698f4dfe91ebe8bef851caa35cadb3fd22d1309f13510e1252856c71394a8e210fdbf3c7aae7998865f98e8744" );
            add_init_len = unhexify( add_init, "a2d5eff6f73f98e5b04c01967dffa69b" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "a1f99bd9522342e963af2ec8eed25c08" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_8)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "0ec7c617f85bec74044111020c977be32ab8050b326ebc03715bbbffa5a34622f2264d4b5141b7883281c21ea91981155a64fb7b902e674e9a41a8a86c32052b" );
            add_init_len = unhexify( add_init, "ea1f47fe5e281136706419ea9b652967" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "daf75b8288fc66802b23af5fd04a9434" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_9)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "cd7ce90f0141e80f6bd6ff3d981d8a0a877d0ddae7c98f9091763b5946fc38b64c1ef698485007d53251ad278daf5d4ae94a725d617fc9a45a919a9e785a9849" );
            add_init_len = unhexify( add_init, "6f072c681a82c00dcd0d9dd5b7ffa2af" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "39c0144f28c5a490eff6221b62384602" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_10)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "854766e842eb165a31551f96008354bca1628a9520d29c3cc4f6a41068bf76d8054b75b7d69f5865266c310b5e9f0290af37c5d94535cb5dc9c854ea1cb36eb7" );
            add_init_len = unhexify( add_init, "9d730655366e2aa89ee09332bd0a5053" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "baa2a3ed6fdc049d0f158693db8c70ef" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_11)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "6abfab14cbf222d553d0e930a38941f6f271b48943ea6f69e796e30135bc9eb30204b77ab416ac066da0a649c8558e5a0eac62f54f2f6e66c207cab461c71510" );
            add_init_len = unhexify( add_init, "3363881611bfd5d16814360e83d8544f" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "5be410ce54288e881acd3e566964df78" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_12)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "0d2e446cad387a962ff2217c7cf4826dcabb997ab7f74f64aa18fbcb69151993f263925ae71f9dfdff122bb61802480f2803930efce01a3f37c97101893c140f" );
            add_init_len = unhexify( add_init, "14e589065423528ff84a1f89507ab519" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "fc2d3df6c9aae68fb01d8382fcd82104" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_13)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "aa04d9fc56349fdd31d868e9efc2938f9104c0291e55ac0aa0c24ec4609731b8e0ac04b42180bde1af6ad1b26faff8a6de60a8a4a828cd6f8758c54b6037a0ee" );
            add_init_len = unhexify( add_init, "974c5ae90347d839475f0f994f2bf01d" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "3caec482015003643d5a319a2af48fb4" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_14)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "203bba645fb5ccee3383cf402e04c713b7a6b6cca8b154e827520daac4ea3a0247bbdc3b2cd853e170587d22c70fb96c320ea71cb80c04826316c7317c797b8a" );
            add_init_len = unhexify( add_init, "b3a110587a16c1eafe51128a66816ecf" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "9af4f67a30a4346e0cfcf51c45fd2589" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_0)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "951e712d057028158831ca8c74d4ae303c6e4641c344a1c80292260bdd9d8e2f5b97606370e95903e3124659de3e3f6e021cd9ccc86aa4a619c0e94b2a9aa3cc" );
            add_init_len = unhexify( add_init, "55546068cd524c51496c5fc9622b64c6" );
            add1_len = unhexify( add1, "2d6de8661c7a30a0ca6a20c13c4c04421ba200fbef4f6eb499c17aee1561faf1" );
            add_reseed_len = unhexify( add_reseed, "41797b2eeaccb8a002538d3480cb0b76060ee5ba9d7e4a2bb2b201154f61c975" );
            add2_len = unhexify( add2, "b744980bb0377e176b07f48e7994fffd7b0d8a539e1f02a5535d2f4051f054f3" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "65b9f7382ed578af03efa2008dbdd56f" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_1)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "6e9b31755c1f45df7d685f86044ab3bc25433a3ff08ab5de7154e06b0867f4e3531ed2e2a15ab63c611fc2894240fdac1d3292d1b36da87caa2080d1c41bcf24" );
            add_init_len = unhexify( add_init, "a0c92565640a3315cac8da6d0458fb07" );
            add1_len = unhexify( add1, "c6c74690bdee26288d2f87a06435d664431206b23b24f426e847fb892d40d5d5" );
            add_reseed_len = unhexify( add_reseed, "4e7dc1adbc8bc16ba7b584c18a0d7e4383c470bff2f320af54ad5ade5f43265b" );
            add2_len = unhexify( add2, "c6fb8ee194a339726f5051b91925c6a214079a661ec78358e98fc4f41e8c4724" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "c3f849ee7d87291301e11b467fa2162f" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_2)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "62c2c790cb56518ed2d8d65952bbd4ab85a56463495c940b94f403a93338bdc96129feea9335b1a3e0ada7cf4c207f4732013bc6a52db41407bf5d6fe9183b3c" );
            add_init_len = unhexify( add_init, "63e143bd6a87065a00eea930593f9b29" );
            add1_len = unhexify( add1, "7b4e9ff0c8f8c90f8b324c7189226d3adccd79df2d0c22b52fb31dbb5dfefba6" );
            add_reseed_len = unhexify( add_reseed, "49e1aecf2b96a366325dc1892c016a5535dd2480360a382e9cc78bf75b2bba37" );
            add2_len = unhexify( add2, "f4ce1d27e759f3ba4a56aaab713642b4c56810c9995fbfc04ce285429f95a8f4" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "513111abaae3069e599b56f7e5fb91d1" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_3)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "2fab4a629e4b21f27488a0c9ed36fc8e75bee0c386346c6ec59a6f045975e29818440a6638eb3b9e952e19df82d6dc7b8b9c18530aef763d0709b3b55433ddc6" );
            add_init_len = unhexify( add_init, "98dc16e95f97b5b9d8287875774d9d19" );
            add1_len = unhexify( add1, "2e9d2f52a55df05fb8b9549947f8690c9ce410268d1d3aa7d69e63cbb28e4eb8" );
            add_reseed_len = unhexify( add_reseed, "57ecdad71d709dcdb1eba6cf36e0ecf04aaccd7527ca44c6f96768968027274f" );
            add2_len = unhexify( add2, "7b2da3d1ae252a71bccbb318e0eec95493a236f0dec97f2600de9f0743030529" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "841882e4d9346bea32b1216eebc06aac" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_4)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "c00b28c78da4f9ce159741437fe7f90e4e23ecd01cd292f197202decbbc823d9ce46b8191c11e8f8d007d38e2ecd93b8bd9bbad5812aaf547ddf4c7a6738b777" );
            add_init_len = unhexify( add_init, "5dbac5c313527d4d0e5ca9b6f5596ed7" );
            add1_len = unhexify( add1, "460c54f4c3fe49d9b25b069ff6664517ed3b234890175a59cde5c3bc230c0a9e" );
            add_reseed_len = unhexify( add_reseed, "bf5187f1f55ae6711c2bc1884324490bf2d29d29e95cad7a1c295045eed5a310" );
            add2_len = unhexify( add2, "28fd8277dcb807741d4d5cb255a8d9a32ef56a880ccf2b3dcca54645bd6f1013" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "b488f5c13bb017b0d9de2092d577c76e" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_5)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "4c1cc9ebe7a03cde31860637d8222faeefa9cbf789fab62e99a98d83084fef29eafcf7177d62d55435a1acb77e7a61ad86c47d1950b8683e167fe3ece3f8c9e8" );
            add_init_len = unhexify( add_init, "254d5f5044415c694a89249b0b6e1a2c" );
            add1_len = unhexify( add1, "71af584657160f0f0b81740ef93017a37c174bee5a02c8967f087fdbfd33bfde" );
            add_reseed_len = unhexify( add_reseed, "96e8522f6ed8e8a9772ffb19e9416a1c6293ad6d1ecd317972e2f6258d7d68dd" );
            add2_len = unhexify( add2, "3aaa5e4d6af79055742150e630c5e3a46288e216d6607793c021d6705349f96a" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "66629af4a0e90550b9bd3811243d6b86" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_6)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "ff62d52aed55d8e966044f7f7c5013b4915197c73668e01b4487c3243bbf5f9248a4fdd6ef0f63b87fc8d1c5d514ff243319b2fbdfa474d5f83b935399655e15" );
            add_init_len = unhexify( add_init, "b46fceed0fcc29665815cc9459971913" );
            add1_len = unhexify( add1, "994d6b5393fbf0351f0bcfb48e1e763b377b732c73bf8e28dec720a2cadcb8a5" );
            add_reseed_len = unhexify( add_reseed, "118bb8c7a43b9c30afaf9ce4db3e6a60a3f9d01c30b9ab3572662955808b41e4" );
            add2_len = unhexify( add2, "bb47e443090afc32ee34873bd106bf867650adf5b5d90a2e7d0e58ed0ae83e8a" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "1865fee6024db510690725f16b938487" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_7)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "bf1ba4166007b53fcaee41f9c54771c8a0b309a52ea7894a005783c1e3e43e2eb9871d7909a1c3567953aabdf75e38c8f5578c51a692d883755102a0c82c7c12" );
            add_init_len = unhexify( add_init, "e1a5dd32fc7cefb281d5d6ce3200f4ca" );
            add1_len = unhexify( add1, "32e9922bd780303828091a140274d04f879cd821f352bd18bcaa49ffef840010" );
            add_reseed_len = unhexify( add_reseed, "01830ddd2f0e323c90830beddedf1480e6c23b0d99c2201871f18cc308ab3139" );
            add2_len = unhexify( add2, "f36d792dbde7609b8bf4724d7d71362840b309c5f2961e2537c8b5979a569ae8" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "7080e8379a43c2e28e07d0c7ed9705a8" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_8)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "6ac34c4ce22b644632283ab13e294df2093e939d32411340b046c26fcc449d0fd6d14132c7205df303dbb663190e6e86ad12e14e145b6603308241f38d94eb5d" );
            add_init_len = unhexify( add_init, "d1b7be857a422b425ae62c61e90a192a" );
            add1_len = unhexify( add1, "aacfe8553d5ffef6abc3fd8f94d796cae2079ff04f7ab1b41982003f02427c7a" );
            add_reseed_len = unhexify( add_reseed, "01d2d1bc29d6a6b52bb29bd6652be772096ca23c838c40730d5b4a4f8f735daa" );
            add2_len = unhexify( add2, "27af728ee07d3f5902f4e56453b6a9feb308ef14795eb5630b2651debdd36d5b" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "b03fbcd03fa1cc69db0a4e3492a52bad" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_9)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "5684c3eb99314127078484959314d52b3bc50cb3615c0eef6b48850d98aee04c528b0693be13ed1bb4040e8e96cb13c316143f0815cd68d1bb7931a3d9b88a3d" );
            add_init_len = unhexify( add_init, "a2c49aa6f3f92e36266bf267af5877ed" );
            add1_len = unhexify( add1, "566522085426b76bdef152adefd73ef0f76eee4614bc5a4391629ec49e0acffb" );
            add_reseed_len = unhexify( add_reseed, "30ef9585148dd2270c41540a4235328de8952f28cf5472df463e88e837419e99" );
            add2_len = unhexify( add2, "adc46e0afcf69302f62c84c5c4bfcbb7132f8db118d1a84dc2b910753fe86a2d" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "4edc4383977ee91aaa2f5b9ac4257570" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_10)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "ab7bca5595084bccdba80ade7ac3df2a0ce198fa49d29414c0249ec3d1c50d271ca74ba5c3521576a89a1964e6deded2d5ba7ff28a364a8f9235981bec1bedfa" );
            add_init_len = unhexify( add_init, "43852c53041a3a4f710435dbd3e4382b" );
            add1_len = unhexify( add1, "c5612a9540b64fc134074cb36f4c9ea62fff993938709b5d354a917e5265adee" );
            add_reseed_len = unhexify( add_reseed, "eee2258aba665aa6d3f5b8c2207f135276f597adb2a0fbfb16a20460e8cc3c68" );
            add2_len = unhexify( add2, "a6d6d126bed13dbcf2b327aa884b7260a9c388cb03751dbe9feb28a3fe351d62" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "e04c3de51a1ffe8cda89e881c396584b" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_11)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "b3a4a3c4d3d53ffa41b85ce3b8f292b1cc8e5af7488286d4c581005f8c02c5545c09bb08d8470b8cffdf62731b1d4b75c036af7dc4f2f1fc7e9a496f3d235f2d" );
            add_init_len = unhexify( add_init, "52628551ce90c338ed94b655d4f05811" );
            add1_len = unhexify( add1, "f5f9d5b51075b12aa300afdc7b8ea3944fc8cf4d1e95625cc4e42fdfdcbeb169" );
            add_reseed_len = unhexify( add_reseed, "60bccbc7345f23733fe8f8eb9760975057238705d9cee33b3269f9bfedd72202" );
            add2_len = unhexify( add2, "c0fa3afd6e9decfbffa7ea6678d2481c5f55ec0a35172ff93214b997400e97c3" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "5a113906e1ef76b7b75fefbf20d78ef8" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_12)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "1ab7c7d8fe8f505e1dd7ddb8e7cda962572f7004b2a14c7a7c5bcf24bd16616e2c42c50ae5db9981ccd7d0c79062ac572d3893486bd0ae1f99cbc1d28a9e4c1e" );
            add_init_len = unhexify( add_init, "0e4873c4cbcde280abc6711a66dbb81a" );
            add1_len = unhexify( add1, "e4b89e28663e853f8b380c8a4491b54121fe6927340a74342362c37d8d615b66" );
            add_reseed_len = unhexify( add_reseed, "619775878879eff9ee2189790ff6f187baed4ed1b156029b80e7a070a1072a09" );
            add2_len = unhexify( add2, "ba3d673e5e41bd1abbc7191cc4b9a945201b8fef0016e4774047ee2abf499e74" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "4758fd021c34a5cf6bea760ad09438a0" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_13)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "748a5f5fde271c563a8f8d15520d6818f7ed0efb9b434adf2ff9471b391dd225b37868179ffa9a6e58df3b1b765b8945685a2f966d29648dd86a42078339650b" );
            add_init_len = unhexify( add_init, "0684e8ef93c3363ba535c4e573af1c24" );
            add1_len = unhexify( add1, "e90c82153d2280f1ddb55bd65e7752bf6717fbe08c49414f6c129bf608578db7" );
            add_reseed_len = unhexify( add_reseed, "c17e97c93cfabe0b925ca5d22615a06430a201b7595ad0d9967cc89a4777947d" );
            add2_len = unhexify( add2, "3d554c430c8928dcdb1f6d5e5a4306b309856a9b78c5f431c55d7ebd519443bb" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "d3da71af70e196483c951d95eb3f0135" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_14)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "e2366eec626bfd9cb932bcaa0569de6a7a37cf1dfde1f25d00d1a0c89fe25fea592cbd2af7c8202521fa48e15f7cc7e97e431b222b516a3ad2bb7b55b7fcf7f4" );
            add_init_len = unhexify( add_init, "89b885ddb12abc4f7422334f27c00439" );
            add1_len = unhexify( add1, "c77ee92bd17939efe9bee48af66589aee1d9fe4cd6c8ae26b74b3799e35342a6" );
            add_reseed_len = unhexify( add_reseed, "23e80d36ca72ecc38551e7e0a4f9502bed0e160f382d802f48fb2714ec6e3315" );
            add2_len = unhexify( add2, "6b83f7458dc813ce0b963b231c424e8bced599d002c0ef91a9c20dcc3f172ea5" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "81d13a6b79f05137e233e3c3a1091360" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_0)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "77de4e5db3b308c38c814228583dfd1eb415771f4ae30f9cc2d35b48075286a4e8c2c6f441d1aac496d0d4be395d078519e31cb77d06d6f7fd4c033bc40fd659" );
            add_init_len = unhexify( add_init, "ff568be02a46343113f06949a16cc7d9da315aef82f5681f0459650e5e180e65d1d77b00e5ce3e3f9eb6c18efff4db36" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "448ac707ba934c909335425de62944d6" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_1)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "667d3ed9f41a154ea33b55182b8bee4d7d46eff8e890c7036cf7c2665d44c28f9e3a8cff166dabfaf262933d337e729e0b6a60a51d00ba18f877bdc9d0cc659e" );
            add_init_len = unhexify( add_init, "6f092b85eb9f96427642f69467911172cba6df86e0db08d04e824cde6fb91d9b9af2cea53f42d53c45ee3e69a2327172" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "16a200f683ab862947e061cddaac5597" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_2)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "80e56f9893beb9f22b2b03caa8f1861d5b31b37f636f2ccbc7e4040ad3073aa20f2f3c6bfefc041df8e57e7100794c42732b6d4b63d8bb51329ca99671d53c7c" );
            add_init_len = unhexify( add_init, "26e635a6a2b6402b968c1eea13c6a980a0ee9b8497abc14fccdc5bf8439008861f74de2c200505185bf5907d3adc9de2" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "807586c977febcf2ad28fcd45e1a1deb" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_3)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "c963e17ef46b7b2c68756019704ec7435ec093c423600b3f2f99dd8989f8539a11b1b0598e93e84d50b65e816e794421ab546b202e4b224a8494538dda85da82" );
            add_init_len = unhexify( add_init, "b239c485d319ce964d69bd3dbc5b7ab9cc72ac9134a25e641bcd3c8b6f89e7e08ef2d0a45cf67667a4e2e634b32d73ff" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "2a3218b4d59f99bd3825631a6eefb09c" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_4)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "71a440b70a2b5ce41b85de27d987fa2a0628d7990dd7cd1460fddc5410ce6e9bb0ae4f90231f45bc71188fd94e4170389a8bbe4a7e781c95c9a97ad78ba7d07b" );
            add_init_len = unhexify( add_init, "0239545a23735b803ae7cb7766194917d6cce164f7ec4f65c6ccd5ec1db5297722d4b7466589da4d39f4585856bc1d7e" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "9dafaa8b727c4829dda10a831e67419d" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_5)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "d8908cfc1ea8518c1442e46731f30fdad85399894db262b8f4fdc0dbcbf11b60b60b25d3108f4b169fcbef621a14c635525fa3af8ccef6b91f808479509967f4" );
            add_init_len = unhexify( add_init, "237e8916eadd65e3422fe59ab257b7e6957fe24f760b499fbd052241879e8294b01d2169ec2b98f52660d9f5170dee22" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "593c39c56bb9e476550299ee8d85d2fc" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_6)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "6767c3eb6ba1b19412c32bfe44e4d0317beba10f3abea328cda7b7c14109b72046c8691c1c7b28487037d381f77a3bbc8464a51b87de68bdc50ec9c658f915ab" );
            add_init_len = unhexify( add_init, "28b6639b415c79012c749dc2a0d18433ec36eda55815f0841241453fa11b9d572b7c29208e01dbb0be91e1075f305d7f" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "e390806219fa727e74a90011b4835ed6" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_7)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "510b0dc06e84ceb901c7195c2f00ad7a04bdd75e0ab52b3d2cd47ddfcd89248dd58e3f1aa8c1ffe306f493905f65369eaed2a5b337dff8ac81c4c1e8903a6ad5" );
            add_init_len = unhexify( add_init, "ce735a8549fc3f9dfc7b96bf0d48936a711439ac7271d715a278718aca9e2fe3c801030bc74b048ac1e40852345e87cc" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "ba871ba5843083b553a57cf8defa39d7" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_8)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "97511ae52590a0b64b75c37e10b89671880d2d6e8f90780ac27263dbc0e32d0824be5e80a88cf8fc3d4c607eb873c0322d09b9ca3498c4015c53ca6fee890093" );
            add_init_len = unhexify( add_init, "841ea92fa42c06769c5c52fe152d07837b8ff0048392caa5dd045054353d363b25439eb5885e96771dded4005f2baf42" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "a8fb31362bd997adf4d9116e23dbaf10" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_9)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "bafc0ba64669c9a36514bde6169034101f29e2a0a4b9a55c0aae7dff0c5aca2371b523e26dc44bf75493bdaa023d1555294178288b70f1ae72150d9f7265b4e6" );
            add_init_len = unhexify( add_init, "55cd76fa5f004b97bb8e14170f79f52715d18c60f142b06d16e8e06c274798190a79c8b325163989d86323c03dbe0d68" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "fa16dbdaf01b3c202426adabf61fa64a" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_10)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "92194e2c700fa724489683d0b6ddcf72c89b9c3f3ff584e802ae426be4908b1ade093bcf9baf7738b988dc0fde1739498a97c9610da853a7c83981c6a7b68096" );
            add_init_len = unhexify( add_init, "ff3f3098fa3d2b23b38ed982e7afb61d46b4848c878b9280f8e5ed6bd81176e76f0a2a85071a411829cf84421c22f23e" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "f85490426dc243ba09f9719bff73545a" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_11)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "7c3806a32ccf3252ac27a92a07209cd7000b160faa70b9024420b903587d1d77f002d3abe28b563d32ccc502b88f83bc5996f3dbbf0f57835839eadd94563b9d" );
            add_init_len = unhexify( add_init, "7242c1020a63770cccf6f8100970990232a9d11d61c9b0d38fe5e7a568a86252a66481212e5d53c868561298dd5bdeec" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "2232181f08c1569efaad1a82bcb5f3ba" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_12)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "fdae5f1ea253108fcb255d215a3ce1dc1d101acf89de4423b75a74619e95f3feaa35b5e0bec430b0ad9567df818989c36c77742129af335c90ceb6dd79c7d2c4" );
            add_init_len = unhexify( add_init, "a2e445290fed8187df6d2a57e68385bb62d700cb8f140410766b53e69e6a0f2939bbfa7ce091525c9051f064e383a2e1" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "3841e2d795b17cb9a2081d6016a1a71d" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_13)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "77bef884a91126564b3214029ac6842d86e4c1fa283e33d6828d428377416f66947e39a4a6708e10bfdae8337a6f302420a6649fc109d0f094c18c1e9361375a" );
            add_init_len = unhexify( add_init, "bc885454e385d911336dda9b7a609a6a7079a4a5a860fcd704161c34658bd98685bb03418b7f24f2ed9475eb8ceb232e" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "ea20780ed280d8109f811a6a398c3e76" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_14)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "56940a6fc4823c9e42e8ffed63fc3cf46d0a2b305c236a511b0b5ec7005ecd8989bf2006ebe52ed55845f7cc25d3d0086cece95f0bff6fa7e17ddf474704abfe" );
            add_init_len = unhexify( add_init, "c1825cf00cdc2da93adb3e7a33c1f3a76c49166887883744ea2683ddca23f31900f25c434364c992a6d913f753a9c42a" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "b037c7f0f85f4d7eaeeb17f4c8643a74" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_0)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "5d85c56d0d20ee39958a90f301d2f8bb136fa34d09b41a0c9375114a0df9c1dcdb2a62c4be398d9eaf2440949b806f0e5a977da608eeb652a41711d1e9b72655" );
            add_init_len = unhexify( add_init, "19b83c0deea6463a3912d21ffc8d8041a5b30640352abc9652770cfca99dc53c9c09942ddd67b91f4da50a8615462ce4" );
            add1_len = unhexify( add1, "9c1db928b95c84cb674060a6d2f6b7a6a5d43e9ee967e9f821bf309ca5f8821f" );
            add_reseed_len = unhexify( add_reseed, "a3111cb57365c617df0b0bb3a1aada49ca789bc75903eeb21e42a7d3d0dd0825" );
            add2_len = unhexify( add2, "ce7f557c70676987d13aca60bc4585147efeed97be139871a1b29caa1e180af9" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "4a49430277d64446e2fa75763eb79ec6" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_1)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "2975a099f7e6530e5576534c25171f39131d6bffb99259f7f2bbf7d77de9fb1e829052b54a9631a733113021692eba1097438347c6de82307a0c2bb308edf065" );
            add_init_len = unhexify( add_init, "239f21be6cda23e8660c8a5e04c79f6dad6f363ac6dcffd9228699ae43fbce5ac3c51645500cb3eae68f0b604dc4472c" );
            add1_len = unhexify( add1, "d451a54584e6d1d634217379e7e60e67303e19dd4ba63b097899c7349a5a7433" );
            add_reseed_len = unhexify( add_reseed, "a33dc24c6a656eb26275415581d568b7c2424a9c5fb9e2944ca35ecbf641f713" );
            add2_len = unhexify( add2, "8dfccc62379af46844df136122b72a878d9d61b40ccaa029b09e6b9f0b4d0192" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "005e91760d89ecb64b5fc3b0e222fca3" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_2)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "37c94d11ed0e93b8199d43d6eb242165dddd12fe39c0bea4cdef6bcfeb5d17bb866f080a9daef128f685fb3bc59c945927fb0aa3e17068515c3c92fbdf04a228" );
            add_init_len = unhexify( add_init, "e326abbe1db3ead3738d2ca4d9f1d62080cd23ff3396f43a0af992bed2420cec6661dfaac83c3c4d83347ac840f7dc14" );
            add1_len = unhexify( add1, "1ff41405dbb3b12b8ddc973069edc2d2801af0e0dc9bde2cdd35c5b2d4091509" );
            add_reseed_len = unhexify( add_reseed, "138b6d2eabef4b32174afb0156ad1df570cf6e5f6ebde5d19cc30daffd9ca4f2" );
            add2_len = unhexify( add2, "f27cf7422808c54c58fcdde1cece92f5342c7a10ac43ab3b2e53362b2272e3ad" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "506d6fae6fff9f222e65ac86df61a832" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_3)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "514ec8c02439290853434e75e3d0bd159eacd5ac13b8f202cfd5c36cdc0fe99b53a1b7a1619e94eb661ac825a48ea5ef8bb9120dd6efc351e39eb7cc5223f637" );
            add_init_len = unhexify( add_init, "cb0229d2bb72d910b0169e8f93318905aef8dd93ed91a2f8388545db32db3f2489e7988b50de64c49a9f7feb5abe8630" );
            add1_len = unhexify( add1, "a6ed69c9216c551793107f1bdaa04944f6d76fe4474f64bb08b0ebc10a18f337" );
            add_reseed_len = unhexify( add_reseed, "e0bc1cc56fdfeef686e0c7ec359e2e8bd48d76c8643c40d12325328170bbf702" );
            add2_len = unhexify( add2, "87c5b23aa3c100ff9e368fc47534ff8fa2f9e2bfd3599519ee6f60164485cf6d" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "bd419968f636e374268ccdd62403f79c" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_4)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "9facd9f4587819acb358e4936d9f44b67ddf82616e79a44ffd6a2510f652f6b9cebc1424b5c642362b19f63c615f49686df66a8f80ddffb56ce0c0d8540150fb" );
            add_init_len = unhexify( add_init, "bdd156ef3c4e09b77fe8781c446eac55b562e4ee1b7d15515a966882d4c7fadb0fc7b37554ba03908838db40499ded5b" );
            add1_len = unhexify( add1, "35ea316fe302786f626e3831530622b62eb33a3608d4af3384ecfcbd198f3f05" );
            add_reseed_len = unhexify( add_reseed, "8d4fae22290b6ef8618ded1c3412e85fab7b8d17fb9cbd09dbc87f97279cc72d" );
            add2_len = unhexify( add2, "2f54928372e4ce447201427a3ae05769ae1c54b2e83bdc86d380a90b07f2890c" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "8045e8da88b1bc126785c8a771db5354" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_5)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "36895f574e9e9d08e6c885d305eb4764c1e5689d1f99c2462b3ebdf659e8ce43818dfc886ec797843bfee361b554cd5f969b0c7b0381b53f4afc1bcadbf7eb1c" );
            add_init_len = unhexify( add_init, "154876298a1b63334624b367da984eb31d7260abe79ced41de35ba68a716233a5df0937b90f89dde7fd55a9693c9031f" );
            add1_len = unhexify( add1, "c3a46105c50a167a5b0391053f3814a06c90cea2c1fa9329d97fdbc62887ff6d" );
            add_reseed_len = unhexify( add_reseed, "54c7d66c65dbddb4665981bff0f503de37d724362aeb67abce6a870fd6a7398a" );
            add2_len = unhexify( add2, "58204ca953cbd46dd6c8870b358cba77c436870db49bcd3e2f92697bb580b460" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "cd903c0f11ea701214f91715cfec11a3" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_6)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "1cd97b6e6e7f19401e409aea7b3ec33a8faefd71402b8f34a73c1cb1af215e0e87debe68bce590d41c1f90c6ad9db3d30b3901862e076d765ffdf58776e5fb7e" );
            add_init_len = unhexify( add_init, "94e273fde1e699f84aeef343eb0277c50d169bb5496575301021a2be50df6a555d1422ea88e0e4d905158e93fd8d0089" );
            add1_len = unhexify( add1, "6ee75e9f9aee6ac93e20f742f20427e5eb9b4ad2ed06fbba8c7b7870a96941ac" );
            add_reseed_len = unhexify( add_reseed, "0ba60399893ede284372bc4e0a37702a23b16aa8e5fe70ea95429af87ff291aa" );
            add2_len = unhexify( add2, "94bd2b51c32d29cd14e2123221e45ec0cf1f38766fb6bb0716856d0138f6fa39" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "831793686abd406f7b385cd59e497b18" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_7)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "de6d2a3b6ad9af07058d3b1d1976cf61d49566b965eb4e9b74a4cad8e286e7a40b254b860e2e209a8cb4cff3a8e615b84f5ae7505957a758e266a4c3e915d251" );
            add_init_len = unhexify( add_init, "5a699113ebf98bff9cb780ce29747a61ba2d7581a5716065d018c89348d7c2ed3f5bba32442cd192c1e37b77b98f5791" );
            add1_len = unhexify( add1, "ed18c16a61ba5ecc0755f94c286390a6d46e6e26439dadd36c83ebdee42b4b4c" );
            add_reseed_len = unhexify( add_reseed, "7c4550d058b85580be2053fd9d933c87041c5c3f62a5b6b303259dafc90d9041" );
            add2_len = unhexify( add2, "ebebfcb9b4b3595e516939ca0688422bbdfc4b9f67b0d6619757cb315b7d7908" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "1a5a496aa2268483444b3740c9cc4104" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_8)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "4765399ccbbf3d33433bb992ee29e4381f28d800b05431f1c5b3e949c5db72c582bfe8ba08db1575b866816cabbe5e1d31d8a870ceed49fb75676c97020d1f22" );
            add_init_len = unhexify( add_init, "42450f2689b87a3dd940f3b9e3b32d4654c725a24ddd2c22f006694321dacf1980b50f7ac0401626453ec836039bfdc9" );
            add1_len = unhexify( add1, "6ee5a7613c25ecec263a2fd2288948b2df9a05d50040c4031b0653878fdb067f" );
            add_reseed_len = unhexify( add_reseed, "68a1038481be7412d6a7c8474d4b2a2535c9b55ea301ee800d5a846127d345cb" );
            add2_len = unhexify( add2, "7a1915cf78e6da2dc7840cba40390d668d07571608b77857d2224c4531c17bb8" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "80a6c622e64495f9a391f5a8a9c76818" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_9)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "d2f92706ca3fb9ced8183c74704440d7eedee1542c2e812f65afc83f4b62dadf1c51fa68f8d5f457a893211c8afc82c93e6a1e15822eff0d4ada6efd25d271a0" );
            add_init_len = unhexify( add_init, "873869e194201b822b140bdd7797dd1ed408f2190b759c068b7019e6707f60751e101d3465c4ec57dbf9d1ea7597fa44" );
            add1_len = unhexify( add1, "8d0393d2a1ae8930ea88773adfa47b49060f0bf2d3def2acc57786bfbd1e2d6f" );
            add_reseed_len = unhexify( add_reseed, "5bcf5ff4fbd9eaabf8bf82ec7c59b043fd64b0025ad1ab2b384e399b9e13147a" );
            add2_len = unhexify( add2, "6e2d05e286c90502a3abf2ee72ab7ffb520ce5facfb27e095787a09a412abec3" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "e1ceda71b8feb4b0d14d35bbb57a79a2" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_10)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "34bc292809674352ffb60786dca59ec799188aa401b366a48cdeddf37c12ee4c666f8fb3a0d53df4cd7191166d50ff01d992f94cd92da7a385ffe5795b197ced" );
            add_init_len = unhexify( add_init, "1fecb5fe87c2a208b4f193e9c3ff810954c554150d544baea1685fb4774320315d5cb651be493ef120ef6966e3e7518c" );
            add1_len = unhexify( add1, "38249fed34a907768eac49267c2c613a65154eec5b73b541d7d7b314b5080061" );
            add_reseed_len = unhexify( add_reseed, "115be9cb914b50480fffe078d8170870b56129a0a74271dee063f8b2049e1be3" );
            add2_len = unhexify( add2, "69fa6faf7223f5bb1b55f35a544f78181579b1745990053357916fe507e51db6" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "60cc92d3ba3ff0715f5627182334ed1b" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_11)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "4aa6917a5c9f370590d70536fdd89c916fec5e5bcbade8c6a6cfcf5b232c98a6b3e6b79a2dfb0778fbc3f1da7b06044d7b0fa2c04ffc3b71324aca1ee19f936b" );
            add_init_len = unhexify( add_init, "4d283eb5ecd85a1613c975e24832770643613c9a5aee0d8649bc0d68c89cf1ea6ec3a1a22eefd9e212d602c338d64c6e" );
            add1_len = unhexify( add1, "05a7092a684ba7a7fbd33533f9be58a4140a3855d4c5f44a31d665a0720c1739" );
            add_reseed_len = unhexify( add_reseed, "557ef1bedc890d1543de6cfeb25642782683d77a46bc8aa0836b07157599c7c3" );
            add2_len = unhexify( add2, "e87e45073ff8e36c38b128cd2275a160e431787b5e81f6c2fd7a37909eb72ea5" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "31ecfb1bcf3253ba5f71b185a66c7cff" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_12)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "22f8ad57a2dfa8010e2865ad6263823652917b84dfea61f639efdb0fdbb35c6341ca7721095d69686212dffe78410c0d0db94f04756d52e7d76165d5a1d516d9" );
            add_init_len = unhexify( add_init, "a6f488104a6c03e354d5d1805c62dcd3016322d218747fa83f9199e20f6ab1cfbc2b889536bda1187f59b7294d557ff2" );
            add1_len = unhexify( add1, "fb9951d563f7aa88db545874b1a3049c5f79774d486e7a28aed1ed75f59224a5" );
            add_reseed_len = unhexify( add_reseed, "b1ea7c6b53e79e4e947e63086dee32dcc17bc4f27fba6142f8215ec081cdd5c9" );
            add2_len = unhexify( add2, "0d12cc0a39bfbf87194e4070f6b54caaabbe48fa192b96cfed2a794d95fa299d" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "62a1c5678e6e8fc738d375e2ca48751f" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_13)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "d8be0ec1119ff959c32c9cf29914e3f7bf2b01bdbf806c2d9ba119ae2a2cfb565871762b02ee7bf68f1d280532fd7ae7368517f6f751739b228d23df2f207f35" );
            add_init_len = unhexify( add_init, "9d67e017e0abdd7c079bc0354f33dab696ad64146802f06d6cefd9cdefbf55b197f5899e5efaa269cc0432c87648ce18" );
            add1_len = unhexify( add1, "74a5e24477e8759bedfbaa196f398777108392efb8c64c65c0c9ecd6cd3b5f04" );
            add_reseed_len = unhexify( add_reseed, "70cbc6cfe1d6ab4bc30d66fa162d5d4b3029e4b1b9d759f3eae17fb508e91a46" );
            add2_len = unhexify( add2, "d3c538e042f0eb796b4af9b4e65cd850425c72e2c896fcea741c17172faf27d9" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "559a5e04b75cec250aac2433176a725e" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_14)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "9ded87d289412dfda8935e5b08ec66b68abd1bae1fc5363e4341f58db954f1f9bc4b681c0d930ba080f85f8fd04c173cb2b77723ce67692efa7ade48b82b6926" );
            add_init_len = unhexify( add_init, "10914608a6d373a26c53ab83014283b678d73dfea65b4a3540af17f2fafa3b3cf698925b423edb9f946b906f43110795" );
            add1_len = unhexify( add1, "225159b4c679094f277516b2335b1e8b7d0a7ea33fd56822906d481fe412586d" );
            add_reseed_len = unhexify( add_reseed, "4967cd401cd466aba0be5f55615ca0d9fb8adbde5cb4e6ae3a0159fcd6c36bf0" );
            add2_len = unhexify( add2, "fec14f325b8b458ddf3e7f2e10938f4c2d04c8d9885bb5b9277bdc229c70b354" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "1cd5c0bdeb87c79235bead416c565d32" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_0)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "2462ad760ddbca4e013688bf61381f190c7b2de57cbeeec81d6ab7b6f067b75adc3545887f8d2aa5d9b9dfcbfa425d610faa9c247eb5d71145f302918e908ae5" );
            add_init_len = unhexify( add_init, "b023f6a6f73d4749b36eb54867994432" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "c0620c68515a4618e572db6e4c14473d" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_1)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "56b2e11d5c2d87d2c9c90c285e0041beb4594a6efdd577580095612e50cf47c0b76208337e1e18453082d725629667d86226ab22944bbfb40c38b7986e489adb" );
            add_init_len = unhexify( add_init, "7e0fcd953c1c8bb8d03d7a0e918fb59d" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "7194eee0d333fa5282dc44db964ecf5b" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_2)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "28e592fd9db72b40ae4888078aedde260f6de4f0472a7601258e694d7bb6af6810ff4eabdffb332932765fa1d66650fb78cc2be484c0ba803eb9a2502020e865" );
            add_init_len = unhexify( add_init, "0130217d4a3945402ed99d7b8504fe4b" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "4652f0545385fdbe02d05aec21668608" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_3)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "c561ab6acfbfb98879982ac7add92b80471e0154b77ccc9fd98e7c2013c411e8075948e97ab4db7505797a99d456e54e6585042efeff7e3970e399ea0d27537c" );
            add_init_len = unhexify( add_init, "07854447e33521d2d997d90c0887f42d" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "1a14a810c11b4f0af23c6467c47bbde0" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_4)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "747c7e9aace6d4f840c7b5261e0af796c516477421d52850a7072a0ab2c768fcc80c9ba8d18b228e77a7f6131c788a76515fe31aef4ed67376568231a4700fac" );
            add_init_len = unhexify( add_init, "68a8ec01581d6066391f3e5977465026" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "a5723c43743442fae3637bb553891aeb" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_5)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "9f7d839310846bd452827a185539c0eb0f106acc7bc4de80d3521a970b23483d57826b1484d329a2d1c2ecfeaf8eeffbaa6e1a305e3f1e47b96ad48a711ad1aa" );
            add_init_len = unhexify( add_init, "1459038c60b70bae7af0da6cfab707a2" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "5fcd6bf108fe68b85f61f85c0556f5c0" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_6)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "f1ce08587ac0338b4d0b8e075b42b6501e77758b30087de028a8622fb7abd7f65e3b4f802d1a472dedb9c1a6dc9263c65918d8b7fafd0ae7e9c39e2e8684af3f" );
            add_init_len = unhexify( add_init, "a3357db173df98da4dd02ee24ce5c303" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "8a5fa11d8e78fbf1ca4e4ca3e1ae82b8" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_7)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "bf1d715b3f56c433827c9cb429bee5ca61c80a8d9b2fd4498e1c86ce703637f8f7f34056ab0039e0baa63320df0ec61de60354f2ece06356d9be3c6d1cdcc4cf" );
            add_init_len = unhexify( add_init, "212f4c80c7e9287c8d25e3b965f91a3c" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "04ac2f969e828f375b03ee16317e8572" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_8)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "ae4316424fa765179404188eb8839ce84ad8db92cb12f39089a93a2dbdc371e2fdbef1ad080eb354eecdda3a10ea66ef647aa095afa1786c01bd1c9f70d8da4f" );
            add_init_len = unhexify( add_init, "46e85752e0af82fc63932950120e4b5d" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "de576284d8ad36b31bd4f8f3da633e36" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_9)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "b964a24bf98264327c0b9e2e1c99ed1b35f534be801c996f318bc2074ed2500ba8488c4feb442b507c3220523c0041c9543133379365e65e092850a5e3f96cc9" );
            add_init_len = unhexify( add_init, "ec2459b1dd7f50df63e14e40aa4a4e66" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "4d466e2f388aae40d1b31ce1f8ddc5e8" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_10)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "d5b3277cf8badf6be86af27dd36f23ffc580847c5fcb56c4d8a42339336f185c38ffb86f4d8aa7646c1aaed6c2b0c7ae7e4d435f481d62bb01e632f6bbb2abf9" );
            add_init_len = unhexify( add_init, "acf480d54f4c66d611519b72f2c0dca6" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "746aaa5423ef77ea6b1eda47410262dd" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_11)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "94aad8c772201435543efd9013c9f5f022038db6864e9ed4141ea75beb236844da6e6a17109262bc80f528427b37d9da6df03c7dd25be233774384a7f53197ea" );
            add_init_len = unhexify( add_init, "edb80fddc595b234e3c5c03b2be3d721" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "511927f10f800445b705ea3cfe6ec823" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_12)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "967050c11050a6d99a5da428d1f0fc8068b29ba4c66965addbfd31b745cb07d2439d268ab32a5fa2b1934bf277ff586506a941768468905ed980537d8baa1d07" );
            add_init_len = unhexify( add_init, "c7790c9888b0e731ca6ccd60c32bb98a" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "978493f0cece6f94d21863a519e06dbe" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_13)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "be3120e8515a98701b4b2fb0667de2bad3f32bcbf10fb9b820956f9aa7ffa1bbbafb70002a9c7fdd1cf7e76a735261798dc60a1163919d58e39ef0c38b54b27b" );
            add_init_len = unhexify( add_init, "58c75625771df61c48a82590eeed3378" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "90f5c486e7efe932258610e744506487" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse25612800_14)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "855c0e3a7567730b11e197c136e5c22b1dc7271d4dbe04bcdfd2fc0ef806b3c05b4264ee6c60d526506622ebf6130738dba4bf35c13ce33db19487312ee691fe" );
            add_init_len = unhexify( add_init, "d3f64c11aa21bb2d12278847547fb11b" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "33ed7089ebae738c6a7e6e2390d573e4" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_0)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "2e5beadd89b663b3903d3a63c3ab5605bfb1a0045a42430e0220243c51a69f7ff7678c2f8edb7bb4a29b646f3edfaca2463f9defd342da87d22b1b8fdb012fd5" );
            add_init_len = unhexify( add_init, "132ad1c40afb066620f004f08409c59e" );
            add1_len = unhexify( add1, "150deb841d1a4d90e66e85b036d9f5a7efca726b907ae3e8f05e1d1338cdfd32" );
            add_reseed_len = unhexify( add_reseed, "fb199beeeaf3939be2a5f9e6ba22f97cdd2c7576e81eccc686facbdf8bb4f2aa" );
            add2_len = unhexify( add2, "4293341721f57e4548ce8c003531d38622446c8825904e1b868dcddc626c5164" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "66d8f3bfb78186b57136ec2c1602e1ef" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_1)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "1d33b1b257a3ae1210fa2099307916a73dd92270769697ea2d7901f56865e3cae1be94b5024d0da3880bce06f0b31231c5a889f8ba3d92a20844b61009db672d" );
            add_init_len = unhexify( add_init, "1c1502ca97c109399a72a77c8d6cc22b" );
            add1_len = unhexify( add1, "23eede46eff4a04b08dcc2133e4537b332351f8469630f11b0c8853fb762a4bc" );
            add_reseed_len = unhexify( add_reseed, "6fd9f9da108e68aea9d1cecd81c49bcd0e7bedb348890f2248cb31c4277369f7" );
            add2_len = unhexify( add2, "76bcc11bd952123f78dd2ba60dd932d49203e418bb832d60b45c083e1e129834" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "a1eee46001616f2bf87729895da0d0d1" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_2)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "5e8cc0fdadc170ed0f5e12f79a6b9e585f9d7c2926c163686a6a724495d88fabcec940d752545cae63f1792dcb966a7325f61997ba8883559ad6f6f8fc09898a" );
            add_init_len = unhexify( add_init, "c79c0a1db75e83af258cdf9ead81264d" );
            add1_len = unhexify( add1, "a2cf6c1c9e4489f504e17f385f08aa82775aa2b0a84abd0b7ee3c6b393d7fd50" );
            add_reseed_len = unhexify( add_reseed, "c7529b874e07d4b876196786d510cc038c9e1ab93c461df2474eba484ae6876f" );
            add2_len = unhexify( add2, "63c6e7f3548529386c9f47c5aece52ce8454da5db9a807a1b960f7730a61582b" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "43b7931e0b3b3769ef8972d0026896a3" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_3)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "c3dae1863d323cc78f43ccb3f632fde29130e6b23b843ff5a8d79fddc3c1f92b55cd3dcaf7848d40d189c0de7790bebb889e01be05980dcdf30d2b3333426c50" );
            add_init_len = unhexify( add_init, "b44d1dd914e88840bc65a94ee199b3ac" );
            add1_len = unhexify( add1, "41e2fce9b48642a1b9bd1695314adcdd38e1a8afe4891e633c5088c6753438a2" );
            add_reseed_len = unhexify( add_reseed, "1eb3f8bbacb0c6b901718bfd7eba29f6f87e1fe056ad442d6d38c1351a684e1f" );
            add2_len = unhexify( add2, "85570db773f3f5202967376f91a0a9c09c89cd4eddd58cdc6210335fd5e7acef" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "bd53036538d9ed904a49966b5428a2a8" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_4)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "be67434ac4d77f0f50ec5bacc8112d1480bd9f20d6b4ea768d9b51bb69c1dffcd8c30e4412127644aaa6fc453e59fb633f6a5a8c2f69e40d1863e35d4d4c0227" );
            add_init_len = unhexify( add_init, "5ef97f7af7df5cc6fa94f8428ec7be5c" );
            add1_len = unhexify( add1, "a64195b1e56cf97fd81e99fa1833d191faf62f534c874def4b8bed0ae7195ac7" );
            add_reseed_len = unhexify( add_reseed, "353cd3a8d9cd92bce82cd8d1cc198baa9276db478b0cfe50249e30c3042ee9db" );
            add2_len = unhexify( add2, "393ab4726f088fdfeb4df752e1b2aec678e41fa60781bc5e914296227d6b3dfc" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "24bdc2cad5dccd2309425f11a24c8c39" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_5)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "cc070df6aa3623f74afd85b59d1bef2b1fcd9c8093362512ff109ebfe992ed75bd58b5ae1561d702b69065eb3cc0bd328ab698d4c6ca274e96d673309b5df5df" );
            add_init_len = unhexify( add_init, "567130da4e7ecc4db0f035d7ecb11878" );
            add1_len = unhexify( add1, "42033054cefa1f20b3443f8ab7d9635ae8f047b833c8529245ba8b4aa07edba3" );
            add_reseed_len = unhexify( add_reseed, "72972fb947bff60df291888ddbfd91e698e0c1c26a346b95fc7c5dac596d0073" );
            add2_len = unhexify( add2, "af29b6a13602ba9c6b11f8dbdeb6cb52e211f9cd2fc96e63b61e3c1ec631d2ea" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "b0849f8317e043271a3fc5f2eaaaaba2" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_6)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "c4bf7a39caf26dc3f61311f54ab3095493c626a988f5abee2826c67a4f4b4d6a02329c99a6bcb5e387fa160741c871acc2929c1cc07f2f0a7ce1619eb7da1ec4" );
            add_init_len = unhexify( add_init, "2c20ae36f1e74542ed8b0a177b8050aa" );
            add1_len = unhexify( add1, "97c148dd10c3dd72b1eaaafbe37a9310ed15b23872e9f2b62d1feb91ea81ffe3" );
            add_reseed_len = unhexify( add_reseed, "23df0c30c68bf2eeb55d273a596f1f54ed916271595b906e4f7793b7a52f2573" );
            add2_len = unhexify( add2, "22f120fa09215105116919aaf8eebcb69eccd5da42feb737018a05268bf08e46" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "b7c73b9ceea2e6ca0be6a3773cdd6886" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_7)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "979b5aeafe555aeba152ed66e32e30e110df20ee1f227932a72acfb8218aec767941efaefa091c0128dad9b93b06b28fc76e01f275e8ce1c02f0eb567c914f89" );
            add_init_len = unhexify( add_init, "2076f9e116a2648e1e664b815b1b3674" );
            add1_len = unhexify( add1, "d12fb10b9fa6d2fd0f39cf76294cd44dcbfa80dca7c2f8537c75453d985ef551" );
            add_reseed_len = unhexify( add_reseed, "4228a99faf35547a58c1a4d842301dca374f1f13c6fd067b7c1b815863b73158" );
            add2_len = unhexify( add2, "a3a7d5f1e2dcf95a90715ec5fd32e7f88c38b0a452b6ccd1f107458db4f74fd6" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "8a63a5002a3636b241f0bec14fd9c2ac" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_8)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "c810cb9db0f169dbc30fda85ccb6d4c40db68d429eeb3653070db7641fbbaba60ef0ff970eaf40887b7e154e2ecd5331de7004689ec604e69927da630a8dd7a7" );
            add_init_len = unhexify( add_init, "a71015cf06ddd0a6cd72fa014cf0aee6" );
            add1_len = unhexify( add1, "5f99f45d8770041703e5a14521c501904fd05ff3340835ac0c41b86442e4939c" );
            add_reseed_len = unhexify( add_reseed, "eb7efa6e46ab926ea04c87eb9ce454f5b10717bd9d85305f27d71bea1bc991b3" );
            add2_len = unhexify( add2, "cbc80c6171d098fc81023486d327efe2415a0f32e5fa6f6793ce1d0e98783258" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "a353f6b350404f3f7b4fb724f84a948a" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_9)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "831fc8d63592b6ce358c08aeac39d67c3e48b4c2617735b6fe5e9fa44d7aee9d60f2fcf549db239d5bed9c608c94e8f8c23b32901442ac53442127377bdcf205" );
            add_init_len = unhexify( add_init, "395931837614c322d8488ec6a2c4c919" );
            add1_len = unhexify( add1, "eb261c737c0a17c8cb1ae055c143f701b74c96c852e4a76ca3ea045e7efdf5ee" );
            add_reseed_len = unhexify( add_reseed, "153276007b3843a897efbf022bd1bcabcf655c7eb8acef9baac710b339ecfd99" );
            add2_len = unhexify( add2, "a8a5cb17a2945e5b41ff370cc88ac498389b89b6cd82bb3bbde81c212f7c17d4" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "537fc2b73183d2c0c106886937a6609c" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_10)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "68c5cf31f7959ffaa83af9dd55a75ec001befbf835e42a789ac42d39d96128eb6d9b3f07ced15e57e39760390c065fb4425c19ef7184635c18e5ed28256937e1" );
            add_init_len = unhexify( add_init, "9a1983859dd6c4cb602970d705952b2b" );
            add1_len = unhexify( add1, "e06497a181a5362980579c91d263f630ad4794519a64261ede8b36cf0ac5e713" );
            add_reseed_len = unhexify( add_reseed, "714e4fc52aea763e23a1f5b18949ab8fd949f1768560559bccb49d78d51dfab5" );
            add2_len = unhexify( add2, "6b6b7f65fd472ad428df2bbb86b85067d0a6f89d9233eea92f5189a9163d0419" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "e32af8a81c59dc44540ed8845b447fdb" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_11)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "6193f0e7b33ce19fde922aec9c93f1271ebcdd296d9c8c77029b59afa2064e3159088e07e91c14a4a3dc23b6005dd8ef1425d7d2ae8282a5b30b7498b6754234" );
            add_init_len = unhexify( add_init, "230576e9518fb9a6a8391a84919b0d97" );
            add1_len = unhexify( add1, "ffaca30a256d18836a0d49bbaad599a28fc7821d71aa91b97158a492d84a6280" );
            add_reseed_len = unhexify( add_reseed, "a3da13852d0717afed7c58c52530d2ae047b645a5e7aa8cfabc11478444151ac" );
            add2_len = unhexify( add2, "e15fdaeea31c95555fc509d2a266abf78d86ca11aa2f87ce1041142eb9f82bae" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "7906f8da1e140345c191dbc2de5ead1b" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_12)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "cfbe8b1464b00bb9e0d18b04d2040ed9bd822741188812b98a440fbc66ff018ddf6c0ea20c62d01b8237bc7c3da9e3f9fb874fca79a360b4f0f967d8d02083ba" );
            add_init_len = unhexify( add_init, "e08a3a33adb4399a9be72fead224155f" );
            add1_len = unhexify( add1, "56f975849197e2eae5a2e6fb445a93c1fadf57280ac27e27c7cbea2cb00c10cc" );
            add_reseed_len = unhexify( add_reseed, "0a6d9e2d6e181addab0ea1ee89c65ce557e10fb8e8d43a24cdd27033d3fff507" );
            add2_len = unhexify( add2, "823e9400a9f563cc1fa5daf10f4ff1ab8affa18d8371f9cd0e067fcddce8caed" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "5ded298f98cffb2e7f5ea97bd50c7e3e" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_13)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "f53343a5a455132df3d1b03db39e44d933855b375d7422ad0d07dfdfb352af28946eb29980793456ec8634bf113e75783246bbd05aa8a7cb5886d372fa012f58" );
            add_init_len = unhexify( add_init, "11c13b917d9f94fd7a008566d8598e89" );
            add1_len = unhexify( add1, "ff1d8d33083023ffbe28f153bddfa9d9f3c221da16f8f20967d2508fa7752b55" );
            add_reseed_len = unhexify( add_reseed, "66a98c7d778d798617e1d31d4bdfabf8d381d38b82125838ddf43fb7f5b27dc6" );
            add2_len = unhexify( add2, "407c72d7c890c00b249be00a53ae722e5d8033c84b1e1a6a69d4b278ba5db9eb" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "67ab88156f20d03b3a1bc363daefc0c6" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561280256_14)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "3d7e2987860cbcba14a12594e1a394ee754c9a7a65cecc990bc79b5e86e672e12f8c144d843e1abca46b4759a11b3d29f4e219077a8696efadee618f254cb80a" );
            add_init_len = unhexify( add_init, "7b95343a4ac0f8c8b2645c33757a3146" );
            add1_len = unhexify( add1, "16297534a79c4ae7493178226b29e42a6f1e0066aeaee8b5af65bcefa2ee3ebb" );
            add_reseed_len = unhexify( add_reseed, "b429ee986f16fb35fe2c47c03c0918870b4560f4ec4678f9df471cbd7ca6a887" );
            add2_len = unhexify( add2, "2b14d612eb00c7fba0d8e23bf91df91daef6f8e279e0050d5497ddf0f3466c76" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "8f72c17405163090fe0bd795b65811c6" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_0)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "80bdf18288cb8adb6e3dacb09c553af2e7317c194d37f433eec27e324a0bad752899bda91fd41e5a08acdfd76007aecabc19c95a8bcede310f7320ce97aaad0e" );
            add_init_len = unhexify( add_init, "327290da2e9a19c840de8d33e425efaa5aa7a7afa4e5a812065965478d640f78520cf3c670b098943fec1914d4c8c411" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "c26222662ed3a649a1745dee5df4eef0" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_1)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "ac71ff53140c1383eb379e5311e37637af933db494e5e689d065661e9095b8302e4174c392f324fac43695d9381e3cf4626a5347938ed9e21502cbd789cca363" );
            add_init_len = unhexify( add_init, "be14f473472db07a43b7f9a517735d7f7ede2aa70dbdb729bc4f578a0dce9d7fe9fd97939cd1ef731262417b5213bd7f" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "4bab95f9f05fc36a337b6f2582c2ce98" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_2)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "bf9bf25a949d447274a8c72f1ae51399521f8aca39b1b37bb7b4d5cf3c67d55ef8dbacfb71aa9c5949416e2868b968883e517215bc20292894f8406ab39c1ea1" );
            add_init_len = unhexify( add_init, "88c31e24f4f859b668946ce73f8600621a70731440762b3c267ceab52a9d77a23d6f70ddba0e46a786697a906ccb18a3" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "841aaa0b171d1526ef365b9201adbff3" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_3)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "686f4f9ee74c3402845fbad9353d7dfeff727584d892eb64bd84b764110cbe4ac8581e7e23acb95caf12979983e8947c570264aec292f1c7b756f7184007dcba" );
            add_init_len = unhexify( add_init, "8545a0de5ea028c8e5976d5b58fa50079b20ba716f0856cc1af7b98537c895f0266b956542d2b8ca661aef5da1f7f8c5" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "f6d6ae6449b2984df8bcb69584fb16f3" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_4)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "5d1b8fa0ca2ee127d1bd41423c17b9a8c736715cc2906818e9216dfd81b7637b66c89b772b55ae707c6effa2d9ce7425df26f966646ab613d5599143cf51e5e8" );
            add_init_len = unhexify( add_init, "d6cd4b4fb9105374605deac7bb49ad792eb225daa560f2a86f66269bf9afc2ea01b6ee6f0eb4926d2f09329df6e90d79" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "c36ab451116d733eb4377de3511db5ce" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_5)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "2026cf7c1b1fe9645ab8759958ac04fb1d8938b9913c3b7f22da81e398b2c00b1921e1d4edb5d21c4531515cb0f9644fe8068685b9fca813176e6780796e8ded" );
            add_init_len = unhexify( add_init, "e73ebae0d0834fdff1829ac3d9722fe9f1bc65b5f652fae5f7615af116440e3d5709b5cddd6065d568c246820de46b09" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "98d1dce30593de8a8d5b4d956f6c684b" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_6)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "1d0dd1a87d59c69f28e118e1083d65f1ee0df31f6308a92dcc47503ec4d20a018d9821c6a7d64385724f0e941231426e028efe6d75e53ff8edf095ef1baf2656" );
            add_init_len = unhexify( add_init, "a53c1813c06b609eff9ddc77204b085ca985f22170b8ecfcbbf45ea11c45c24fcf25bc33150f9f97ce48244d5beb685c" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "035cec3a24ba7c44e5c19436c2689a75" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_7)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "aa82a5ea33439d0c16a1cc13cbae53b169f4d369bcbdae81a9a38129c65ae0ea4f720576c012f8d7eb1c0202003c39d28453a22e502b4949cf5ba23a727721bf" );
            add_init_len = unhexify( add_init, "16d5b8290693a5c40c5a526dd6d653ac54cabb5608d77bb2cb7d6270b96c2fe2de076716ae8cf0a5c781edbde861dc70" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "de4ed9d163d11e9b52470d078df4c869" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_8)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "3da9e9518eb1f1b6268e4597f158844ff672ddb414f7ec23fa66d6c86b90a732a7b3016a3387ec3dbed34eb479413d017932ebf9f2a2fea0b35d2bf4e06718f9" );
            add_init_len = unhexify( add_init, "68bfabdbb821cb978527ff18ce37c96c79ad751756551f36b6991981285a68854ec7f72f548c3395ad3ee40410064d4b" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "ec4e3e2b6b8763deb17b8611d1fe7953" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_9)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "72ebeda7342770d03bc0e531754f946ca5cca684c41f9d089fe9147fad93b6154919c5cb2e6d162fbfde7b9ff0aa590a17993ca6c80bd59eee4134fc2ce944d8" );
            add_init_len = unhexify( add_init, "171a74ab694a7d7c2baa3ccf103ad94f11094e07a955ae9ac3bad370f1448753e99b63cc23d1878ab66f94136ec2ecac" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "582ab4f105c3e1fed9593f58fc335fc3" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_10)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "8e27f0dbeae4613bcf0011105f824ed2ecb150a83a0994f8f6607833755216e016fb175e51d42370afe27b11c18477886b530c95bc31bd1c0f8fe00f61fc15a0" );
            add_init_len = unhexify( add_init, "caed30015b34064762591eba9a59f440566a6621832f650572362229e8a38cd0f5d6d322afd8444132056690d6fa5540" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "d42787e97147d457f1590c742443ad92" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_11)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "38a8b685e6bbab67824f4cc72995043ea2854f067f2afaec762c9e78ff9d585a25bc63c8d0d075d06d43f3f694733982d26cbe0648b2d0cf8053918b912c303a" );
            add_init_len = unhexify( add_init, "c58d62f8145622cd86cfbda66bc26d2ce4c5610cd9cd1c326b99b60355a6fe751783c07f2cc21ba68f1f20ca70f0ad31" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "84001709f15a2fd167c161b5d376d86d" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_12)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "f188a1ba21b1791ebf8a08d8ba555e49423d9178a561bcc1672539c3a7ba1d856eae9922c4d96c181ed045d6f1d15e855690cdae451edac60f1ca2021f1fec57" );
            add_init_len = unhexify( add_init, "dc9719050d5257152d8a7d60d3ef1fc5b8cb1700bafc7de863c019f244779c464b6214f21a2f6d0aa3ca282007615ce5" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "7540fed313c96261cac255bf83b5ae99" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_13)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "0ddd0f4a43a7b54d9abb0928a2242c378db7a95a0b206baa642afe5cd55108f412f1d727fd591bca2c76355aa62aa8638cfa1916739bc66e02b9459ccd0881ba" );
            add_init_len = unhexify( add_init, "ff057781af4a4a1eefeb26ab38f82a2efb6f065de290ebf225bd693dfb1f97455b49143bdb430324c9d945c48824f6cc" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "8b6e74a94fcac0d2f212d3594213fbb6" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse2561282560_14)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "128566fe6c5b5595742190519445c25db85ee0ce29371f4cab213400d479d2bfe27655155be0fa237173abb214f0226a2f1770802dd69485adb25e6d837485e1" );
            add_init_len = unhexify( add_init, "ef027327e47fc5875c01cb17d798fdc2b27a5c78000727842f8a516f4e8dd34afc167ae145b1e763bebdca51e2f461a7" );
            add1_len = unhexify( add1, "" );
            add_reseed_len = unhexify( add_reseed, "" );
            add2_len = unhexify( add2, "" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "76cd1553b2b73d4ef6043a09fb90d679" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_0)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "23677c04a2d6ab446b7b3c582a8071654d27859441b10799f08b788378b926ca4306e7cb5c0f9f104c607fbf0c379be49426e53bf5637225b551f0cc694d6593" );
            add_init_len = unhexify( add_init, "8e1a59210f876d017109cb90c7d5dd669b375d971266b7320ba8db9bd79b373bcc895974460e08eadd07a00ce7bdade9" );
            add1_len = unhexify( add1, "19e914ffbc6d872be010d66b17874010ec8b036a3d60d7f7dda5accc6962a542" );
            add_reseed_len = unhexify( add_reseed, "bd7a0c09e780e0ad783fd708355b8df77b4454c3d606fb8de053bffa5ecf9021" );
            add2_len = unhexify( add2, "d284dc2caf6d214f8909efc9a75297bccfc04353c2788a96f8b752749c7fec0c" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "129d256e7db6269e5a0a160d2278f305" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_1)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "ec47b029643f85ea19388b6e9de6ab22705b060ae10cee71262027d0bdff5efd7393af619bc6658612fabc78439a0bd5a01255563a96013fa130dd06fd0f5442" );
            add_init_len = unhexify( add_init, "00674e633670c9971be7af789d37d5a4ef567b3ca4766722cd8f67e09d21cbbfa08d43ea1aa259999c6a307ae6347d62" );
            add1_len = unhexify( add1, "5b92bce3f87645126daa4704fd7df98b880aa07743a57399b985ad1a00b1f2fc" );
            add_reseed_len = unhexify( add_reseed, "8199de1338c688234c77262ef35423f4695b277726c76d8b5f426399c14d83b5" );
            add2_len = unhexify( add2, "eb95f5a4d8400cec2d4e0f548b6e92636b5e284fb6b61766a1f35bb9cdc5df0a" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "9fbe95817578eb272aa9da2f509c2a06" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_2)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "a9bebd13711c0c22c94b3252654854515a9dc015fe69e688fbac9676b3d77ab67e19b020cd2427ac789ca17f656e499be3ba3ab2075ff95247c6355157eebc79" );
            add_init_len = unhexify( add_init, "2553423c3cb0fae8ca54af56f496e9935d5af4738898f77f789a9bee867dfbc6010c4e5bc68da2b922cdd84eea68e1da" );
            add1_len = unhexify( add1, "e74e45fa28697a06dab08545fde0cc26e7eca31c40aa68ee41c4de402fdcc961" );
            add_reseed_len = unhexify( add_reseed, "5aa8abf7062079929d6a131cd3844a5fb6514c07061e25cad67677d867297685" );
            add2_len = unhexify( add2, "84819109b2e09b46ba3f5464c34b28ce25a186f0e0fd83fe5fa0ab026c01292a" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "3846f3406e49040c48b5cfc9cbc75d1a" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_3)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "a691b8bf6a407c93a36d18aeced4c75f76d8397d4ecbcd4e8f820cb393186897f05c1ef668b027fc78ba6da9bd554cc31a467d47b5e534b5340c7799383ec05c" );
            add_init_len = unhexify( add_init, "856f1371454bb9aa06be897dcda9b295817c6eeb865a9acb3a89d145bfe29ce5e1b3b12b714571afdfaca7951cd47e33" );
            add1_len = unhexify( add1, "2c81d1e94b33164a177d0183d182fe7d23ef4f88444246464e58bdd0de38d82c" );
            add_reseed_len = unhexify( add_reseed, "1b5dae81c96771bea091521c0973c5af76a03e3624160e2511e57ff43a1d32a9" );
            add2_len = unhexify( add2, "bf5878e2bd139f8f058f3d834acd771514da6d4c5b9ef84466e5a4e0e4b2eaaf" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "6a5ea73aad476ce201e173d4d5a7ffcc" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_4)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "1ab9ada5eeebc3fc8e53f358b643476fcfd4dd9f092f21d2bc1c4bb1ffd01a0c5b207aaa09ff76a9cab0aa6ce62b6a65b2650ab448b8bb2e8696a7aa4b6f4e8d" );
            add_init_len = unhexify( add_init, "0436075cf8cf62ce623c2301ebd45203c98282611cfa5a12dd7c04525ffa7eb343a607af2f57feb7ce3af97e0abc2285" );
            add1_len = unhexify( add1, "62f07d1f49e40f7f472985947ac4d8ef2d58216d918f7942b9c70f43daff8972" );
            add_reseed_len = unhexify( add_reseed, "37ae758141fbc890ee7e1d0854426b2984fb1c094677e6a61546e9315bab0898" );
            add2_len = unhexify( add2, "353d1dd0c8d8656bc418a6a3ace138ecd62819d4e21b8bd87694ea683ec0cc37" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "bfee6bb4afc228da981bfe7f0d17578b" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_5)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "c36004075f5fd078137ea08de6cb15f71aeb9eca21c891cfdf7a8c0d21790c94ffa93be5fa06beb5e82d9fbf173ef9b29c18511fee2455dbbe61d6b01baf024a" );
            add_init_len = unhexify( add_init, "d004a0893bf326d50ee52e04cb3e64409f204f4e9af780d5dd092d04162d088385b1f243000914c62cba3dadf9827c81" );
            add1_len = unhexify( add1, "7d313ada131650c7a506d2c194444ed202d568544caa75bbc60e57a0b74c9a10" );
            add_reseed_len = unhexify( add_reseed, "791d60238677ff53150cf7074061eac68335c0a7cec7de43ea63a5df0f312cd8" );
            add2_len = unhexify( add2, "6754366be264deb9e94f39e92ac2894bd93c1d7e1198d39e6eddccb0ea486f4d" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "1c29795f03e3c771603293473e347ab4" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_6)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "c4d68b76dc0e785823be2da9d339dc900132f12721e8a63ebe92e36d740c5a5e5564c367bff4a52bc70b1c60c86f0bcb7c1d99c414956a259963207184f01246" );
            add_init_len = unhexify( add_init, "9a8c79b48ada409183f7260aa1415c9ee4e0b662e0fb81b5c56f85d76ed75efac5751dd4de7e7f8b53a36ee0dce2bc9e" );
            add1_len = unhexify( add1, "04c7060f36569a5d9578c718627fc2695e8d783c0c8aefca2744da6664e67c8c" );
            add_reseed_len = unhexify( add_reseed, "1d4b7d587421dea4f7f3e77fcf997607ecfeb6e665a9a184138eb5736b16f516" );
            add2_len = unhexify( add2, "8cb8daf9cda230d8d39b829b968aaa5f5d3e3106d8b693227ab1b6201b78a7b8" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "faa146098526546927a43fa4a5073e46" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_7)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "ea7a046fa1760866bcb37fecf9ade7bcea4444662ea782d6f2820b22a96bab97b4c5adcb0a50ced885121b6b85a5074444b1555d9655f4f6ded31fe15281b30e" );
            add_init_len = unhexify( add_init, "a0736a5a8b0a394625d8985b05e3a9f277c7ba03b253c0e783359a8c4c086121cb46ea469c7756d5f099f5ee8ed16243" );
            add1_len = unhexify( add1, "47f3655dd05c42454fad68e330aabca49f27c76ba05ef07b6d77fba41153c0ab" );
            add_reseed_len = unhexify( add_reseed, "a5d07da3e399cc51d136096599fcbd9779e839b1fd86f21d7d1e23acd91f9fa7" );
            add2_len = unhexify( add2, "150b028b64a988fc1ffdfc9e66b4c8dfe4fcd8538ee976c89923638ebad33802" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "6ffdc685169b174ad0dd84cdeed050a7" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_8)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "da5f9b2db13d0555846c00da96115036bb75ace66d56fc582d6cd0171e3e23335c5c2b8691e58af8899ed0204316479f849ca6f47309cae571ccb42d3d35c166" );
            add_init_len = unhexify( add_init, "d445a3d9332c8577715c1e93f119521bd31a464db08cdbd73d50080d62d5a48fba4cef2dd097ec749973037e33e8d6fa" );
            add1_len = unhexify( add1, "79346394f795f05c5a5199423649b8b5345355ef11eb4239db1c767c68afa70a" );
            add_reseed_len = unhexify( add_reseed, "c22810de9987b228c19680eb044da22a08032148a6015f358849d6d608a214b9" );
            add2_len = unhexify( add2, "7747d68ca8bcb43931f1edce4f8c9727dd56c1d1d2600ad1fb767eb4fbc7b2d6" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "f5c40babbec97cb60ba65200e82d7a68" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_9)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "d663d2cfcddf40ff61377c3811266d927a5dfc7b73cf549e673e5a15f4056ad1f9733c8ed875ff77928284dc1cdb33accc47971d3626615a45b9a16d9baf426e" );
            add_init_len = unhexify( add_init, "2728be06796e2a77c60a401752cd36e4a051724aa3276a146b4b351017eee79c8257398c612fc1129c0e74ecef455cd3" );
            add1_len = unhexify( add1, "62349efbac4a4747d0e92727c67a6bc7f8404cf746002e7d3eeffb9a9be0bbdc" );
            add_reseed_len = unhexify( add_reseed, "381c0cffbdfa61a6af3f11ccd0e543208b584c3f520130e33617564ec7a48cf7" );
            add2_len = unhexify( add2, "6974043362f834fd793de07ceebd051599163d50489441005afc9db09a9ab44f" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "df7894746c599e02d985b195ca3b4863" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_10)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "bf03a6b3e8e23ff53369b971217dc3d3f4c1211329c94847347b3aa77dc7a3e0670381573527844a1ade786f18631944558defffb9a00900ca55f97ec726126b" );
            add_init_len = unhexify( add_init, "2b65b56de410ee82e55bd2bf80e6cee356a37c3a3aa7042df45fa750a74e097b071fc18d6eed96523dd4fbb677b8c729" );
            add1_len = unhexify( add1, "59255e5cd2221316c945bd614471df76d5b2f394b8829de82e5c30bc178565e2" );
            add_reseed_len = unhexify( add_reseed, "5739bc14f0f2ef9d3393928aee67b0908adaf587650928916d8ae78b0077a3b3" );
            add2_len = unhexify( add2, "6b236cf0ee0dba0c92b26c60235d3868715a80c0efbc0c898b6f0b1ace8146e9" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "8374b571d7f2d94ce2bdadeb9d815397" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_11)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "19705743eaaaa0e8890a0faa2e0df37c820d556c7a45f04d76276f9f9ce2e7c133258ae6d1ba9cdf7745d01745763d18dcd1af2c9e9b0bed2806e60f0f9b636c" );
            add_init_len = unhexify( add_init, "8756ee2c5e381c7c1dc530748b76a6274ef6583090e555d85210e2356feb2974a8f15119a04e9b481cd3bc557a197b8e" );
            add1_len = unhexify( add1, "2b4a92b682e9a557466af97b735e2ffdbac3bfc31fd5be2cd212cfbd4b8d690a" );
            add_reseed_len = unhexify( add_reseed, "e86504f10317bbeab346f3b9e4b310cbe9fbd81a42054f358eacd08cccab6eff" );
            add2_len = unhexify( add2, "19ffad856a6675268cc464ca6fdb8afd0912143e552668528d1484c9a54592cf" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "f347fd58aff2999530e258be77591701" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_12)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "f9939592ab2b31d92ac72673da013a588ea17bbf02cfd6e79d79f8296601633d04ceb005110f266e6100040ef33194858def8b535314c73caa0e48fc4d2f6e2d" );
            add_init_len = unhexify( add_init, "f58be57e5035d5c455b17a41ccf7542ffd77f5c009e0a737118ed6c4188f78fcbdbe946bf82e1fa50fd81691de82dcf3" );
            add1_len = unhexify( add1, "bb1cb21a316d4b88093cbfc7917d614dca97090cdc8bb340d864547cb3e1fef6" );
            add_reseed_len = unhexify( add_reseed, "7e42d5439d81680c8edf5c571d548699730cfada33b650a4d510172a42b298bb" );
            add2_len = unhexify( add2, "e9e3cf180f72ba2c1a45d0a94b822943612143e0b642398796b0428ae1af6cf5" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "d0c83a4bf3517648b441d411ddcb808c" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_13)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "b8d6be3036eeb5657fb10766354d4be897bd27973b3530270ccc02a08169a2e437b30a3635eb6ccb310f319257f58d8aa030c8aab616418e0914a46131306a0c" );
            add_init_len = unhexify( add_init, "898064243e44ff67151736ce8bb6f1c759cab4aaca9b87543a1ac984ef955cd5db76c1aa56aff83f1f6799f18fe531cc" );
            add1_len = unhexify( add1, "37572428df5826e6ae5ce95db4ef63f41e908f685204a7b64edb9f473c41e45c" );
            add_reseed_len = unhexify( add_reseed, "28beda0e0e346b447d32208c6b4c42dcd567acfe1e483fb4a95ea82cb8ce55a5" );
            add2_len = unhexify( add2, "7a0fffa541d723e16340eeb960b1b9c9aae912477e0ebfac03f8f1a3a8bdc531" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "611c9f6fc5193dbe3db96cbcd276168a" ) == 0 );
        }
        FCT_TEST_END();


        FCT_TEST_BGN(ctr_drbg_nist_validation_aes_256_use_dffalse256128256256_14)
        {
            unsigned char entropy[512];
            unsigned char add_init[512];
            unsigned char add1[512];
            unsigned char add_reseed[512];
            unsigned char add2[512];
            ctr_drbg_context ctx;
            unsigned char buf[512];
            unsigned char output_str[512];
            int add_init_len, add1_len, add_reseed_len, add2_len;
        
            memset( output_str, 0, 512 );
        
            unhexify( entropy, "5c9954fd0143e62c3bf2d5734052e3c9370f7b9d75c70f58fe33b12e3997ee2c8db84f8467affd7cfd9a9e7ec60da6f31bf9bf32aedf644e4934bd1fc916bc8d" );
            add_init_len = unhexify( add_init, "50de72903b9d99764123ffaa0c721e14ad1ab5c46a34c040f25324ba1d937b8ef10467161fcf2978c2a680ac5570c6d2" );
            add1_len = unhexify( add1, "d5dc4c9fc7171fcbfdaead558a565ffd55d245a58b22ad1666ee05131e33f49e" );
            add_reseed_len = unhexify( add_reseed, "ea3114e92e6a19f53b207a0a54cd363a6d053fed0a827f92556f0a8580f7a342" );
            add2_len = unhexify( add2, "53686f069b455af4692888d11fac15cf7b4bd38e198de4e62b7098f875198a75" );
        
            test_offset = 0;
            fct_chk( ctr_drbg_init_entropy_len( &ctx, entropy_func, entropy, add_init, add_init_len, 32 ) == 0 );
        
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add1, add1_len ) == 0 );
            fct_chk( ctr_drbg_reseed( &ctx, add_reseed, add_reseed_len ) == 0 );
            fct_chk( ctr_drbg_random_with_add( &ctx, buf, 16, add2, add2_len ) == 0 );
            hexify( output_str, buf, 16 );
            fct_chk( strcmp( (char *) output_str, "9fb0df053e0345e5640aa97fedef50a6" ) == 0 );
        }
        FCT_TEST_END();

    }
    FCT_SUITE_END();

#endif /* POLARSSL_CTR_DRBG_C */

}
FCT_END();

