#include <wmmintrin.h>
#include <immintrin.h>
#include <immintrin.h>
#include <stdio.h>
#include <stdint.h>

#include <string.h>

const unsigned char userkey[16] = {0x2b, 0x7e, 0x15, 0x16,
                                   0x28, 0xae, 0xd2, 0xa6,
                                   0xab, 0xf7, 0x15, 0x88,
                                   0x09, 0xcf, 0x4f, 0x3c};
unsigned char Key[176];

unsigned char state[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
__m128i Key_Schedule[11];
unsigned char output[16];
unsigned char plain[16];

__m128i AES_128_ASSIST(__m128i temp1, __m128i temp2)
{
    __m128i temp3;
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp3 = _mm_slli_si128(temp1, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp1 = _mm_xor_si128(temp1, temp2);
    return temp1;
}
void AES_128_Key_Expansion(const unsigned char *userkey,
                           unsigned char *key)
{
    __m128i temp1, temp2;
    __m128i *Key_Schedule = (__m128i *)key;
    temp1 = _mm_loadu_si128((__m128i *)userkey);
    Key_Schedule[0] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[1] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x2);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[2] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x4);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[3] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x8);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[4] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[5] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[6] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[7] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[8] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[9] = temp1;
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[10] = temp1;
}

void aesencrypt(unsigned char *Key, unsigned char *state, unsigned char *output)
{
    int round, i;
    __m128i *cipher = (__m128i *)output;
    printf("%x,%x,%x,%x", Key[16], Key[17], Key[18], Key[19]);

    __m128i input = _mm_loadu_si128((__m128i *)state);

    input = _mm_xor_si128(input, ((__m128i *)Key)[0]);

    for (round = 1; round < 10; round++)
    {
        input = _mm_aesenc_si128(input, ((__m128i *)Key)[round]);
    }

    input = _mm_aesenclast_si128(input, ((__m128i *)Key)[10]);

    _mm_storeu_si128(((__m128i *)output), input);
    // memcpy(output, &input, sizeof(output));
}

void aesdecrypt(unsigned char *key, unsigned char *cipher, unsigned char *plain)
{
    int round, i;

    //__m128i *cipher = (__m128i *)cipher;
    // printf("%x,%x,%x,%x", Key[16], Key[17], Key[18], Key[19]);

    __m128i input = _mm_loadu_si128((__m128i *)cipher);

    input = _mm_xor_si128(input, ((__m128i *)Key)[10]);

    for (round = 9; round > 0; round--)
    {

        input = _mm_aesdec_si128(input, _mm_aesimc_si128(((__m128i *)Key)[round]));
    }

    input = _mm_aesdeclast_si128(input, ((__m128i *)Key)[0]);

    _mm_storeu_si128(((__m128i *)plain), input);
    // memcpy(output, &input, sizeof(output));
    printf("\noutput:\n");
    for (int i = 0; i < 16; i++)
    {
        printf("%x,", plain[i]);
    }
}

void main()
{

    AES_128_Key_Expansion(userkey, Key);
    for (int round = 0; round <= 10; round++)
    {
        printf("Round:%d\n", round);
        for (int i = 0; i < 4; i++)
        {

            printf("%x,%x,%x,%x", Key[(round * 4 * 4) + (i * 4) + 0], Key[(round * 4 * 4) + (i * 4) + 1], Key[(round * 4 * 4) + (i * 4) + 2], Key[(round * 4 * 4) + (i * 4) + 3]);
            printf("\n");
        }
    }

    aesencrypt(Key, state, output);
    printf("\noutput:\n");
    for (int i = 0; i < 16; i++)
    {
        printf("%x,", output[i]);
    }
    aesdecrypt(Key, output, plain);
}