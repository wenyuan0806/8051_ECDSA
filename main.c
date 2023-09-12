#include <stdio.h>
#include "nECC.h"

/* generate random number through linear congruential generator */
uint8_t getRandomNumber(uint8_t seed)
{
    uint8_t a, c, m;

    a = 161;
    c = 193;
    m = 251;

    seed = (a * seed + c) % m;

    return seed;
}

/* please note that 8051 mcu not support printf() function */
int main()
{
    EccPoint l_public;
    uint8_t l_private[NUM_ECC_DIGITS];
    uint8_t l_random[NUM_ECC_DIGITS];
    uint8_t hash[NUM_ECC_DIGITS] = {0x95, 0x8e, 0x72, 0xe6, 0x3c, 0x1b, 0x65, 0xd3, 0x25, 0xac, 0xf7, 0xf6, 0x50, 0xaf, 0xba, 0x75, 0x32, 0x5e, 0x22, 0x47, 0x58, 0xb0, 0x7c, 0x10, 0x66, 0xbb, 0xc1, 0x5a};

    uint8_t r[NUM_ECC_DIGITS];
    uint8_t s[NUM_ECC_DIGITS];

    /* generate random number */
    uint8_t seed = 1;
    for (int i = 0; i < NUM_ECC_DIGITS; i++)
    {
        seed = getRandomNumber(seed);
        l_random[i] = seed;
    }

    /* generate ecdsa public and private key */
    ecc_make_key(&l_public, l_private, l_random);

    /* check whether public key is illegal */
    if (!ecc_valid_public_key(&l_public))
    {
        printf("Invalid Public Key\n");
    }

    /* use private key to generate ecdsa signature (r, s) */
    if (!ecdsa_sign(r, s, l_private, l_random, hash))
    {
        printf("ecdsa_sign() failed\n");
    }

    /* print out public key */
    printf("publicKey[NUM_ECC_DIGITS] = {");
    printf("{");
    for (int i = 0; i < NUM_ECC_DIGITS; i++)
    {
        if (i == NUM_ECC_DIGITS - 1)
            printf("0x%02x", l_public.x[i]);
        else
            printf("0x%02x, ", l_public.x[i]);
    }
    printf("}, ");
    printf("{");
    for (int i = 0; i < NUM_ECC_DIGITS; i++)
    {
        if (i == NUM_ECC_DIGITS - 1)
            printf("0x%02x", l_public.y[i]);
        else
            printf("0x%02x, ", l_public.y[i]);
    }
    printf("}");
    printf("};\n\n");

    /* print out private key */
    printf("privateKey[NUM_ECC_DIGITS] = {");
    for (int i = 0; i < NUM_ECC_DIGITS; i++)
    {
        if (i == NUM_ECC_DIGITS - 1)
            printf("0x%02x", l_private[i]);
        else
            printf("0x%02x, ", l_private[i]);
    }
    printf("};\n\n");

    /* print out hash of message */
    printf("hash[NUM_ECC_DIGITS] = {");
    for (int i = 0; i < NUM_ECC_DIGITS; i++)
    {
        if (i == NUM_ECC_DIGITS - 1)
            printf("0x%02x", hash[i]);
        else
            printf("0x%02x, ", hash[i]);
    }
    printf("};\n\n");

    /* print out r of signature */
    printf("r[NUM_ECC_DIGITS] = {");
    for (int i = 0; i < NUM_ECC_DIGITS; i++)
    {
        if (i == NUM_ECC_DIGITS - 1)
            printf("0x%02x", r[i]);
        else
            printf("0x%02x, ", r[i]);
    }
    printf("};\n\n");

    /* print out s of signature */
    printf("s[NUM_ECC_DIGITS] = {");
    for (int i = 0; i < NUM_ECC_DIGITS; i++)
    {
        if (i == NUM_ECC_DIGITS - 1)
            printf("0x%02x", s[i]);
        else
            printf("0x%02x, ", s[i]);
    }
    printf("};\n\n");

    /* execute ecdsa verify */
    if (!uECC_verify(&l_public, hash, r, s))
    {
        printf("ECDSA Verify Fail\n");
    }
    else
    {
        printf("ECDSA Verify Pass\n");
    }

    return 0;
}