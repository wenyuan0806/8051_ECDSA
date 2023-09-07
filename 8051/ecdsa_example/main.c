#include <stdio.h>
#include "uECC.h"

int randfd;
void getRandomBytes(void *p_dest, unsigned p_size)
{
    if(read(randfd, p_dest, p_size) != (int)p_size)
    {
        printf("Failed to get random bytes.\n");
    }
}

uint8_t genRandomNumber(uint8_t seed)
{
    uint8_t a, c, m;
    
    a = 161;
    c = 193;
    m = 251;
    
    seed = (a * seed + c) % m;
    
    return seed;
}

int main()
{
    EccPoint l_public;
    uint8_t l_private[NUM_ECC_DIGITS];
    uint8_t l_random[NUM_ECC_DIGITS];
    uint8_t hash[NUM_ECC_DIGITS] = {0x95, 0x8e, 0x72, 0xe6, 0x3c, 0x1b, 0x65, 0xd3, 0x25, 0xac, 0xf7, 0xf6, 0x50, 0xaf, 0xba, 0x75, 0x32, 0x5e, 0x22, 0x47, 0x58, 0xb0, 0x7c, 0x10, 0x66, 0xbb, 0xc1, 0x5a, 0xc5, 0x46, 0x89, 0xed};

    uint8_t r[NUM_ECC_DIGITS];
    uint8_t s[NUM_ECC_DIGITS];

    uint8_t seed = 1;
    for(int i=0; i<NUM_ECC_DIGITS; i++)
    {
        seed = genRandomNumber(seed);
        l_random[i] = seed;
    }

    ecc_make_key(&l_public, l_private, l_random);
    
    if (!ecc_valid_public_key(&l_public))
    {
        printf("Invalid Public Key\n");
    }
    
    if (!ecdsa_sign(r, s, l_private, l_random, hash))
    {
        printf("ecdsa_sign() failed\n");
    }
    
    printf("publicKey[NUM_ECC_DIGITS] = {");
    printf("{");
    for(int i=0; i<NUM_ECC_DIGITS; i++)
    {
        if(i==NUM_ECC_DIGITS-1)
            printf("0x%02x", l_public.x[i]);
        else
            printf("0x%02x, ", l_public.x[i]);
    }
    printf("}, ");
    printf("{");
    for(int i=0; i<NUM_ECC_DIGITS; i++)
    {
        if(i==NUM_ECC_DIGITS-1)
            printf("0x%02x", l_public.y[i]);
        else
            printf("0x%02x, ", l_public.y[i]);
    }
    printf("}");
    printf("};\n\n");
    
    printf("privateKey[NUM_ECC_DIGITS] = {");
    for(int i=0; i<NUM_ECC_DIGITS; i++)
    {
        if(i==NUM_ECC_DIGITS-1)
            printf("0x%02x", l_private[i]);
        else
            printf("0x%02x, ", l_private[i]);
    }
    printf("};\n\n");
    
    printf("hash[NUM_ECC_DIGITS] = {");
    for(int i=0; i<NUM_ECC_DIGITS; i++)
    {
        if(i==NUM_ECC_DIGITS-1)
            printf("0x%02x", hash[i]);
        else
            printf("0x%02x, ", hash[i]);
    }
    printf("};\n\n");
    
    printf("r[NUM_ECC_DIGITS] = {");
    for(int i=0; i<NUM_ECC_DIGITS; i++)
    {
        if(i==NUM_ECC_DIGITS-1)
            printf("0x%02x", r[i]);
        else
            printf("0x%02x, ", r[i]);
    }
    printf("};\n\n");
    
    printf("s[NUM_ECC_DIGITS] = {");
    for(int i=0; i<NUM_ECC_DIGITS; i++)
    {
        if(i==NUM_ECC_DIGITS-1)
            printf("0x%02x", s[i]);
        else
            printf("0x%02x, ", s[i]);
    }
    printf("};\n\n");
    
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
