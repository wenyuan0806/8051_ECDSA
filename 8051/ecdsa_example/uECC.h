#ifndef _MICRO_ECC_H_
#define _MICRO_ECC_H_

#define ECC_KEYGEN 1
#define ECC_SIGN 1
#define ECC_VERIFY 1
#define ECC_SQUARE_FUNC 1

// #include <stdint.h>
// C51 platform
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned long uint32_t;
typedef char int8_t;
typedef short int16_t;
typedef long int32_t;

/* Curve selection options. */
#define secp128r1 16
#define secp192r1 24
#define secp256r1 32
#define secp384r1 48
#ifndef ECC_CURVE
#define ECC_CURVE secp256r1
#endif

#if (ECC_CURVE != secp128r1 && ECC_CURVE != secp192r1 && ECC_CURVE != secp256r1 && ECC_CURVE != secp384r1)
#error "Must define ECC_CURVE to one of the available curves"
#endif

#define NUM_ECC_DIGITS ECC_CURVE

typedef struct EccPoint
{
    uint8_t x[NUM_ECC_DIGITS];
    uint8_t y[NUM_ECC_DIGITS];
} EccPoint;

#if ECC_KEYGEN

/* ecc_make_key() function.
Create a public/private key pair.

You must use a new nonpredictable random number to generate each new key pair.

Outputs:
    p_publicKey  - Will be filled in with the point representing the public key.
    p_privateKey - Will be filled in with the private key.

Inputs:
    p_random - The random number to use to generate the key pair.

Returns 1 if the key pair was generated successfully, 0 if an error occurred. If 0 is returned,
try again with a different random number.
*/
int ecc_make_key(EccPoint *p_publicKey, uint8_t p_privateKey[NUM_ECC_DIGITS], uint8_t p_random[NUM_ECC_DIGITS]);

/* ecc_valid_public_key() function.
Determine whether or not a given point is on the chosen elliptic curve (ie, is a valid public key).

Inputs:
    p_publicKey - The point to check.

Returns 1 if the given point is valid, 0 if it is invalid.
*/
int ecc_valid_public_key(EccPoint *p_publicKey);

#endif // end of ECC_KEYGEN

#if ECC_SIGN

/* ecdsa_sign() function.
Generate an ECDSA signature for a given hash value.

Usage: Compute a hash of the data you wish to sign (SHA-2 is recommended) and pass it in to
this function along with your private key and a random number.
You must use a new nonpredictable random number to generate each new signature.

Outputs:
    r, s - Will be filled in with the signature values.

Inputs:
    p_privateKey - Your private key.
    p_random     - The random number to use to generate the signature.
    p_hash       - The message hash to sign.

Returns 1 if the signature generated successfully, 0 if an error occurred. If 0 is returned,
try again with a different random number.
*/
int ecdsa_sign(uint8_t r[NUM_ECC_DIGITS], uint8_t s[NUM_ECC_DIGITS], uint8_t p_privateKey[NUM_ECC_DIGITS],
               uint8_t p_random[NUM_ECC_DIGITS], uint8_t p_hash[NUM_ECC_DIGITS]);

#endif // end of ECC_SIGN

#if ECC_VERIFY

/* ecdsa_verify() function.
Verify an ECDSA signature.

Usage: Compute the hash of the signed data using the same hash as the signer and
pass it to this function along with the signer's public key and the signature values (r and s).

Inputs:
    p_publicKey - The signer's public key
    p_hash      - The hash of the signed data.
    r, s        - The signature values.

Returns 1 if the signature is valid, 0 if it is invalid.
*/

int uECC_verify(const EccPoint *p_publicKey, const uint8_t p_hash[NUM_ECC_DIGITS], const uint8_t r[NUM_ECC_DIGITS], const uint8_t s[NUM_ECC_DIGITS]);

#endif // end of ECC_VERIFY

#endif /* _MICRO_ECC_H_ */