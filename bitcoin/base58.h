#ifndef LIGHTNING_BITCOIN_BASE58_H
#define LIGHTNING_BITCOIN_BASE58_H
/* FIXME: Use libsecpk1 */
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <openssl/ripemd.h>
#include <openssl/bn.h>
#include <stdbool.h>
#include <stdlib.h>

struct pubkey;
struct privkey;
struct bitcoin_address;

/* Encoding is version byte + ripemd160 + 4-byte checksum == 200 bits => 2^200.
 *
 * Now, 58^34 < 2^200, but 58^35 > 2^200.  So 35 digits is sufficient,
 * plus 1 terminator.
 */
#define BASE58_ADDR_MAX_LEN 36

/* For encoding private keys, it's 302 bits.
 * 58^51 < 2^302, but 58^52 > 2^302.  So 52 digits, plus one terminator. */
#define BASE58_KEY_MAX_LEN 53

/* Bitcoin address encoded in base58, with version and checksum */
char *bitcoin_to_base58(const tal_t *ctx, bool test_net,
			const struct bitcoin_address *addr);
bool bitcoin_from_base58(bool *test_net,
			 struct bitcoin_address *addr,
			 const char *base58, size_t len);

bool ripemd_from_base58(u8 *version, u8 ripemd160[RIPEMD160_DIGEST_LENGTH],
			const char *base58);

char *base58_with_check(char dest[BASE58_ADDR_MAX_LEN],
			u8 buf[1 + RIPEMD160_DIGEST_LENGTH + 4]);

char *key_to_base58(const tal_t *ctx, bool test_net, const struct privkey *key);
bool key_from_base58(const char *base58, size_t base58_len,
		     bool *test_net, struct privkey *priv, struct pubkey *key);

bool raw_decode_base_n(BIGNUM *bn, const char *src, size_t len, int base);
bool raw_decode_base58(BIGNUM *bn, const char *src, size_t len);
void base58_get_checksum(u8 csum[4], const u8 buf[], size_t buflen);

#endif /* PETTYCOIN_BITCOIN_BASE58_H */
