#include "header_protection.h"

#include <asm/unaligned.h>
#include <linux/kernel.h>
#include <linux/string.h>

#define QR(a, b, c, d) do { \
	(a) += (b); (d) ^= (a); (d) = rol32((d), 16); \
	(c) += (d); (b) ^= (c); (b) = rol32((b), 12); \
	(a) += (b); (d) ^= (a); (d) = rol32((d), 8);  \
	(c) += (d); (b) ^= (c); (b) = rol32((b), 7);  \
} while (0)

static void header_protection_chacha20_block(u32 out[16], const u32 in[16])
{
	u32 x[16];
	unsigned int i;

	memcpy(x, in, sizeof(x));
	for (i = 0; i < 10; ++i) {
		QR(x[0], x[4], x[8],  x[12]);
		QR(x[1], x[5], x[9],  x[13]);
		QR(x[2], x[6], x[10], x[14]);
		QR(x[3], x[7], x[11], x[15]);
		QR(x[0], x[5], x[10], x[15]);
		QR(x[1], x[6], x[11], x[12]);
		QR(x[2], x[7], x[8],  x[13]);
		QR(x[3], x[4], x[9],  x[14]);
	}
	for (i = 0; i < 16; ++i)
		out[i] = x[i] + in[i];
	memzero_explicit(x, sizeof(x));
}

static void header_protection_chacha20(const u8 key[HEADER_PROTECTION_KEY_SIZE],
				       const u8 nonce[HEADER_PROTECTION_NONCE_SIZE],
				       u8 *data, size_t len)
{
	u32 state[16] = {
		0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U
	};
	u32 block[16];
	u8 stream[64];
	unsigned int i;
	size_t chunk;

	for (i = 0; i < 8; ++i)
		state[4 + i] = get_unaligned_le32(key + i * 4);

	state[12] = 0;
	state[13] = get_unaligned_le32(nonce + 0);
	state[14] = get_unaligned_le32(nonce + 4);
	state[15] = get_unaligned_le32(nonce + 8);

	while (len) {
		header_protection_chacha20_block(block, state);
		for (i = 0; i < 16; ++i)
			put_unaligned_le32(block[i], stream + i * 4);

		chunk = min_t(size_t, len, sizeof(stream));
		for (i = 0; i < chunk; ++i)
			data[i] ^= stream[i];

		++state[12];
		data += chunk;
		len -= chunk;
	}

	memzero_explicit(stream, sizeof(stream));
	memzero_explicit(block, sizeof(block));
	memzero_explicit(state, sizeof(state));
}

bool wg_header_protection_enabled(struct header_protection *protection)
{
	bool enabled;

	down_read(&protection->lock);
	enabled = protection->enabled;
	up_read(&protection->lock);
	return enabled;
}

void wg_header_protection_set_key(struct header_protection *protection,
				  const u8 key[HEADER_PROTECTION_KEY_SIZE])
{
	u8 zero[HEADER_PROTECTION_KEY_SIZE] = { 0 };

	down_write(&protection->lock);
	memcpy(protection->key, key, HEADER_PROTECTION_KEY_SIZE);
	protection->enabled = memcmp(key, zero, HEADER_PROTECTION_KEY_SIZE) != 0;
	up_write(&protection->lock);

}

void wg_header_protection_get_key(struct header_protection *protection,
				  u8 key[HEADER_PROTECTION_KEY_SIZE])
{
	down_read(&protection->lock);
	memcpy(key, protection->key, HEADER_PROTECTION_KEY_SIZE);
	up_read(&protection->lock);
}

bool wg_header_protection_crypt(struct header_protection *protection,
				const u8 nonce[HEADER_PROTECTION_NONCE_SIZE],
				u8 *data, size_t len)
{
	u8 key[HEADER_PROTECTION_KEY_SIZE];
	bool enabled;

	down_read(&protection->lock);
	enabled = protection->enabled;
	if (enabled)
		memcpy(key, protection->key, sizeof(key));
	up_read(&protection->lock);
	if (!enabled)
		return false;

	header_protection_chacha20(key, nonce, data, len);
	memzero_explicit(key, sizeof(key));
	return true;
}

bool wg_header_protection_hash(struct header_protection *protection,
			       const u8 nonce[HEADER_PROTECTION_NONCE_SIZE],
			       u8 hash[sizeof(u32)])
{
	memset(hash, 0, sizeof(u32));
	return wg_header_protection_crypt(protection, nonce, hash, sizeof(u32));
}
