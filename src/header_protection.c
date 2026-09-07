#include "header_protection.h"

#include <zinc/chacha20.h>
#include <linux/string.h>

static void header_protection_init_chacha(struct chacha20_ctx *ctx,
					  const u8 key[HEADER_PROTECTION_KEY_SIZE],
					  const u8 nonce[HEADER_PROTECTION_NONCE_SIZE])
{
	ctx->constant[0] = CHACHA20_CONSTANT_EXPA;
	ctx->constant[1] = CHACHA20_CONSTANT_ND_3;
	ctx->constant[2] = CHACHA20_CONSTANT_2_BY;
	ctx->constant[3] = CHACHA20_CONSTANT_TE_K;
	ctx->key[0] = get_unaligned_le32(key + 0);
	ctx->key[1] = get_unaligned_le32(key + 4);
	ctx->key[2] = get_unaligned_le32(key + 8);
	ctx->key[3] = get_unaligned_le32(key + 12);
	ctx->key[4] = get_unaligned_le32(key + 16);
	ctx->key[5] = get_unaligned_le32(key + 20);
	ctx->key[6] = get_unaligned_le32(key + 24);
	ctx->key[7] = get_unaligned_le32(key + 28);
	ctx->counter[0] = 0;
	ctx->counter[1] = get_unaligned_le32(nonce + 0);
	ctx->counter[2] = get_unaligned_le32(nonce + 4);
	ctx->counter[3] = get_unaligned_le32(nonce + 8);
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
	struct chacha20_ctx state;
	simd_context_t simd_context;
	u8 key[HEADER_PROTECTION_KEY_SIZE];
	bool enabled;

	down_read(&protection->lock);
	enabled = protection->enabled;
	if (enabled)
		memcpy(key, protection->key, sizeof(key));
	up_read(&protection->lock);
	if (!enabled)
		return false;

	header_protection_init_chacha(&state, key, nonce);
	simd_get(&simd_context);
	chacha20(&state, data, data, len, &simd_context);
	simd_put(&simd_context);
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
