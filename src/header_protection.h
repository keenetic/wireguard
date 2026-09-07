#ifndef _WG_HEADER_PROTECTION_H
#define _WG_HEADER_PROTECTION_H

#include <linux/rwsem.h>
#include <linux/types.h>

enum header_protection_lengths {
	HEADER_PROTECTION_KEY_SIZE = 32,
	HEADER_PROTECTION_NONCE_SIZE = 12
};

struct header_protection {
	u8 key[HEADER_PROTECTION_KEY_SIZE];
	struct rw_semaphore lock;
	bool enabled;
};

bool wg_header_protection_enabled(struct header_protection *protection);
void wg_header_protection_set_key(struct header_protection *protection,
				  const u8 key[HEADER_PROTECTION_KEY_SIZE]);
void wg_header_protection_get_key(struct header_protection *protection,
				  u8 key[HEADER_PROTECTION_KEY_SIZE]);
bool wg_header_protection_hash(struct header_protection *protection,
			       const u8 nonce[HEADER_PROTECTION_NONCE_SIZE],
			       u8 hash[sizeof(u32)]);
bool wg_header_protection_crypt(struct header_protection *protection,
				const u8 nonce[HEADER_PROTECTION_NONCE_SIZE],
				u8 *data, size_t len);

#endif /* _WG_HEADER_PROTECTION_H */
