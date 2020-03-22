/* Copyright (C) 2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/random.h>

struct entry {
	uint8_t pubkey[32];

	uint64_t some_member;
	uint32_t some_other_member;

	struct entry *next;
};

enum { ENTRY_BUCKETS_POW2 = 1 << 17 };

static uint64_t hash_v[4];

static __attribute__((constructor)) void init_hash_v(void)
{
	assert(!getentropy(&hash_v, sizeof(hash_v) / 2));
	hash_v[0] ^= 0x736f6d6570736575ULL;
	hash_v[1] ^= 0x646f72616e646f6dULL;
	hash_v[2] = hash_v[0] ^ 0x736f6d6570736575ULL ^ 0x6c7967656e657261ULL;
	hash_v[3] = hash_v[1] ^ 0x646f72616e646f6dULL ^ 0x7465646279746573ULL;
}

static unsigned int pubkey_bucket(uint8_t key[32])
{
	uint64_t first, second, third, forth;
	uint64_t v0 = hash_v[0];
	uint64_t v1 = hash_v[1];
	uint64_t v2 = hash_v[2];
	uint64_t v3 = hash_v[3];

	memcpy(&first, &key[0], sizeof(first));
	memcpy(&second, &key[8], sizeof(second));
	memcpy(&third, &key[16], sizeof(third));
	memcpy(&forth, &key[24], sizeof(forth));

#define SIPROUND (						\
		v0 += v1,					\
		v1 = ((v1 << (13 & 63)) | (v1 >> ((-13) & 63))),\
		v1 ^= v0,					\
		v0 = ((v0 << (32 & 63)) | (v0 >> ((-32) & 63))),\
		v2 += v3,					\
		v3 = ((v3 << (16 & 63)) | (v3 >> ((-16) & 63))),\
		v3 ^= v2,					\
		v0 += v3,					\
		v3 = ((v3 << (21 & 63)) | (v3 >> ((-21) & 63))),\
		v3 ^= v0,					\
		v2 += v1,					\
		v1 = ((v1 << (17 & 63)) | (v1 >> ((-17) & 63))),\
		v1 ^= v2,					\
		v2 = ((v2 << (32 & 63)) | (v2 >> ((-32) & 63))))

	v3 ^= first;
	SIPROUND;
	SIPROUND;
	v0 ^= first;
	v3 ^= second;
	SIPROUND;
	SIPROUND;
	v0 ^= second;
	v3 ^= third;
	SIPROUND;
	SIPROUND;
	v0 ^= third;
	v3 ^= forth;
	SIPROUND;
	SIPROUND;
	v0 ^= forth;

	v3 ^= 32ULL << 56;
	SIPROUND;
	SIPROUND;
	v0 ^= 32ULL << 56;
	v2 ^= 0xFF;
	SIPROUND;
	SIPROUND;
	SIPROUND;
	SIPROUND;
#undef SIPROUND

	return (v0 ^ v1 ^ v2 ^ v3) & (ENTRY_BUCKETS_POW2 - 1);
}

static struct entry *entry_buckets[ENTRY_BUCKETS_POW2];

static struct entry *find_entry(uint8_t key[32])
{
	struct entry *entry;
	for (entry = entry_buckets[pubkey_bucket(key)]; entry; entry = entry->next) {
		if (!memcmp(entry->pubkey, key, 32))
			return entry;
	}
	return NULL;
}

static struct entry *find_or_insert_entry(uint8_t key[32])
{
	struct entry **entry;
	for (entry = &entry_buckets[pubkey_bucket(key)]; *entry; entry = &(*entry)->next) {
		if (!memcmp((*entry)->pubkey, key, 32))
			return *entry;
	}
	*entry = calloc(1, sizeof(**entry));
	assert(*entry);
	memcpy((*entry)->pubkey, key, 32);
	return *entry;
}

/* Just a small test */
int main(int argc, char *argv[])
{
	uint8_t key[32] = { 0 };
	int i;

	for (i = 0; i < 1 << 20; ++i) {
		struct entry *entry;

		memcpy(key, &i, sizeof(i));
		entry = find_or_insert_entry(key);
		entry->some_member = i ^ 0xffffffff;
	}

	for (i = 0; i < 1 << 20; ++i) {
		struct entry *entry;

		memcpy(key, &i, sizeof(i));
		entry = find_entry(key);
		assert(entry);
		assert(entry->some_member == i ^ 0xffffffff);
	}

	return 0;
}
