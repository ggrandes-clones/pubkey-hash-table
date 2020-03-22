/* Copyright (C) 2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <sys/random.h>

struct entry {
	uint8_t pubkey[32];

	uint64_t some_member;
	uint32_t some_other_member;
};

enum { MAX_ENTRIES_POW2 = 1 << 22 };

static uint64_t hash_v[4];

static __attribute__((constructor)) void init_hash_v(void)
{
	assert(!getentropy(&hash_v, sizeof(hash_v) / 2));
	hash_v[0] ^= 0x736f6d6570736575ULL;
	hash_v[1] ^= 0x646f72616e646f6dULL;
	hash_v[2] = hash_v[0] ^ 0x736f6d6570736575ULL ^ 0x6c7967656e657261ULL;
	hash_v[3] = hash_v[1] ^ 0x646f72616e646f6dULL ^ 0x7465646279746573ULL;
}

static unsigned int pubkey_startindex(uint8_t key[32])
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

	return (v0 ^ v1 ^ v2 ^ v3) & (MAX_ENTRIES_POW2 - 1);
}

static struct entry *entries[MAX_ENTRIES_POW2];

static struct entry *find_entry(uint8_t key[32])
{
	unsigned int start_index = pubkey_startindex(key), i;

	for (i = start_index;;) {
		if (entries[i] && !memcmp(entries[i]->pubkey, key, 32))
			return entries[i];
		i = (i + 1) & (MAX_ENTRIES_POW2 - 1);
		if (i == start_index)
			break;
	}
	return NULL;
}

static struct entry *find_or_insert_entry(uint8_t key[32])
{
	unsigned int start_index = pubkey_startindex(key), i;

	for (i = start_index;;) {
		if (!entries[i]) {
			entries[i] = calloc(1, sizeof(*entries[i]));
			assert(entries[i]);
			memcpy(entries[i]->pubkey, key, 32);
			return entries[i];
		}
		if (entries[i] && !memcmp(entries[i]->pubkey, key, 32))
			return entries[i];
		i = (i + 1) & (MAX_ENTRIES_POW2 - 1);
		if (i == start_index)
			break;
	}
	return NULL;
}

/* Just a small test */
int main(int argc, char *argv[])
{
	struct timespec start, end;
	uint8_t key[32] = { 0 };
	int i;

	for (i = 0; i < 1 << 20; ++i) {
		struct entry *entry;

		memcpy(key, &i, sizeof(i));
		entry = find_or_insert_entry(key);
		entry->some_member = i ^ 0xffffffff;
	}

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i = 0; i < 1 << 20; ++i) {
		struct entry *entry;

		memcpy(key, &i, sizeof(i));
		entry = find_entry(key);
		assert(entry);
		assert(entry->some_member == i ^ 0xffffffff);
	}
	clock_gettime(CLOCK_MONOTONIC, &end);

	printf("%s: %llu ns\n", argv[0], (end.tv_sec * 1000000000ULL + end.tv_nsec) - (start.tv_sec * 1000000000ULL + start.tv_nsec));
	return 0;
}
