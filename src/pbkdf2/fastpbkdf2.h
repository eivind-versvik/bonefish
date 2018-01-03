/*
 * fastpbkdf2 - Faster PBKDF2-HMAC calculation
 * Written in 2015 by Joseph Birr-Pixton <jpixton@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to the
 * public domain worldwide. This software is distributed without any
 * warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#ifndef FASTPBKDF2_H
#define FASTPBKDF2_H

#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

char *base64encode (const void *b64_encode_this, int encode_this_many_bytes);

unsigned char* hmac_sha256(const void *key, int keylen,
                           const unsigned char *data, int datalen,
                           unsigned char *result, unsigned int* resultlen);

char *base64decode (const void *b64_decode_this, int decode_this_many_bytes);


#ifdef __cplusplus
}
#endif

#endif
