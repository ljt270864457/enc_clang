// sha1.h
#ifndef SHA1_H
#define SHA1_H

#include <stddef.h>
#include <stdint.h>

// SHA-1 上下文结构
typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;

#define SHA1_DIGEST_SIZE 20

// 函数原型
void SHA1_Init(SHA1_CTX* context);
void SHA1_Update(SHA1_CTX* context, const unsigned char* data, const size_t len);
void SHA1_Final(unsigned char digest[SHA1_DIGEST_SIZE], SHA1_CTX* context);

#endif /* SHA1_H */