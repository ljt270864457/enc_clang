#ifndef MD5_H
#define MD5_H
#include <stdlib.h>

/* MD5 算法实现 (RFC 1321) */

/* MD5 数据结构 */
typedef unsigned char md5_byte_t; /* 8-bit byte */
typedef unsigned int md5_word_t; /* 32-bit word */

/* MD5 上下文结构 */
typedef struct {
    md5_word_t count[2]; /* 消息长度 (以比特为单位) */
    md5_word_t state[4]; /* MD5 状态 (A, B, C, D) */
    md5_byte_t buffer[64]; /* 输入缓冲区 */
} MD5_CTX;

/* 定义 MD5 算法的基本函数 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* 定义循环左移操作 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* MD5 算法的四轮处理函数 */
#define FF(a, b, c, d, x, s, ac) { \
(a) += F ((b), (c), (d)) + (x) + (md5_word_t)(ac); \
(a) = ROTATE_LEFT ((a), (s)); \
(a) += (b); \
}

#define GG(a, b, c, d, x, s, ac) { \
(a) += G ((b), (c), (d)) + (x) + (md5_word_t)(ac); \
(a) = ROTATE_LEFT ((a), (s)); \
(a) += (b); \
}

#define HH(a, b, c, d, x, s, ac) { \
(a) += H ((b), (c), (d)) + (x) + (md5_word_t)(ac); \
(a) = ROTATE_LEFT ((a), (s)); \
(a) += (b); \
}

#define II(a, b, c, d, x, s, ac) { \
(a) += I ((b), (c), (d)) + (x) + (md5_word_t)(ac); \
(a) = ROTATE_LEFT ((a), (s)); \
(a) += (b); \
}

/* MD5 初始化函数 */
void MD5_Init(MD5_CTX *context);

/* MD5 更新函数 - 处理输入数据 */
void MD5_Update(MD5_CTX *context, const md5_byte_t *input, size_t length);

/* MD5 最终函数 - 生成 MD5 哈希值 */
void MD5_Final(md5_byte_t digest[16], MD5_CTX *context);

/* 将 MD5 哈希值转换为十六进制字符串 */
void MD5_ToHexString(const md5_byte_t digest[16], char *hexString, size_t length);

/* MD5 转换核心函数 */
static void MD5_Transform(md5_word_t state[4], const md5_byte_t block[64]);

/* 字节序转换函数 */
static void Encode(md5_byte_t *output, const md5_word_t *input, size_t length);

static void Decode(md5_word_t *output, const md5_byte_t *input, size_t length);

#endif //MD5_H