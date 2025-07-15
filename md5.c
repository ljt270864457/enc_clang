//
// Created by admin on 25-7-15.
//

#include "md5.h"

#include <stdio.h>
#include <string.h>


/* MD5 初始化函数实现 */
void MD5_Init(MD5_CTX *context) {
    context->count[0] = context->count[1] = 0; // 用于记录消息长度的计数器
    // 小端序初始化状态值
    /* 初始状态值 (A, B, C, D) */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
}

/* MD5 更新函数实现 */
void MD5_Update(MD5_CTX *context, const md5_byte_t *input, size_t length) {
    md5_word_t i, index, partLen;

    /* 计算已处理的比特数 */
    index = (context->count[0] >> 3) & 0x3F;

    /* 更新消息长度 */
    if ((context->count[0] += (length << 3)) < (length << 3))
        context->count[1]++;
    context->count[1] += (length >> 29);

    partLen = 64 - index;

    /* 如果缓冲区足够，直接填充 */
    if (length >= partLen) {
        memcpy(&context->buffer[index], input, partLen);
        MD5_Transform(context->state, context->buffer);

        /* 循环处理剩余数据 */
        for (i = partLen; i + 64 <= length; i += 64)
            MD5_Transform(context->state, &input[i]);

        index = 0;
    } else {
        i = 0;
    }

    /* 将剩余数据复制到缓冲区 */
    memcpy(&context->buffer[index], &input[i], length - i);
}

/* MD5 最终函数实现 */
void MD5_Final(md5_byte_t digest[16], MD5_CTX *context) {
    static md5_byte_t padding[64] = {
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    md5_byte_t bits[8];
    md5_word_t index, padLen;

    /* 保存消息长度 */
    Encode(bits, context->count, 8);

    /* 计算填充长度 */
    index = (context->count[0] >> 3) & 0x3F;
    padLen = (index < 56) ? (56 - index) : (120 - index);

    /* 填充消息 */
    MD5_Update(context, padding, padLen);

    /* 添加原始长度 */
    MD5_Update(context, bits, 8);

    /* 输出最终哈希值 */
    Encode(digest, context->state, 16);

    /* 清空上下文 */
    memset(context, 0, sizeof(*context));
}

/* MD5 核心转换函数实现 */
static void MD5_Transform(md5_word_t state[4], const md5_byte_t block[64]) {
    md5_word_t a = state[0], b = state[1], c = state[2], d = state[3];
    md5_word_t x[16];

    Decode(x, block, 64);

    /* 第一轮 */
    FF(a, b, c, d, x[ 0], 7, 0xD76AA478);
    FF(d, a, b, c, x[ 1], 12, 0xE8C7B756);
    FF(c, d, a, b, x[ 2], 17, 0x242070DB);
    FF(b, c, d, a, x[ 3], 22, 0xC1BDCEEE);
    FF(a, b, c, d, x[ 4], 7, 0xF57C0FAF);
    FF(d, a, b, c, x[ 5], 12, 0x4787C62A);
    FF(c, d, a, b, x[ 6], 17, 0xA8304613);
    FF(b, c, d, a, x[ 7], 22, 0xFD469501);
    FF(a, b, c, d, x[ 8], 7, 0x698098D8);
    FF(d, a, b, c, x[ 9], 12, 0x8B44F7AF);
    FF(c, d, a, b, x[10], 17, 0xFFFF5BB1);
    FF(b, c, d, a, x[11], 22, 0x895CD7BE);
    FF(a, b, c, d, x[12], 7, 0x6B901122);
    FF(d, a, b, c, x[13], 12, 0xFD987193);
    FF(c, d, a, b, x[14], 17, 0xA679438E);
    FF(b, c, d, a, x[15], 22, 0x49B40821);

    /* 第二轮 */
    GG(a, b, c, d, x[ 1], 5, 0xF61E2562);
    GG(d, a, b, c, x[ 6], 9, 0xC040B340);
    GG(c, d, a, b, x[11], 14, 0x265E5A51);
    GG(b, c, d, a, x[ 0], 20, 0xE9B6C7AA);
    GG(a, b, c, d, x[ 5], 5, 0xD62F105D);
    GG(d, a, b, c, x[10], 9, 0x02441453);
    GG(c, d, a, b, x[15], 14, 0xD8A1E681);
    GG(b, c, d, a, x[ 4], 20, 0xE7D3FBC8);
    GG(a, b, c, d, x[ 9], 5, 0x21E1CDE6);
    GG(d, a, b, c, x[14], 9, 0xC33707D6);
    GG(c, d, a, b, x[ 3], 14, 0xF4D50D87);
    GG(b, c, d, a, x[ 8], 20, 0x455A14ED);
    GG(a, b, c, d, x[13], 5, 0xA9E3E905);
    GG(d, a, b, c, x[ 2], 9, 0xFCEFA3F8);
    GG(c, d, a, b, x[ 7], 14, 0x676F02D9);
    GG(b, c, d, a, x[12], 20, 0x8D2A4C8A);

    /* 第三轮 */
    HH(a, b, c, d, x[ 5], 4, 0xFFFA3942);
    HH(d, a, b, c, x[ 8], 11, 0x8771F681);
    HH(c, d, a, b, x[11], 16, 0x6D9D6122);
    HH(b, c, d, a, x[14], 23, 0xFDE5380C);
    HH(a, b, c, d, x[ 1], 4, 0xA4BEEA44);
    HH(d, a, b, c, x[ 4], 11, 0x4BDECFA9);
    HH(c, d, a, b, x[ 7], 16, 0xF6BB4B60);
    HH(b, c, d, a, x[10], 23, 0xBEBFBC70);
    HH(a, b, c, d, x[13], 4, 0x289B7EC6);
    HH(d, a, b, c, x[ 0], 11, 0xEAA127FA);
    HH(c, d, a, b, x[ 3], 16, 0xD4EF3085);
    HH(b, c, d, a, x[ 6], 23, 0x04881D05);
    HH(a, b, c, d, x[ 9], 4, 0xD9D4D039);
    HH(d, a, b, c, x[12], 11, 0xE6DB99E5);
    HH(c, d, a, b, x[15], 16, 0x1FA27CF8);
    HH(b, c, d, a, x[ 2], 23, 0xC4AC5665);

    /* 第四轮 */
    II(a, b, c, d, x[ 0], 6, 0xF4292244);
    II(d, a, b, c, x[ 7], 10, 0x432AFF97);
    II(c, d, a, b, x[14], 15, 0xAB9423A7);
    II(b, c, d, a, x[ 5], 21, 0xFC93A039);
    II(a, b, c, d, x[12], 6, 0x655B59C3);
    II(d, a, b, c, x[ 3], 10, 0x8F0CCC92);
    II(c, d, a, b, x[10], 15, 0xFFEFF47D);
    II(b, c, d, a, x[ 1], 21, 0x85845DD1);
    II(a, b, c, d, x[ 8], 6, 0x6FA87E4F);
    II(d, a, b, c, x[15], 10, 0xFE2CE6E0);
    II(c, d, a, b, x[ 6], 15, 0xA3014314);
    II(b, c, d, a, x[13], 21, 0x4E0811A1);
    II(a, b, c, d, x[ 4], 6, 0xF7537E82);
    II(d, a, b, c, x[11], 10, 0xBD3AF235);
    II(c, d, a, b, x[ 2], 15, 0x2AD7D2BB);
    II(b, c, d, a, x[ 9], 21, 0xEB86D391);

    /* 更新状态 */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    /* 清空缓冲区 */
    memset(x, 0, sizeof(x));
}

/* 函数把 32 位无符号整数（md5_word_t）转换为小端序的字节数组。 */
static void Encode(md5_byte_t *output, const md5_word_t *input, size_t length) {
    size_t i, j;

    for (i = 0, j = 0; j < length; i++, j += 4) {
        output[j] = (md5_byte_t) (input[i] & 0xFF);
        output[j + 1] = (md5_byte_t) ((input[i] >> 8) & 0xFF);
        output[j + 2] = (md5_byte_t) ((input[i] >> 16) & 0xFF);
        output[j + 3] = (md5_byte_t) ((input[i] >> 24) & 0xFF);
    }
}

/*函数把小端序的字节数组转换为 32 位无符号整数。*/
static void Decode(md5_word_t *output, const md5_byte_t *input, size_t length) {
    size_t i, j;

    for (i = 0, j = 0; j < length; i++, j += 4) {
        output[i] = ((md5_word_t) input[j]) |
                    (((md5_word_t) input[j + 1]) << 8) |
                    (((md5_word_t) input[j + 2]) << 16) |
                    (((md5_word_t) input[j + 3]) << 24);
    }
}

/* MD5 哈希值转十六进制字符串 */
void MD5_ToHexString(const md5_byte_t digest[16], char *hexString, size_t length) {
    if (length < 33) return; // 至少需要 32 字符 + 1 终止符

    const char *hex_chars = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        hexString[i * 2] = hex_chars[(digest[i] >> 4) & 0xF];
        hexString[i * 2 + 1] = hex_chars[digest[i] & 0xF];
    }
    hexString[32] = '\0';
}