// des.h
#ifndef DES_H
#define DES_H

#include <stdint.h>
#include <stddef.h>

// 定义加密和解密常量
#define DES_ENCRYPT 1
#define DES_DECRYPT 0

// DES 使用 64 位 (8 字节) 的块
typedef unsigned char DES_cblock[8];

// DES 密钥计划结构，用于存储16个48位的子密钥
typedef struct {
    uint64_t subkeys[16];
} DES_key_schedule;

/**
 * @brief 设置 DES 密钥，并根据密钥生成16轮的子密钥。
 * @param key 指向 8 字节密钥的指针。DES会忽略每个字节的最低位，因此有效密钥长度为56位。
 * @param schedule 指向 DES_key_schedule 结构的指针，用于存储生成的子密钥。
 * @return 0 表示成功。
 */
int DES_set_key(const DES_cblock *key, DES_key_schedule *schedule);

/**
 * @brief 使用 ECB (Electronic Codebook) 模式对单个 8 字节块进行 DES 加密或解密。
 * @param input 指向 8 字节输入数据块的指针。
 * @param output 指向 8 字节输出数据块的指针。
 * @param schedule 指向已通过 DES_set_key 初始化的密钥计划结构的指针。
 * @param enc DES_ENCRYPT (1) 表示加密, DES_DECRYPT (0) 表示解密。
 */
void DES_ecb_encrypt(const DES_cblock *input, DES_cblock *output, DES_key_schedule *schedule, int enc);

#endif // DES_H