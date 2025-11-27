/*
* Simple MD5 & SHA1 implementation
 *
 * Compile with: gcc -o crypto_test main.c md5.c sha1.c
 */
#include <stdio.h>
#include <string.h>

#include "md5.h"
#include "sha1.h" // 引入 sha1 头文件
#include "des.h" // 引入 des 头文件
#include "aes.h" // 引入 aes 头文件

// MD5 调用函数
// 修改函数参数类型为 char *
void call_md5(char *content, size_t length) {
    MD5_CTX context;
    md5_byte_t digest[16];
    char hexString[33];
    MD5_Init(&context);
    // 显式类型转换
    MD5_Update(&context, (const md5_byte_t *) content, length);
    MD5_Final(digest, &context);
    MD5_ToHexString(digest, hexString, sizeof(hexString));
    printf("MD5(\"%s\") = %s\n", content, hexString);
}

// 通用十六进制输出函数
void print_hex_digest(const char *label, const unsigned char *digest, size_t digest_len) {
    printf("%s = ", label);
    for (size_t i = 0; i < digest_len; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

// 新增: SHA1 调用函数
void call_sha1(const char *content, size_t length) {
    SHA1Context sha;
    uint8_t Message_Digest[SHA1HashSize];
    char label[256]; // 假设最大长度为 256，可按需调整

    printf("\nSHA-1 Validation Tests:\n\n");

    // TEST 1
    SHA1Reset(&sha);
    SHA1Input(&sha, (const unsigned char *) content, length);
    SHA1Result(&sha, Message_Digest);

    // 动态构造 label
    snprintf(label, sizeof(label), "SHA1(\"%s\")", content);
    print_hex_digest(label, Message_Digest, SHA1HashSize);

    printf("Expected: ddba2c9277cd909b2d4fac91a3cc754a462c7a90\n\n");
}

// 调用DES加密函数
void call_des(const char *content, size_t length) {
    DES_cblock output;
    DES_key_schedule schedule;
    // 初始化秘钥
    DES_cblock key = "mysecret";
    char label[256]; // 假设最大长度为 256，可按需调整


    // 设置密钥
    DES_set_key(&key, &schedule);

    // 加密
    DES_ecb_encrypt((const DES_cblock *) content, &output, &schedule, 1);

    // 动态构造 label
    snprintf(label, sizeof(label), "DES(\"%s\")", content);
    // 以十六进制摘要方式输出结果
    print_hex_digest(label, output, sizeof(DES_cblock));
}

// 封装测试流程
void run_test(const char *test_name, void (*test_func)(const char *, size_t), const char *content) {
    size_t length = strlen(content);
    printf("--- %s Test ---\n", test_name);
    test_func((char *) content, length);
}

// 测试函数
int call_aes() {
    // 示例明文
    unsigned char plaintext[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };

    // 示例密钥
    unsigned char key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char ciphertext[16];
    unsigned char decrypted[16];

    printf("AES加密算法演示\n");
    printf("================\n");

    printf("原始明文: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", plaintext[i]);
    }
    printf("\n");

    printf("加密密钥: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", key[i]);
    }
    printf("\n\n");

    // 执行加密
    aes_encrypt(plaintext, key, ciphertext);

    printf("加密结果: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n\n");

    // 执行解密
    aes_decrypt(ciphertext, key, decrypted);

    printf("解密结果: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", decrypted[i]);
    }
    printf("\n\n");

    // 验证解密是否正确
    int success = 1;
    for (int i = 0; i < 16; i++) {
        if (plaintext[i] != decrypted[i]) {
            success = 0;
            break;
        }
    }

    if (success) {
        printf("验证成功: 解密结果与原始明文一致\n");
    } else {
        printf("验证失败: 解密结果与原始明文不一致\n");
    }

    return 0;
}


int main() {
    char content[] = "Gemini12";

    run_test("MD5", call_md5, content);
    run_test("SHA1", call_sha1, content);
    // DES 测试封装到 run_test 中
    run_test("DES", call_des, content);

    printf("\n--- DES Test ---\n");
    call_des(content, strlen(content));
    printf("\n--- AES Test ---\n");
    call_aes();

    return 0;
}
