/*
* Simple MD5 & SHA1 implementation
 *
 * Compile with: gcc -o crypto_test main.c md5.c sha1.c
 */
#include <stdio.h>
#include <string.h>

#include "md5.h"
#include "sha1.h" // 引入 sha1 头文件

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

// 新增: SHA1 调用函数
void call_sha1(const char *content, size_t length) {
    SHA1_CTX context;
    unsigned char digest[SHA1_DIGEST_SIZE];
    char hexString[SHA1_DIGEST_SIZE * 2 + 1]; // 20字节摘要 -> 40个十六进制字符 + '\0'

    SHA1_Init(&context);
    SHA1_Update(&context, (const unsigned char*)content, length);
    SHA1_Final(digest, &context);

    // 将20字节的摘要转换为40字节的十六进制字符串
    for (int i = 0; i < SHA1_DIGEST_SIZE; i++) {
        sprintf(hexString + (i * 2), "%02x", digest[i]);
    }
    hexString[SHA1_DIGEST_SIZE * 2] = '\0';

    printf("SHA1(\"%s\") = %s\n", content, hexString);
}


int main() {
    char content[] = "Gemini";
    // 使用 size_t 类型接收 strlen 的返回值
    size_t length = strlen(content);

    printf("--- MD5 Test ---\n");
    // 直接传入 content
    call_md5(content, length);

    // 新增: SHA1 测试用例
    printf("\n--- SHA1 Test ---\n");
    call_sha1(content, length);

    // 测试一个空字符串
    printf("\n--- Empty String Test ---\n");
    call_md5("", 0);
    call_sha1("", 0);

    return 0;
}