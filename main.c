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

void PrintSHA1TestResult(const char *testName, const char *input, uint8_t digest[SHA1HashSize]) {
    int i;

    printf("%s (\"%s\") = ", testName, input);
    for (i = 0; i < SHA1HashSize; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

// 新增: SHA1 调用函数
void call_sha1(const char *content, size_t length) {
    SHA1Context sha;
    uint8_t Message_Digest[SHA1HashSize];

    /*
     *  执行RFC 3174中定义的标准测试用例
     */

    printf("\nSHA-1 Validation Tests:\n\n");

    /* TEST 1 */
    SHA1Reset(&sha);
    SHA1Input(&sha, (const unsigned char *) content, length);
    SHA1Result(&sha, Message_Digest);
    PrintSHA1TestResult("TEST1", content, Message_Digest);
    printf("Expected: ddba2c9277cd909b2d4fac91a3cc754a462c7a90\n\n");
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

    return 0;
}
