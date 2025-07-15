/*
* Simple MD5 implementation
 *
 * Compile with: gcc -o md5 md5.c
 */
#include <stdio.h>
#include <string.h>

#include "md5.h"

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

int main() {
    char content[] = "hello world";
    // 使用 size_t 类型接收 strlen 的返回值
    size_t length = strlen(content);

    // 直接传入 content
    call_md5(content, length);

    return 0;
}
