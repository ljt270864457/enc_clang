/*
 *  sha1.c
 *
 *  Description:
 *      This file implements the Secure Hashing Algorithm 1 as
 *      defined in FIPS PUB 180-1 published April 17, 1995.
 *
 *      The SHA-1 algorithm produces a 160-bit message digest for a
 *      given data stream.  It should take about 2**n steps to find a
 *      message with the same digest as a given message and
 *      2**(n/2) steps to find any two messages with the same digest,
 *      when n is the digest size in bits.  Therefore, this
 *      algorithm can serve as a means of providing a
 *      "fingerprint" for a message.
 *
 *  Portability Issues:
 *      SHA-1 is defined in terms of 32-bit "words".  This code
 *      uses <stdint.h> (included via "sha1.h") to define 32 and
 *      8 bit unsigned integer types.  If your C compiler does
 *      not support 32 bit unsigned integers, this code is not
 *      appropriate.
 *
 *  Caveats:
 *      SHA-1 is designed to work with messages less than 2^64 bits
 *      long.  Although SHA-1 allows a message digest to be generated
 *      for messages of any number of bits less than 2^64, this
 *      implementation only works with messages with a length that is
 *      a multiple of the size of an 8-bit character.
 *
 */

#include "sha1.h"

/*
 *  Define the SHA1 circular left shift macro
 *  循环左移宏定义：将32位值左移n位，溢出的高位补充到低位
 */
#define SHA1CircularShift(bits,word) \
                (((word) << (bits)) | ((word) >> (32-(bits))))

/* Local Function Prototyptes */
void SHA1PadMessage(SHA1Context *);

void SHA1ProcessMessageBlock(SHA1Context *);

/*
 *  SHA1Reset
 *
 *  Description:
 *      This function will initialize the SHA1Context in preparation
 *      for computing a new SHA1 message digest.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to reset.
 *
 *  Returns:
 *      sha Error Code.
 *
 *  初始化SHA-1上下文，为计算新的消息摘要做准备
 */
int SHA1Reset(SHA1Context *context) {
    if (!context) {
        return shaNull;
    }

    context->Length_Low = 0;
    context->Length_High = 0;
    context->Message_Block_Index = 0;

    /*
     *  初始化5个32位缓冲区寄存器，这些是SHA-1标准规定的初始值
     *  H0 = 0x67452301
     *  H1 = 0xEFCDAB89
     *  H2 = 0x98BADCFE
     *  H3 = 0x10325476
     *  H4 = 0xC3D2E1F0
     */
    context->Intermediate_Hash[0] = 0x67452301;
    context->Intermediate_Hash[1] = 0xEFCDAB89;
    context->Intermediate_Hash[2] = 0x98BADCFE;
    context->Intermediate_Hash[3] = 0x10325476;
    context->Intermediate_Hash[4] = 0xC3D2E1F0;

    context->Computed = 0;
    context->Corrupted = 0;

    return shaSuccess;
}

/*
 *  SHA1Input
 *
 *  Description:
 *      This function accepts an array of octets as the next portion
 *      of the message.
 *
 *  Parameters:
 *      context: [in/out]
 *          The SHA context to update
 *      message_array: [in]
 *          An array of characters representing the next portion of
 *          the message.
 *      length: [in]
 *          The length of the message in message_array
 *
 *  Returns:
 *      sha Error Code.
 *
 *  接受消息的下一个部分，更新SHA-1上下文
 */
int SHA1Input(SHA1Context *context,
              const uint8_t *message_array,
              unsigned length) {
    if (!length) {
        return shaSuccess;
    }

    if (!context || !message_array) {
        return shaNull;
    }

    if (context->Computed) {
        context->Corrupted = shaStateError;
        return shaStateError;
    }

    if (context->Corrupted) {
        return context->Corrupted;
    }

    /*
     *  处理输入的消息数组，逐字节处理
     *  当消息块填满512位(64字节)时，调用处理函数
     */
    while (length-- && !context->Corrupted) {
        context->Message_Block[context->Message_Block_Index++] =
                (*message_array & 0xFF);

        context->Length_Low += 8; // 每个字节8位
        if (context->Length_Low == 0) {
            context->Length_High++;
            if (context->Length_High == 0) {
                /* Message is too long */
                context->Corrupted = 1;
            }
        }

        /*
         *  如果消息块已满(512位)，则处理该块
         */
        if (context->Message_Block_Index == 64) {
            SHA1ProcessMessageBlock(context);
        }

        message_array++;
    }

    return shaSuccess;
}

/*
 *  SHA1Result
 *
 *  Description:
 *      This function will return the 160-bit message digest into the
 *      Message_Digest array  provided by the caller.
 *      NOTE: The first octet of hash is stored in the 0th element,
 *            the last octet of hash in the 19th element.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to use to calculate the SHA-1 hash.
 *      Message_Digest: [out]
 *          Where the digest is returned.
 *
 *  Returns:
 *      sha Error Code.
 *
 *  返回160位(20字节)的消息摘要
 */
int SHA1Result(SHA1Context *context,
               uint8_t Message_Digest[SHA1HashSize]) {
    int i;

    if (!context || !Message_Digest) {
        return shaNull;
    }

    if (context->Corrupted) {
        return context->Corrupted;
    }

    if (!context->Computed) {
        SHA1PadMessage(context); // 填充消息
        for (i = 0; i < 64; ++i) {
            /* message may be sensitive, clear it out */
            context->Message_Block[i] = 0;
        }
        context->Length_Low = 0; /* and clear length */
        context->Length_High = 0;
        context->Computed = 1;
    }

    /*
     *  将32位中间哈希值转换为字节数组
     *  按大端序存储：最高有效字节在前
     */
    for (i = 0; i < SHA1HashSize; ++i) {
        Message_Digest[i] = context->Intermediate_Hash[i >> 2]
                            >> 8 * (3 - (i & 0x03));
    }

    return shaSuccess;
}

/*
 *  SHA1ProcessMessageBlock
 *
 *  Description:
 *      This function will process the next 512 bits of the message
 *      stored in the Message_Block array.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      Nothing.
 *
 *  Global Variables:
 *      Intermediate_Hash: [in/out]
 *          The intermediate hash value that is being computed.
 *      Message_Block: [in]
 *          The message block to process.
 *
 *  处理512位的消息块，这是SHA-1算法的核心
 */
void SHA1ProcessMessageBlock(SHA1Context *context) {
    const uint32_t K[] = /* Constants defined in SHA-1   */
    {
        0x5A827999, /* 0 <= t <= 19 */
        0x6ED9EBA1, /* 20 <= t <= 39 */
        0x8F1BBCDC, /* 40 <= t <= 59 */
        0xCA62C1D6 /* 60 <= t <= 79 */
    };

    int t; /* Loop counter                */
    uint32_t temp; /* Temporary word value        */
    uint32_t W[80]; /* Word sequence               */
    uint32_t A, B, C, D, E; /* Word buffers                */

    /*
     *  初始化工作变量
     */
    A = context->Intermediate_Hash[0];
    B = context->Intermediate_Hash[1];
    C = context->Intermediate_Hash[2];
    D = context->Intermediate_Hash[3];
    E = context->Intermediate_Hash[4];

    /*
     *  消息块扩展：将16个32位字扩展为80个32位字
     *  前16个字直接从消息块获取
     */
    for (t = 0; t < 16; t++) {
        W[t] = context->Message_Block[t * 4] << 24;
        W[t] |= context->Message_Block[t * 4 + 1] << 16;
        W[t] |= context->Message_Block[t * 4 + 2] << 8;
        W[t] |= context->Message_Block[t * 4 + 3];
    }

    /*
     *  后64个字通过前序字计算得到
     *  W[t] = S^1(W[t-3] XOR W[t-8] XOR W[t-14] XOR W[t-16])
     *  其中S^1表示循环左移1位
     */
    for (t = 16; t < 80; t++) {
        W[t] = SHA1CircularShift(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }

    /*
     *  主循环：进行80轮运算，分为4个阶段
     *  每个阶段20轮，使用不同的布尔函数和常量
     */
    for (t = 0; t < 80; t++) {
        /*
         *  选择适当的常量K和布尔函数f(t)
         */
        if (t < 20) {
            temp = SHA1CircularShift(5, A) +
                   ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        } else if (t < 40) {
            temp = SHA1CircularShift(5, A) +
                   (B ^ C ^ D) + E + W[t] + K[1];
        } else if (t < 60) {
            temp = SHA1CircularShift(5, A) +
                   ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        } else {
            temp = SHA1CircularShift(5, A) +
                   (B ^ C ^ D) + E + W[t] + K[3];
        }

        E = D;
        D = C;
        C = SHA1CircularShift(30, B); // S^5(B) 循环左移30位
        B = A;
        A = temp;
    }

    /*
     *  更新中间哈希值
     */
    context->Intermediate_Hash[0] += A;
    context->Intermediate_Hash[1] += B;
    context->Intermediate_Hash[2] += C;
    context->Intermediate_Hash[3] += D;
    context->Intermediate_Hash[4] += E;

    context->Message_Block_Index = 0;
}

/*
 *  SHA1PadMessage
 *
 *  Description:
 *      According to the standard, the message must be padded to an even
 *      512 bit boundary.  The first padding bit must be a '1'.  The
 *      last 64 bits represent the length of the original message.  All
 *      bits in between should be 0.  This function will pad the message
 *      according to those rules by filling the Message_Block array
 *      accordingly.  It will also call the ProcessMessageBlock function
 *      provided appropriately.  When it returns, it can be assumed that
 *      the message digest has been computed.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to pad
 *      ProcessMessageBlock: [in]
 *          The appropriate SHA*ProcessMessageBlock function
 *
 *  Returns:
 *      Nothing.
 *
 *  按照标准要求填充消息：
 *  1. 在消息末尾添加位'1'
 *  2. 添加足够多的'0'位，使消息长度 ≡ 448 (mod 512)
 *  3. 在最后64位添加原始消息的长度
 */
void SHA1PadMessage(SHA1Context *context) {
    /*
     *  检查是否需要在当前块中添加'1'位
     *  如果当前块中剩余空间不足64位来存储长度，则需要额外的块
     */
    if (context->Message_Block_Index > 55) {
        /*
         *  填充当前块至末尾
         */
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while (context->Message_Block_Index < 64) {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }

        SHA1ProcessMessageBlock(context);

        /*
         *  开始新的块用于填充
         */
        while (context->Message_Block_Index < 56) {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    } else {
        /*
         *  在当前块中添加'1'位
         */
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while (context->Message_Block_Index < 56) {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }

    /*
     *  存储原始消息长度（大端序）
     *  长度以位为单位，存储在最后64位中
     */
    context->Message_Block[56] = context->Length_High >> 24;
    context->Message_Block[57] = context->Length_High >> 16;
    context->Message_Block[58] = context->Length_High >> 8;
    context->Message_Block[59] = context->Length_High;
    context->Message_Block[60] = context->Length_Low >> 24;
    context->Message_Block[61] = context->Length_Low >> 16;
    context->Message_Block[62] = context->Length_Low >> 8;
    context->Message_Block[63] = context->Length_Low;

    SHA1ProcessMessageBlock(context);
}
