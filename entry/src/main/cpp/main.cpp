#include "napi/native_api.h"
#include <hilog/log.h>
#include <iostream>
#include "rsa_utils.h"
#include "aes_utils.h"
#include "base64_utils.h"

#define LOGD(...) OH_LOG_Print(LOG_APP, LOG_DEBUG, 0xFFFFF, "Native", __VA_ARGS__)

static int testRsaAes() {
    //
    //    printf("\n-------------------------------\n");
    //
    //    std::string content = "Hello, World!";
    //
    //    /* 加密过程 */
    //    // 1、RSA公钥
    std::string rsaPubKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCn6jDm6aa1Fw6sd5lhjz+0RdO7d+v7FaUOXJo+"
                            "T7cZfZ6FRLkb0QLbLo4hsG1YuYtCL3Uc2xr3tniGZDCpsaLoVeIqCZ6Yb8fma3lI88LkFSQsa+qJwPA/"
                            "2Ph+gmLDEuceeZI5EwRU1meKHQ5wpISxLvmtYkOO8H4okRB2gMDt5QIDAQAB";
    //    // 2、AES密钥
    //    std::vector<uint8_t> aesKeyBytes = aes_utils::generateAESKey(aes_utils::AES_KEY_SIZE_128);
    //    // 3、使用AES密钥加密原文
    //    std::string aesEncryptContent = aes_utils::aesEncrypt(content, std::string(aesKeyBytes.begin(),
    //    aesKeyBytes.end())); printf("aes encrypt content: %s\n", aesEncryptContent.c_str());
    //    // 4、使用RSA公钥加密AES密钥


    int nPublicKeyLen = rsaPubKey.size(); // strPublicKey为base64编码的公钥字符串
    for (int i = 64; i < nPublicKeyLen; i += 64) {
        if (rsaPubKey[i] != '\n') {
            rsaPubKey.insert(i, "\n");
        }
        i++;
    }
    rsaPubKey.insert(0, "-----BEGIN PUBLIC KEY-----\n");
    rsaPubKey.append("\n-----END PUBLIC KEY-----\n");
    LOGD("public key:\n%{public}s\n", rsaPubKey.c_str());


    /* 解密过程 */
    std::string encryptValue = "tPNs406q+1UUx1K9G2K27l90XRuUaLx1ZDI7vnvl7cBONQHvcA6bHJYZxNBRgERe1UhWnU8v/"
                               "2SssGF9tcG7iFkBPjbmsYfOle6/kODMtE86EZ9ADEXDOk7lR5b3aYBZlqJJbXFXe/"
                               "bkmOSBEId+Pd497HpwbOu4EnFk23zXUxTN0cj7vg2/bD+d2ED2s9BIOUU1qlORS3QH1SGDkRh3XQ==";
    std::string secretKey = "nG5+PXoHfwIgiE0oTyk4O4Ug3It+9/XP/"
                            "6MFhWIN2ba7hW6IgeHsXxZVyQAqWt14PajXUrIuDqxuafWqGuGGeV6ioD8wDmUHBueTDjMZGEcSdzXj5WQpVFkHhPN"
                            "0HwkBsNDM+W+kgjAn2PhdJPZN8VBSuM/iCyTlh+hSux3aoBA=";
    std::string aesKey = rsa_utils::rsaPubKeyDecrypt(base64_utils::base64Decode(secretKey), rsaPubKey);
    std::string aesKeyBase64 = base64_utils::base64Encode(aesKey);
    std::string respContent = aes_utils::aesDecrypt(base64_utils::base64Decode(encryptValue), aesKey);

    LOGD("aesKey: %{public}s\n", aesKey.c_str());
    LOGD("aesKeyBase64: %{public}s\n", aesKeyBase64.c_str());
    LOGD("respContent: %{public}s\n", respContent.c_str());

    return 0;
}

static napi_value Add(napi_env env, napi_callback_info info) {
    size_t requireArgc = 2;
    size_t argc = 2;
    napi_value args[2] = {nullptr};

    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    napi_valuetype valuetype0;
    napi_typeof(env, args[0], &valuetype0);

    napi_valuetype valuetype1;
    napi_typeof(env, args[1], &valuetype1);

    double value0;
    napi_get_value_double(env, args[0], &value0);

    double value1;
    napi_get_value_double(env, args[1], &value1);

    napi_value sum;
    napi_create_double(env, value0 + value1, &sum);
    // todo remove test method
    testRsaAes();
    return sum;
}

EXTERN_C_START
static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {{"add", nullptr, Add, nullptr, nullptr, nullptr, napi_default, nullptr}};
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}
EXTERN_C_END

static napi_module demoModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "entry",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterEntryModule(void) { napi_module_register(&demoModule); }
