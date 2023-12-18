#pragma once

#include <string>
#include <sstream>
#include <iterator>
#include <algorithm>
#include "openssl/buffer.h"
#include "openssl/evp.h"
#include "openssl/types.h"

namespace base64_utils {
    std::string base64Encode(const std::string &input) {
        BIO *bio, *b64;
        BUF_MEM *bufferPtr;

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);

        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Remove newlines

        BIO_write(bio, input.c_str(), static_cast<int>(input.length()));
        BIO_flush(bio);

        BIO_get_mem_ptr(bio, &bufferPtr);
        BIO_set_close(bio, BIO_NOCLOSE);
        BIO_free_all(bio);

        return std::string(bufferPtr->data, bufferPtr->length);
    }

    std::string base64Decode(const std::string &input) {
        BIO *bio, *b64;

        std::string decoded_data;
        bio = BIO_new_mem_buf(input.c_str(), static_cast<int>(input.length()));
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);

        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Remove newlines

        char buffer[4096];
        int len;
        while ((len = BIO_read(bio, buffer, 4096)) > 0) {
            decoded_data.append(buffer, static_cast<unsigned long>(len));
        }

        BIO_free_all(bio);

        return decoded_data;
    }

}