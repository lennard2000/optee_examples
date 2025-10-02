#ifndef OPTEE_WRAPPER_H
#define OPTEE_WRAPPER_H

#include <crypto_types.h>

#include <tee_api_types.h>
#define mbedtls_printf(...) IMSG(__VA_ARGS__)
#define printf(...) IMSG(__VA_ARGS__)
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

#endif //OPTEE_WRAPPER_H
