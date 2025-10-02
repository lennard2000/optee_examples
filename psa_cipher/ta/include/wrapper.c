#include <wrapper.h>
#include <crypto_values.h>
#include <tee_internal_api.h>

#define RETURN_IF_FAIL(res, msg) \
if ((res) != TEE_SUCCESS) { \
EMSG(msg ": 0x%x", res); \
return PSA_ERROR_GENERIC_ERROR; \
}
