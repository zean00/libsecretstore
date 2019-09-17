#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define ENCRYPTION_ERROR -32055

typedef struct {
  /**
   * Common encryption point. Pass this to Secret Store 'Document key storing session'
   */
  const char *common_point;
  /**
   * Encrypted point. Pass this to Secret Store 'Document key storing session'.
   */
  const char *encrypted_point;
  /**
   * Document key itself, encrypted with passed account public. Pass this to 'secretstore_encrypt'.
   */
  const char *encrypted_key;
} DocumentKey;

const char *decrypt(const char *key, const char *data);

const char *decrypt_key(const char *secret,
                        const char *decrypted_secret,
                        const char *common_point,
                        const char *const *decrypt_shadows,
                        uintptr_t shadow_len);

const char *decrypt_shadow(const char *secret,
                           const char *decrypted_secret,
                           const char *common_point,
                           const char *const *decrypt_shadows,
                           uintptr_t shadow_len,
                           const char *data);

const char *encrypt(const char *secret, const char *key, const char *data);

const DocumentKey *get_document_key(const char *secret, const char *public_);

const char *sign_hash(const char *secret, const char *hash);
