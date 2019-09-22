#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

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

const char *ss_echo(const char *val);

const char *ss_shared_secret(const char *public, const char *secret);

const char *ss_decrypt(const char *key, const char *data);

const char *ss_decrypt_key(const char *secret,
                        const char *decrypted_secret,
                        const char *common_point,
                        const char *const *decrypt_shadows,
                        uintptr_t shadow_len);

const char *ss_decrypt_shadow(const char *secret,
                           const char *decrypted_secret,
                           const char *common_point,
                           const char *const *decrypt_shadows,
                           uintptr_t shadow_len,
                           const char *data);

const char *ss_encrypt(const char *secret, const char *key, const char *data);

const DocumentKey *ss_get_document_key(const char *secret, const char *public_);

const char *ss_sign_hash(const char *secret, const char *hash);
