#include <stdio.h>
#include <string.h>
#include "chacha20/ecrypt-sync.h"

#include "chacha20/chacha.h"

int main()
{
  const char *key = "0123456789abcdef0123456789abcdef";
  const char *iv = "01234567";
  ECRYPT_ctx ctx;

  ECRYPT_init();
  ECRYPT_keysetup(&ctx, (const u8 *)key, 256, 64);

  ECRYPT_ivsetup(&ctx, (const u8 *)iv);

  const char *plaintext = "Hello, ChaCha20!";

  printf("Plaintext:  %s\n", plaintext);

  size_t len = strlen(plaintext);
  u8 ciphertext[len];
  ECRYPT_encrypt_bytes(&ctx, (const u8 *)plaintext, ciphertext, len);

  printf("Ciphertext: ");
  for (size_t i = 0; i < len; ++i)
  {
    printf("%02x", ciphertext[i]);
  }
  printf("\n");

  // 復号
  u8 decrypted[17];
  ECRYPT_ivsetup(&ctx, (const u8 *)iv);
  ECRYPT_decrypt_bytes(&ctx, ciphertext, decrypted, len);

  // 復号結果の表示
  printf("Decrypted:  %s\n", decrypted);

  return 0;
}
