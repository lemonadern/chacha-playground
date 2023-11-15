#include <stdio.h>
#include <string.h>
#include "ecrypt-sync.h"

#include "chacha.h"

int main()
{
  // キーとIVの設定
  const char *key = "0123456789abcdef0123456789abcdef";
  const char *iv = "01234567";
  ECRYPT_ctx ctx;

  // 暗号化キーのセットアップ
  ECRYPT_init();
  ECRYPT_keysetup(&ctx, (const u8 *)key, 256, 64);

  // IVのセットアップ
  ECRYPT_ivsetup(&ctx, (const u8 *)iv);

  // 暗号化するデータ
  const char *plaintext = "Hello, ChaCha20!";
  printf("Plaintext:  %s\n", plaintext);

  // 暗号化
  size_t len = strlen(plaintext);
  u8 ciphertext[len];
  ECRYPT_encrypt_bytes(&ctx, (const u8 *)plaintext, ciphertext, len);

  // 暗号文の表示
  printf("Ciphertext: ");
  for (size_t i = 0; i < len; ++i)
  {
    printf("%02x", ciphertext[i]);
  }
  printf("\n");

  // 復号（復号結果は元の平文になるはず）
  u8 decrypted[len];
  ECRYPT_ivsetup(&ctx, (const u8 *)iv); // IVをリセット
  ECRYPT_decrypt_bytes(&ctx, ciphertext, decrypted, len);

  // 復号結果の表示
  printf("Decrypted:  %s\n", decrypted);

  return 0;
}
