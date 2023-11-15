#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ecrypt-sync.h"

void encryptFile(const char *inputFilename, const char *outputFilename, const char *key, const char *iv)
{
  FILE *inputFile = fopen(inputFilename, "rb");
  FILE *outputFile = fopen(outputFilename, "wb");

  if (!inputFile || !outputFile)
  {
    perror("Error opening file");
    exit(EXIT_FAILURE);
  }

  ECRYPT_ctx ctx;
  ECRYPT_init();
  ECRYPT_keysetup(&ctx, (const u8 *)key, 256, 64);
  ECRYPT_ivsetup(&ctx, (const u8 *)iv);

  // ファイルからデータを読み込んで暗号化し、結果をファイルに書き込む
  size_t bufferSize = 4096;
  u8 buffer[bufferSize];
  size_t bytesRead;

  while ((bytesRead = fread(buffer, 1, bufferSize, inputFile)) > 0)
  {
    ECRYPT_encrypt_bytes(&ctx, buffer, buffer, bytesRead);
    fwrite(buffer, 1, bytesRead, outputFile);
  }

  fclose(inputFile);
  fclose(outputFile);
}

void decryptFile(const char *inputFilename, const char *outputFilename, const char *key, const char *iv)
{
  FILE *inputFile = fopen(inputFilename, "rb");
  FILE *outputFile = fopen(outputFilename, "wb");

  if (!inputFile || !outputFile)
  {
    perror("Error opening file");
    exit(EXIT_FAILURE);
  }

  ECRYPT_ctx ctx;
  ECRYPT_init();
  ECRYPT_keysetup(&ctx, (const u8 *)key, 256, 64);
  ECRYPT_ivsetup(&ctx, (const u8 *)iv);

  // ファイルから暗号文を読み込んで復号し、結果をファイルに書き込む
  size_t bufferSize = 4096;
  u8 buffer[bufferSize];
  size_t bytesRead;

  while ((bytesRead = fread(buffer, 1, bufferSize, inputFile)) > 0)
  {
    ECRYPT_decrypt_bytes(&ctx, buffer, buffer, bytesRead);
    fwrite(buffer, 1, bytesRead, outputFile);
  }

  fclose(inputFile);
  fclose(outputFile);
}

int main()
{
  const char *inputFilename = "input.txt";
  const char *encryptedFilename = "encrypted.txt";
  const char *decryptedFilename = "decrypted.txt";
  const char *key = "0123456789abcdef0123456789abcdef";
  const char *iv = "01234567";

  // ファイルを暗号化
  encryptFile(inputFilename, encryptedFilename, key, iv);
  printf("File encrypted: %s -> %s\n", inputFilename, encryptedFilename);

  // 暗号文を復号
  decryptFile(encryptedFilename, decryptedFilename, key, iv);
  printf("File decrypted: %s -> %s\n", encryptedFilename, decryptedFilename);

  return 0;
}
