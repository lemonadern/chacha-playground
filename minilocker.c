#include <stdio.h>
#include <stdlib.h>

#include "chacha20/ecrypt-sync.h"

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

// コマンドライン引数で指定されたファイルを暗号化する
int main(int argc, char *argv[])
{
  char *inputFilename;
  char *outputFilename;
  char *key;
  char *iv;

  if (argc == 3)
  {
    inputFilename = argv[1];
    outputFilename = argv[2];

    // use constant key and iv
    key = "0123456789abcdef0123456789abcdef";
    iv = "01234567";
  }
  else if (argc == 5)
  {
    inputFilename = argv[1];
    outputFilename = argv[2];
    key = argv[3];
    iv = argv[4];
  }
  else
  {
    fprintf(stderr, "Usage: %s <input file> <output file> <key> <iv>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  encryptFile(inputFilename, outputFilename, key, iv);
  printf("File encrypted: %s -> %s\n", inputFilename, outputFilename);

  return 0;
}
