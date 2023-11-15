void ECRYPT_init(void);
void ECRYPT_keysetup(ECRYPT_ctx *x, const u8 *k, u32 kbits, u32 ivbits);
void ECRYPT_ivsetup(ECRYPT_ctx *x, const u8 *iv);
void ECRYPT_encrypt_bytes(ECRYPT_ctx *x, const u8 *m, u8 *c, u32 bytes);
void ECRYPT_decrypt_bytes(ECRYPT_ctx *x, const u8 *c, u8 *m, u32 bytes);
