#include <corecrypto/ccrng_system.h>
#include <corecrypto/ccder.h>
#include <corecrypto/ccec.h>
#include <corecrypto/ccec25519.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
void cc_ecdsa_test()
{
    NSData* ns_sk = dataFromHexString(@"30770201 0104203f 1da566e4 0e5fbb93 89a319a0 585d8b03 61a6fcec 02f3424a ba1d591c 0aa1b6a0 0a06082a 8648ce3d 030107a1 44034200 04ef16bc e2b6b44d ef8de3ea 7cec1c77 9831f7bd 57507638 4a24edd7 70ac10ae 9f392ca6 27d3eb1d 57229bf6 14f9bcf9 a5f7fbc5 841bd15d 56bcf66e df42a8c4 8e");
    NSData* ns_sig = dataFromHexString(@"30460221 00f708ab f2de9cb2 5e46f360 69ea1f7c 13b71e1b 7710097d a0ccb5e8 f144fde3 78022100 84cdf763 d957b6f8 23576d76 9c8e192b 7d3a99a6 9a2685cf 0aab8728 a0603e6e");
    ccec_const_cp_t cp = ccec_cp_256();
    struct ccrng_system_state rng;
    int status = ccrng_system_init(&rng);
    ccec_full_ctx_decl(ccec_ccn_size(cp), key);
    ccec_der_import_priv(cp, [ns_sk length], [ns_sk bytes], key);
//    ccec_generate_key_legacy(cp, &rng, key);
    char* info = "0123456789abcdef";
    unsigned char digest[CCSHA256_OUTPUT_SIZE] = {0};
    ccdigest(ccsha256_di(), strlen(info), info, digest);
    size_t vk_size = ccec_export_pub_size(key);
    char* vk = malloc(vk_size);
    ccec_export_pub(key, vk);
    NSLog(@"pubkey %@", [NSData dataWithBytes:vk length:ccec_export_pub_size(key)]);
    ccoid_t oid;
    char*signature = malloc(0x100);
    size_t  siglen = 0x100;
    ccec_sign(key, CCSHA256_OUTPUT_SIZE, digest, &siglen, signature, &rng);
    NSLog(@"signature %@", [NSData dataWithBytes:signature length:siglen]);
    oid = (ccoid_t)CC_EC_OID_SECP256R1;
    size_t sk_size = ccec_der_export_priv_size(key, oid, 1);
    char* sk = malloc(sk_size);
    status = ccec_der_export_priv(key, oid, 1, sk_size, sk);
    NSLog(@"signingkey %@", [NSData dataWithBytes:sk length:sk_size]);
    bool valid = true;
    ccec_verify(key, CCSHA256_OUTPUT_SIZE, digest, siglen , signature, &valid);
    NSLog(@"now data valid signature %d", valid);
    ccec_verify(key, CCSHA256_OUTPUT_SIZE, digest, [ns_sig length] , [ns_sig bytes], &valid);
    NSLog(@"pre saved data valid signature %d", valid);
    ccec_pub_ctx_decl(vk_size, vk_ctx);
    ccec_import_pub(cp, vk_size, vk, vk_ctx);
    ccec_verify(vk_ctx, CCSHA256_OUTPUT_SIZE, digest, [ns_sig length] , [ns_sig bytes], &valid);
    NSLog(@"only pubkey verify valid signature %d", valid);
    NSLog(@"the signature should be true. if verify success.");

}
int main()
{
    cc_ecdsa_test();
}
