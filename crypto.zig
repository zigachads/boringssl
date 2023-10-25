const std = @import("std");

pub fn build(
    b: *std.Build,
    target: std.zig.CrossTarget,
    optimize: std.builtin.OptimizeMode,
    boringssl_dep: *std.build.Dependency,
) !*std.build.LibExeObjStep {
    const lib = b.addStaticLibrary(.{
        .name = "crypto",
        .optimize = optimize,
        .target = target,
    });
    lib.linkLibC();
    if (optimize == .ReleaseSmall) {
        lib.defineCMacro("OPENSSL_SMALL", null);
    }

    lib.defineCMacro("ARCH", "generic");
    lib.defineCMacro("OPENSSL_NO_ASM", null);

    lib.defineCMacro("OPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED", null);
    lib.defineCMacro("SO_KEEPALIVE", "0");
    lib.defineCMacro("SO_ERROR", "0");
    lib.defineCMacro("FREEBSD_GETRANDOM", null);
    lib.defineCMacro("getrandom(a,b,c)", "getentropy(a,b)|b");
    lib.defineCMacro("GRND_NONBLOCK", "0");

    const cflags: []const []const u8 = &[_][]const u8{
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Wconversion",
        "-Wsign-conversion",
    };

    lib.addIncludePath(boringssl_dep.path("include"));

    lib.addCSourceFile(.{
        .file = .{ .path = "./err_data.c" },
        .flags = cflags,
    });

    for (sources) |source| {
        lib.addCSourceFile(.{
            .file = boringssl_dep.path(source),
            .flags = cflags,
        });
    }

    return lib;
}

const sources = &[_][]const u8{
    "crypto/asn1/a_bitstr.c",
    "crypto/asn1/a_bool.c",
    "crypto/asn1/a_d2i_fp.c",
    "crypto/asn1/a_dup.c",
    "crypto/asn1/a_gentm.c",
    "crypto/asn1/a_i2d_fp.c",
    "crypto/asn1/a_int.c",
    "crypto/asn1/a_mbstr.c",
    "crypto/asn1/a_object.c",
    "crypto/asn1/a_octet.c",
    "crypto/asn1/a_strex.c",
    "crypto/asn1/a_strnid.c",
    "crypto/asn1/a_time.c",
    "crypto/asn1/a_type.c",
    "crypto/asn1/a_utctm.c",
    "crypto/asn1/asn1_lib.c",
    "crypto/asn1/asn1_par.c",
    "crypto/asn1/asn_pack.c",
    "crypto/asn1/f_int.c",
    "crypto/asn1/f_string.c",
    "crypto/asn1/posix_time.c",
    "crypto/asn1/tasn_dec.c",
    "crypto/asn1/tasn_enc.c",
    "crypto/asn1/tasn_fre.c",
    "crypto/asn1/tasn_new.c",
    "crypto/asn1/tasn_typ.c",
    "crypto/asn1/tasn_utl.c",
    "crypto/base64/base64.c",
    "crypto/bio/bio.c",
    "crypto/bio/bio_mem.c",
    "crypto/bio/connect.c",
    "crypto/bio/errno.c",
    "crypto/bio/fd.c",
    "crypto/bio/file.c",
    "crypto/bio/hexdump.c",
    "crypto/bio/pair.c",
    "crypto/bio/printf.c",
    "crypto/bio/socket.c",
    "crypto/bio/socket_helper.c",
    "crypto/blake2/blake2.c",
    "crypto/bn_extra/bn_asn1.c",
    "crypto/bn_extra/convert.c",
    "crypto/buf/buf.c",
    "crypto/bytestring/asn1_compat.c",
    "crypto/bytestring/ber.c",
    "crypto/bytestring/cbb.c",
    "crypto/bytestring/cbs.c",
    "crypto/bytestring/unicode.c",
    "crypto/chacha/chacha.c",
    "crypto/cipher_extra/cipher_extra.c",
    "crypto/cipher_extra/derive_key.c",
    "crypto/cipher_extra/e_aesctrhmac.c",
    "crypto/cipher_extra/e_aesgcmsiv.c",
    "crypto/cipher_extra/e_chacha20poly1305.c",
    "crypto/cipher_extra/e_des.c",
    "crypto/cipher_extra/e_null.c",
    "crypto/cipher_extra/e_rc2.c",
    "crypto/cipher_extra/e_rc4.c",
    "crypto/cipher_extra/e_tls.c",
    "crypto/cipher_extra/tls_cbc.c",
    "crypto/conf/conf.c",
    "crypto/cpu_aarch64_apple.c",
    "crypto/cpu_aarch64_fuchsia.c",
    "crypto/cpu_aarch64_linux.c",
    "crypto/cpu_aarch64_openbsd.c",
    "crypto/cpu_aarch64_sysreg.c",
    "crypto/cpu_aarch64_win.c",
    "crypto/cpu_arm_freebsd.c",
    "crypto/cpu_arm_linux.c",
    "crypto/cpu_intel.c",
    "crypto/crypto.c",
    "crypto/curve25519/curve25519.c",
    "crypto/curve25519/curve25519_64_adx.c",
    "crypto/curve25519/spake25519.c",
    "crypto/des/des.c",
    "crypto/dh_extra/dh_asn1.c",
    "crypto/dh_extra/params.c",
    "crypto/digest_extra/digest_extra.c",
    "crypto/dsa/dsa.c",
    "crypto/dsa/dsa_asn1.c",
    "crypto/ec_extra/ec_asn1.c",
    "crypto/ec_extra/ec_derive.c",
    "crypto/ec_extra/hash_to_curve.c",
    "crypto/ecdh_extra/ecdh_extra.c",
    "crypto/ecdsa_extra/ecdsa_asn1.c",
    "crypto/engine/engine.c",
    "crypto/err/err.c",
    "crypto/evp/evp.c",
    "crypto/evp/evp_asn1.c",
    "crypto/evp/evp_ctx.c",
    "crypto/evp/p_dsa_asn1.c",
    "crypto/evp/p_ec.c",
    "crypto/evp/p_ec_asn1.c",
    "crypto/evp/p_ed25519.c",
    "crypto/evp/p_ed25519_asn1.c",
    "crypto/evp/p_hkdf.c",
    "crypto/evp/p_rsa.c",
    "crypto/evp/p_rsa_asn1.c",
    "crypto/evp/p_x25519.c",
    "crypto/evp/p_x25519_asn1.c",
    "crypto/evp/pbkdf.c",
    "crypto/evp/print.c",
    "crypto/evp/scrypt.c",
    "crypto/evp/sign.c",
    "crypto/ex_data.c",
    "crypto/fipsmodule/aes/aes.c",
    "crypto/fipsmodule/aes/aes_nohw.c",
    "crypto/fipsmodule/aes/key_wrap.c",
    "crypto/fipsmodule/aes/mode_wrappers.c",
    "crypto/fipsmodule/bcm.c",
    "crypto/fipsmodule/bn/add.c",
    "crypto/fipsmodule/bn/asm/x86_64-gcc.c",
    "crypto/fipsmodule/bn/bn.c",
    "crypto/fipsmodule/bn/bytes.c",
    "crypto/fipsmodule/bn/cmp.c",
    "crypto/fipsmodule/bn/ctx.c",
    "crypto/fipsmodule/bn/div.c",
    "crypto/fipsmodule/bn/div_extra.c",
    "crypto/fipsmodule/bn/exponentiation.c",
    "crypto/fipsmodule/bn/gcd.c",
    "crypto/fipsmodule/bn/gcd_extra.c",
    "crypto/fipsmodule/bn/generic.c",
    "crypto/fipsmodule/bn/jacobi.c",
    "crypto/fipsmodule/bn/montgomery.c",
    "crypto/fipsmodule/bn/montgomery_inv.c",
    "crypto/fipsmodule/bn/mul.c",
    "crypto/fipsmodule/bn/prime.c",
    "crypto/fipsmodule/bn/random.c",
    "crypto/fipsmodule/bn/rsaz_exp.c",
    "crypto/fipsmodule/bn/shift.c",
    "crypto/fipsmodule/bn/sqrt.c",
    "crypto/fipsmodule/cipher/aead.c",
    "crypto/fipsmodule/cipher/cipher.c",
    "crypto/fipsmodule/cipher/e_aes.c",
    "crypto/fipsmodule/cipher/e_aesccm.c",
    "crypto/fipsmodule/cmac/cmac.c",
    "crypto/fipsmodule/dh/check.c",
    "crypto/fipsmodule/dh/dh.c",
    "crypto/fipsmodule/digest/digest.c",
    "crypto/fipsmodule/digest/digests.c",
    "crypto/fipsmodule/digestsign/digestsign.c",
    "crypto/fipsmodule/ec/ec.c",
    "crypto/fipsmodule/ec/ec_key.c",
    "crypto/fipsmodule/ec/ec_montgomery.c",
    "crypto/fipsmodule/ec/felem.c",
    "crypto/fipsmodule/ec/oct.c",
    "crypto/fipsmodule/ec/p224-64.c",
    "crypto/fipsmodule/ec/p256-nistz.c",
    "crypto/fipsmodule/ec/p256.c",
    "crypto/fipsmodule/ec/scalar.c",
    "crypto/fipsmodule/ec/simple.c",
    "crypto/fipsmodule/ec/simple_mul.c",
    "crypto/fipsmodule/ec/util.c",
    "crypto/fipsmodule/ec/wnaf.c",
    "crypto/fipsmodule/ecdh/ecdh.c",
    "crypto/fipsmodule/ecdsa/ecdsa.c",
    "crypto/fipsmodule/fips_shared_support.c",
    "crypto/fipsmodule/hkdf/hkdf.c",
    "crypto/fipsmodule/hmac/hmac.c",
    "crypto/fipsmodule/md4/md4.c",
    "crypto/fipsmodule/md5/md5.c",
    "crypto/fipsmodule/modes/cbc.c",
    "crypto/fipsmodule/modes/cfb.c",
    "crypto/fipsmodule/modes/ctr.c",
    "crypto/fipsmodule/modes/gcm.c",
    "crypto/fipsmodule/modes/gcm_nohw.c",
    "crypto/fipsmodule/modes/ofb.c",
    "crypto/fipsmodule/modes/polyval.c",
    "crypto/fipsmodule/rand/ctrdrbg.c",
    "crypto/fipsmodule/rand/fork_detect.c",
    "crypto/fipsmodule/rand/rand.c",
    "crypto/fipsmodule/rand/urandom.c",
    "crypto/fipsmodule/rsa/blinding.c",
    "crypto/fipsmodule/rsa/padding.c",
    "crypto/fipsmodule/rsa/rsa.c",
    "crypto/fipsmodule/rsa/rsa_impl.c",
    "crypto/fipsmodule/self_check/fips.c",
    "crypto/fipsmodule/self_check/self_check.c",
    "crypto/fipsmodule/service_indicator/service_indicator.c",
    "crypto/fipsmodule/sha/sha1.c",
    "crypto/fipsmodule/sha/sha256.c",
    "crypto/fipsmodule/sha/sha512.c",
    "crypto/fipsmodule/tls/kdf.c",
    "crypto/hpke/hpke.c",
    "crypto/hrss/hrss.c",
    "crypto/kyber/keccak.c",
    "crypto/kyber/kyber.c",
    "crypto/lhash/lhash.c",
    "crypto/mem.c",
    "crypto/obj/obj.c",
    "crypto/obj/obj_xref.c",
    "crypto/pem/pem_all.c",
    "crypto/pem/pem_info.c",
    "crypto/pem/pem_lib.c",
    "crypto/pem/pem_oth.c",
    "crypto/pem/pem_pk8.c",
    "crypto/pem/pem_pkey.c",
    "crypto/pem/pem_x509.c",
    "crypto/pem/pem_xaux.c",
    "crypto/pkcs7/pkcs7.c",
    "crypto/pkcs7/pkcs7_x509.c",
    "crypto/pkcs8/p5_pbev2.c",
    "crypto/pkcs8/pkcs8.c",
    "crypto/pkcs8/pkcs8_x509.c",
    "crypto/poly1305/poly1305.c",
    "crypto/poly1305/poly1305_arm.c",
    "crypto/poly1305/poly1305_vec.c",
    "crypto/pool/pool.c",
    "crypto/rand_extra/deterministic.c",
    "crypto/rand_extra/forkunsafe.c",
    "crypto/rand_extra/getentropy.c",
    "crypto/rand_extra/ios.c",
    "crypto/rand_extra/passive.c",
    "crypto/rand_extra/rand_extra.c",
    "crypto/rand_extra/trusty.c",
    "crypto/rand_extra/windows.c",
    "crypto/rc4/rc4.c",
    "crypto/refcount.c",
    "crypto/rsa_extra/rsa_asn1.c",
    "crypto/rsa_extra/rsa_crypt.c",
    "crypto/rsa_extra/rsa_print.c",
    "crypto/siphash/siphash.c",
    "crypto/stack/stack.c",
    "crypto/thread.c",
    "crypto/thread_none.c",
    "crypto/thread_pthread.c",
    "crypto/thread_win.c",
    "crypto/trust_token/pmbtoken.c",
    "crypto/trust_token/trust_token.c",
    "crypto/trust_token/voprf.c",
    "crypto/x509/a_digest.c",
    "crypto/x509/a_sign.c",
    "crypto/x509/a_verify.c",
    "crypto/x509/algorithm.c",
    "crypto/x509/asn1_gen.c",
    "crypto/x509/by_dir.c",
    "crypto/x509/by_file.c",
    "crypto/x509/i2d_pr.c",
    "crypto/x509/name_print.c",
    "crypto/x509/policy.c",
    "crypto/x509/rsa_pss.c",
    "crypto/x509/t_crl.c",
    "crypto/x509/t_req.c",
    "crypto/x509/t_x509.c",
    "crypto/x509/t_x509a.c",
    "crypto/x509/x509.c",
    "crypto/x509/x509_att.c",
    "crypto/x509/x509_cmp.c",
    "crypto/x509/x509_d2.c",
    "crypto/x509/x509_def.c",
    "crypto/x509/x509_ext.c",
    "crypto/x509/x509_lu.c",
    "crypto/x509/x509_obj.c",
    "crypto/x509/x509_req.c",
    "crypto/x509/x509_set.c",
    "crypto/x509/x509_trs.c",
    "crypto/x509/x509_txt.c",
    "crypto/x509/x509_v3.c",
    "crypto/x509/x509_vfy.c",
    "crypto/x509/x509_vpm.c",
    "crypto/x509/x509cset.c",
    "crypto/x509/x509name.c",
    "crypto/x509/x509rset.c",
    "crypto/x509/x509spki.c",
    "crypto/x509/x_algor.c",
    "crypto/x509/x_all.c",
    "crypto/x509/x_attrib.c",
    "crypto/x509/x_crl.c",
    "crypto/x509/x_exten.c",
    "crypto/x509/x_info.c",
    "crypto/x509/x_name.c",
    "crypto/x509/x_pkey.c",
    "crypto/x509/x_pubkey.c",
    "crypto/x509/x_req.c",
    "crypto/x509/x_sig.c",
    "crypto/x509/x_spki.c",
    "crypto/x509/x_val.c",
    "crypto/x509/x_x509.c",
    "crypto/x509/x_x509a.c",
    "crypto/x509v3/v3_akey.c",
    "crypto/x509v3/v3_akeya.c",
    "crypto/x509v3/v3_alt.c",
    "crypto/x509v3/v3_bcons.c",
    "crypto/x509v3/v3_bitst.c",
    "crypto/x509v3/v3_conf.c",
    "crypto/x509v3/v3_cpols.c",
    "crypto/x509v3/v3_crld.c",
    "crypto/x509v3/v3_enum.c",
    "crypto/x509v3/v3_extku.c",
    "crypto/x509v3/v3_genn.c",
    "crypto/x509v3/v3_ia5.c",
    "crypto/x509v3/v3_info.c",
    "crypto/x509v3/v3_int.c",
    "crypto/x509v3/v3_lib.c",
    "crypto/x509v3/v3_ncons.c",
    "crypto/x509v3/v3_ocsp.c",
    "crypto/x509v3/v3_pcons.c",
    "crypto/x509v3/v3_pmaps.c",
    "crypto/x509v3/v3_prn.c",
    "crypto/x509v3/v3_purp.c",
    "crypto/x509v3/v3_skey.c",
    "crypto/x509v3/v3_utl.c",
};