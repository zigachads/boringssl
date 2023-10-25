const std = @import("std");

pub fn build(
    b: *std.Build,
    target: std.zig.CrossTarget,
    optimize: std.builtin.OptimizeMode,
    boringssl_dep: *std.build.Dependency,
) !*std.build.LibExeObjStep {
    const lib = b.addStaticLibrary(.{
        .name = "ssl",
        .optimize = optimize,
        .target = target,
    });
    lib.linkLibC();
    lib.linkLibCpp();
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
    lib.defineCMacro("WIN32_LEAN_AND_MEAN", null);

    const cflags: []const []const u8 = &[_][]const u8{
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Wconversion",
        "-Wsign-conversion",
    };

    lib.addIncludePath(boringssl_dep.path("include"));

    for (sources) |source| {
        lib.addCSourceFile(.{
            .file = boringssl_dep.path(source),
            .flags = cflags,
        });
    }

    b.installDirectory(.{
        .source_dir = boringssl_dep.path("include"),
        .install_dir = .header,
        .install_subdir = "",
    });

    return lib;
}

const sources = &[_][]const u8{
    "ssl/bio_ssl.cc",
    "ssl/d1_both.cc",
    "ssl/d1_lib.cc",
    "ssl/d1_pkt.cc",
    "ssl/d1_srtp.cc",
    "ssl/dtls_method.cc",
    "ssl/dtls_record.cc",
    "ssl/encrypted_client_hello.cc",
    "ssl/extensions.cc",
    "ssl/handoff.cc",
    "ssl/handshake.cc",
    "ssl/handshake_client.cc",
    "ssl/handshake_server.cc",
    "ssl/s3_both.cc",
    "ssl/s3_lib.cc",
    "ssl/s3_pkt.cc",
    "ssl/ssl_aead_ctx.cc",
    "ssl/ssl_asn1.cc",
    "ssl/ssl_buffer.cc",
    "ssl/ssl_cert.cc",
    "ssl/ssl_cipher.cc",
    "ssl/ssl_file.cc",
    "ssl/ssl_key_share.cc",
    "ssl/ssl_lib.cc",
    "ssl/ssl_privkey.cc",
    "ssl/ssl_session.cc",
    "ssl/ssl_stat.cc",
    "ssl/ssl_transcript.cc",
    "ssl/ssl_versions.cc",
    "ssl/ssl_x509.cc",
    "ssl/t1_enc.cc",
    "ssl/tls13_both.cc",
    "ssl/tls13_client.cc",
    "ssl/tls13_enc.cc",
    "ssl/tls13_server.cc",
    "ssl/tls_method.cc",
    "ssl/tls_record.cc",
};

const headers = &[_][]const u8{
    "include/openssl/aead.h",
    "include/openssl/aes.h",
    "include/openssl/arm_arch.h",
    "include/openssl/asm_base.h",
    "include/openssl/asn1.h",
    "include/openssl/asn1_mac.h",
    "include/openssl/asn1t.h",
    "include/openssl/base.h",
    "include/openssl/base64.h",
    "include/openssl/bio.h",
    "include/openssl/blake2.h",
    "include/openssl/blowfish.h",
    "include/openssl/bn.h",
    "include/openssl/buf.h",
    "include/openssl/buffer.h",
    "include/openssl/bytestring.h",
    "include/openssl/cast.h",
    "include/openssl/chacha.h",
    "include/openssl/cipher.h",
    "include/openssl/cmac.h",
    "include/openssl/conf.h",
    "include/openssl/cpu.h",
    "include/openssl/crypto.h",
    "include/openssl/ctrdrbg.h",
    "include/openssl/curve25519.h",
    "include/openssl/des.h",
    "include/openssl/dh.h",
    "include/openssl/digest.h",
    "include/openssl/dsa.h",
    "include/openssl/dtls1.h",
    "include/openssl/e_os2.h",
    "include/openssl/ec.h",
    "include/openssl/ec_key.h",
    "include/openssl/ecdh.h",
    "include/openssl/ecdsa.h",
    "include/openssl/engine.h",
    "include/openssl/err.h",
    "include/openssl/evp.h",
    "include/openssl/evp_errors.h",
    "include/openssl/ex_data.h",
    "include/openssl/hkdf.h",
    "include/openssl/hmac.h",
    "include/openssl/hpke.h",
    "include/openssl/hrss.h",
    "include/openssl/is_boringssl.h",
    "include/openssl/kdf.h",
    "include/openssl/kyber.h",
    "include/openssl/lhash.h",
    "include/openssl/md4.h",
    "include/openssl/md5.h",
    "include/openssl/mem.h",
    "include/openssl/nid.h",
    "include/openssl/obj.h",
    "include/openssl/obj_mac.h",
    "include/openssl/objects.h",
    "include/openssl/opensslconf.h",
    "include/openssl/opensslv.h",
    "include/openssl/ossl_typ.h",
    "include/openssl/pem.h",
    "include/openssl/pkcs12.h",
    "include/openssl/pkcs7.h",
    "include/openssl/pkcs8.h",
    "include/openssl/poly1305.h",
    "include/openssl/pool.h",
    "include/openssl/rand.h",
    "include/openssl/rc4.h",
    "include/openssl/ripemd.h",
    "include/openssl/rsa.h",
    "include/openssl/safestack.h",
    "include/openssl/service_indicator.h",
    "include/openssl/sha.h",
    "include/openssl/siphash.h",
    "include/openssl/span.h",
    "include/openssl/srtp.h",
    "include/openssl/ssl.h",
    "include/openssl/ssl3.h",
    "include/openssl/stack.h",
    "include/openssl/target.h",
    "include/openssl/thread.h",
    "include/openssl/time.h",
    "include/openssl/tls1.h",
    "include/openssl/trust_token.h",
    "include/openssl/type_check.h",
    "include/openssl/x509.h",
    "include/openssl/x509_vfy.h",
    "include/openssl/x509v3.h",
};
