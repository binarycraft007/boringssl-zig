const std = @import("std");

const pki_sources = &.{
    "pki/cert_error_id.cc",
    "pki/cert_error_params.cc",
    "pki/cert_errors.cc",
    "pki/cert_issuer_source_static.cc",
    "pki/certificate_policies.cc",
    "pki/common_cert_errors.cc",
    "pki/crl.cc",
    "pki/encode_values.cc",
    "pki/extended_key_usage.cc",
    "pki/fillins/fillins_base64.cc",
    "pki/fillins/fillins_string_util.cc",
    "pki/fillins/openssl_util.cc",
    "pki/general_names.cc",
    "pki/input.cc",
    "pki/ip_util.cc",
    "pki/name_constraints.cc",
    "pki/ocsp.cc",
    "pki/ocsp_verify_result.cc",
    "pki/parse_certificate.cc",
    "pki/parse_name.cc",
    "pki/parse_values.cc",
    "pki/parsed_certificate.cc",
    "pki/parser.cc",
    "pki/path_builder.cc",
    "pki/pem.cc",
    "pki/revocation_util.cc",
    "pki/signature_algorithm.cc",
    "pki/simple_path_builder_delegate.cc",
    "pki/string_util.cc",
    "pki/tag.cc",
    "pki/trust_store.cc",
    "pki/trust_store_collection.cc",
    "pki/trust_store_in_memory.cc",
    "pki/verify_certificate_chain.cc",
    "pki/verify_name_match.cc",
    "pki/verify_signed_data.cc",
};

const bssl_sources = &.{
    "tool/args.cc",
    "tool/ciphers.cc",
    "tool/client.cc",
    "tool/const.cc",
    "tool/digest.cc",
    "tool/fd.cc",
    "tool/file.cc",
    "tool/generate_ech.cc",
    "tool/generate_ed25519.cc",
    "tool/genrsa.cc",
    "tool/pkcs12.cc",
    "tool/rand.cc",
    "tool/server.cc",
    "tool/sign.cc",
    "tool/speed.cc",
    "tool/tool.cc",
    "tool/transport_common.cc",
};

const ssl_sources = &.{
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

const crypto_sources = &.{
    "crypto/curve25519/asm/x25519-asm-arm.S",
    "crypto/hrss/asm/poly_rq_mul.S",
    "crypto/poly1305/poly1305_arm_asm.S",
    "third_party/fiat/asm/fiat_curve25519_adx_mul.S",
    "third_party/fiat/asm/fiat_curve25519_adx_square.S",
    "third_party/fiat/asm/fiat_p256_adx_mul.S",
    "third_party/fiat/asm/fiat_p256_adx_sqr.S",

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
    "crypto/hpke/hpke.c",
    "crypto/hrss/hrss.c",
    "crypto/keccak/keccak.c",
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

const decrepit_sources = &.{
    "decrepit/bio/base64_bio.c",
    "decrepit/blowfish/blowfish.c",
    "decrepit/cast/cast.c",
    "decrepit/cast/cast_tables.c",
    "decrepit/cfb/cfb.c",
    "decrepit/des/cfb64ede.c",
    "decrepit/dh/dh_decrepit.c",
    "decrepit/dsa/dsa_decrepit.c",
    "decrepit/evp/dss1.c",
    "decrepit/evp/evp_do_all.c",
    "decrepit/obj/obj_decrepit.c",
    "decrepit/rc4/rc4_decrepit.c",
    "decrepit/ripemd/ripemd.c",
    "decrepit/rsa/rsa_decrepit.c",
    "decrepit/ssl/ssl_decrepit.c",
    "decrepit/x509/x509_decrepit.c",
    "decrepit/xts/xts.c",
};

const fipsmodule_sources = &.{
    "crypto/fipsmodule/bcm.c",
    "crypto/fipsmodule/fips_shared_support.c",
};

const generated_fipsmodule_sources = &.{
    "generated/apple-x86_64/crypto/fipsmodule/aesni-gcm-x86_64-apple.S",
    "generated/apple-x86_64/crypto/fipsmodule/aesni-x86_64-apple.S",
    "generated/apple-x86_64/crypto/fipsmodule/ghash-ssse3-x86_64-apple.S",
    "generated/apple-x86_64/crypto/fipsmodule/ghash-x86_64-apple.S",
    "generated/apple-x86_64/crypto/fipsmodule/md5-x86_64-apple.S",
    "generated/apple-x86_64/crypto/fipsmodule/p256-x86_64-asm-apple.S",
    "generated/apple-x86_64/crypto/fipsmodule/p256_beeu-x86_64-asm-apple.S",
    "generated/apple-x86_64/crypto/fipsmodule/rdrand-x86_64-apple.S",
    "generated/apple-x86_64/crypto/fipsmodule/rsaz-avx2-apple.S",
    "generated/apple-x86_64/crypto/fipsmodule/sha1-x86_64-apple.S",
    "generated/apple-x86_64/crypto/fipsmodule/sha256-x86_64-apple.S",
    "generated/apple-x86_64/crypto/fipsmodule/sha512-x86_64-apple.S",
    "generated/apple-x86_64/crypto/fipsmodule/vpaes-x86_64-apple.S",
    "generated/apple-x86_64/crypto/fipsmodule/x86_64-mont-apple.S",
    "generated/apple-x86_64/crypto/fipsmodule/x86_64-mont5-apple.S",
    "generated/apple-aarch64/crypto/fipsmodule/aesv8-armv8-apple.S",
    "generated/apple-aarch64/crypto/fipsmodule/aesv8-gcm-armv8-apple.S",
    "generated/apple-aarch64/crypto/fipsmodule/armv8-mont-apple.S",
    "generated/apple-aarch64/crypto/fipsmodule/bn-armv8-apple.S",
    "generated/apple-aarch64/crypto/fipsmodule/ghash-neon-armv8-apple.S",
    "generated/apple-aarch64/crypto/fipsmodule/ghashv8-armv8-apple.S",
    "generated/apple-aarch64/crypto/fipsmodule/p256-armv8-asm-apple.S",
    "generated/apple-aarch64/crypto/fipsmodule/p256_beeu-armv8-asm-apple.S",
    "generated/apple-aarch64/crypto/fipsmodule/sha1-armv8-apple.S",
    "generated/apple-aarch64/crypto/fipsmodule/sha256-armv8-apple.S",
    "generated/apple-aarch64/crypto/fipsmodule/sha512-armv8-apple.S",
    "generated/apple-aarch64/crypto/fipsmodule/vpaes-armv8-apple.S",
    "generated/linux-aarch64/crypto/fipsmodule/aesv8-armv8-linux.S",
    "generated/linux-aarch64/crypto/fipsmodule/aesv8-gcm-armv8-linux.S",
    "generated/linux-aarch64/crypto/fipsmodule/armv8-mont-linux.S",
    "generated/linux-aarch64/crypto/fipsmodule/bn-armv8-linux.S",
    "generated/linux-aarch64/crypto/fipsmodule/ghash-neon-armv8-linux.S",
    "generated/linux-aarch64/crypto/fipsmodule/ghashv8-armv8-linux.S",
    "generated/linux-aarch64/crypto/fipsmodule/p256-armv8-asm-linux.S",
    "generated/linux-aarch64/crypto/fipsmodule/p256_beeu-armv8-asm-linux.S",
    "generated/linux-aarch64/crypto/fipsmodule/sha1-armv8-linux.S",
    "generated/linux-aarch64/crypto/fipsmodule/sha256-armv8-linux.S",
    "generated/linux-aarch64/crypto/fipsmodule/sha512-armv8-linux.S",
    "generated/linux-aarch64/crypto/fipsmodule/vpaes-armv8-linux.S",
    "generated/linux-x86_64/crypto/chacha/chacha-x86_64-linux.S",
    "generated/linux-x86_64/crypto/cipher_extra/aes128gcmsiv-x86_64-linux.S",
    "generated/linux-x86_64/crypto/cipher_extra/chacha20_poly1305_x86_64-linux.S",
    "generated/linux-x86_64/crypto/fipsmodule/aesni-gcm-x86_64-linux.S",
    "generated/linux-x86_64/crypto/fipsmodule/aesni-x86_64-linux.S",
    "generated/linux-x86_64/crypto/fipsmodule/ghash-ssse3-x86_64-linux.S",
    "generated/linux-x86_64/crypto/fipsmodule/ghash-x86_64-linux.S",
    "generated/linux-x86_64/crypto/fipsmodule/md5-x86_64-linux.S",
    "generated/linux-x86_64/crypto/fipsmodule/p256-x86_64-asm-linux.S",
    "generated/linux-x86_64/crypto/fipsmodule/p256_beeu-x86_64-asm-linux.S",
    "generated/linux-x86_64/crypto/fipsmodule/rdrand-x86_64-linux.S",
    "generated/linux-x86_64/crypto/fipsmodule/rsaz-avx2-linux.S",
    "generated/linux-x86_64/crypto/fipsmodule/sha1-x86_64-linux.S",
    "generated/linux-x86_64/crypto/fipsmodule/sha256-x86_64-linux.S",
    "generated/linux-x86_64/crypto/fipsmodule/sha512-x86_64-linux.S",
    "generated/linux-x86_64/crypto/fipsmodule/vpaes-x86_64-linux.S",
    "generated/linux-x86_64/crypto/fipsmodule/x86_64-mont-linux.S",
    "generated/linux-x86_64/crypto/fipsmodule/x86_64-mont5-linux.S",
    "generated/win-aarch64/crypto/fipsmodule/aesv8-armv8-win.S",
    "generated/win-aarch64/crypto/fipsmodule/aesv8-gcm-armv8-win.S",
    "generated/win-aarch64/crypto/fipsmodule/armv8-mont-win.S",
    "generated/win-aarch64/crypto/fipsmodule/bn-armv8-win.S",
    "generated/win-aarch64/crypto/fipsmodule/ghash-neon-armv8-win.S",
    "generated/win-aarch64/crypto/fipsmodule/ghashv8-armv8-win.S",
    "generated/win-aarch64/crypto/fipsmodule/p256-armv8-asm-win.S",
    "generated/win-aarch64/crypto/fipsmodule/p256_beeu-armv8-asm-win.S",
    "generated/win-aarch64/crypto/fipsmodule/sha1-armv8-win.S",
    "generated/win-aarch64/crypto/fipsmodule/sha256-armv8-win.S",
    "generated/win-aarch64/crypto/fipsmodule/sha512-armv8-win.S",
    "generated/win-aarch64/crypto/fipsmodule/vpaes-armv8-win.S",
};

const generated_crypto_sources = &.{
    "generated/err_data.c",
    "generated/apple-aarch64/crypto/chacha/chacha-armv8-apple.S",
    "generated/apple-aarch64/crypto/cipher_extra/chacha20_poly1305_armv8-apple.S",
    "generated/apple-x86_64/crypto/chacha/chacha-x86_64-apple.S",
    "generated/apple-x86_64/crypto/cipher_extra/aes128gcmsiv-x86_64-apple.S",
    "generated/apple-x86_64/crypto/cipher_extra/chacha20_poly1305_x86_64-apple.S",
    "generated/linux-aarch64/crypto/chacha/chacha-armv8-linux.S",
    "generated/linux-aarch64/crypto/cipher_extra/chacha20_poly1305_armv8-linux.S",
    "generated/win-aarch64/crypto/chacha/chacha-armv8-win.S",
    "generated/win-aarch64/crypto/cipher_extra/chacha20_poly1305_armv8-win.S",
};

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const target_info = try std.zig.system.NativeTargetInfo.detect(target);
    const boringssl_dep = b.dependency("boringssl", .{});
    const winpthreads_dep = b.dependency("winpthreads", .{
        .target = target,
        .optimize = optimize,
    });
    const libfipsmodule = b.addStaticLibrary(.{
        .name = "fipsmodule",
        .target = target,
        .optimize = optimize,
    });
    libfipsmodule.linkLibC();
    libfipsmodule.addIncludePath(boringssl_dep.path("include"));
    inline for (fipsmodule_sources) |path| {
        libfipsmodule.addCSourceFile(.{
            .file = boringssl_dep.path(path),
            .flags = &.{},
        });
    }
    inline for (generated_fipsmodule_sources) |path| {
        libfipsmodule.addCSourceFile(.{
            .file = .{ .path = path },
            .flags = &.{},
        });
    }
    if (target_info.target.os.tag == .windows) {
        addWindowsOptions(libfipsmodule, winpthreads_dep);
    }
    b.installArtifact(libfipsmodule);

    const libcrypto = b.addStaticLibrary(.{
        .name = "crypto",
        .root_source_file = .{ .path = "src/compat.zig" },
        .target = target,
        .optimize = optimize,
    });
    if (target_info.target.os.tag == .windows) {
        addWindowsOptions(libcrypto, winpthreads_dep);
        libcrypto.linkSystemLibrary("ws2_32");
    }
    libcrypto.linkLibC();
    libcrypto.linkLibrary(libfipsmodule);
    libcrypto.addIncludePath(boringssl_dep.path("include"));
    inline for (crypto_sources) |path| {
        libcrypto.addCSourceFile(.{
            .file = boringssl_dep.path(path),
            .flags = &.{},
        });
    }
    inline for (generated_crypto_sources) |path| {
        libcrypto.addCSourceFile(.{
            .file = .{ .path = path },
            .flags = &.{},
        });
    }

    b.installArtifact(libcrypto);
    const libssl = b.addStaticLibrary(.{
        .name = "ssl",
        .target = target,
        .optimize = optimize,
    });
    libssl.linkLibC();
    libssl.linkLibCpp();
    libssl.linkLibrary(libcrypto);
    libssl.addIncludePath(boringssl_dep.path("include"));
    libssl.installHeadersDirectory(
        boringssl_dep.path("include").getPath(b),
        "",
    );
    inline for (ssl_sources) |path| {
        libssl.addCSourceFile(.{
            .file = boringssl_dep.path(path),
            .flags = &.{},
        });
    }
    if (target_info.target.os.tag == .windows) {
        addWindowsOptions(libssl, winpthreads_dep);
    }
    b.installArtifact(libssl);

    const libdecrepit = b.addStaticLibrary(.{
        .name = "decrepit",
        .target = target,
        .optimize = optimize,
    });
    libdecrepit.linkLibC();
    libdecrepit.linkLibrary(libcrypto);
    libdecrepit.linkLibrary(libssl);
    libdecrepit.addIncludePath(boringssl_dep.path("include"));
    inline for (decrepit_sources) |path| {
        libdecrepit.addCSourceFile(.{
            .file = boringssl_dep.path(path),
            .flags = &.{},
        });
    }
    if (target_info.target.os.tag == .windows) {
        addWindowsOptions(libdecrepit, winpthreads_dep);
    }
    b.installArtifact(libdecrepit);

    const libpki = b.addStaticLibrary(.{
        .name = "pki",
        .target = target,
        .optimize = optimize,
    });
    libpki.linkLibC();
    libpki.linkLibCpp();
    libpki.linkLibrary(libcrypto);
    libpki.addIncludePath(boringssl_dep.path("include"));
    libpki.defineCMacro("_BORINGSSL_LIBPKI_", null);
    inline for (pki_sources) |path| {
        libpki.addCSourceFile(.{
            .file = boringssl_dep.path(path),
            .flags = &.{},
        });
    }
    if (target_info.target.os.tag == .windows) {
        addWindowsOptions(libpki, winpthreads_dep);
    }
    b.installArtifact(libpki);

    const bssl = b.addExecutable(.{
        .name = "bssl",
        .target = target,
        .optimize = optimize,
    });
    bssl.linkLibC();
    bssl.linkLibCpp();
    bssl.linkLibrary(libssl);
    bssl.linkLibrary(libcrypto);
    bssl.addIncludePath(boringssl_dep.path("include"));
    inline for (bssl_sources) |path| {
        bssl.addCSourceFile(.{
            .file = boringssl_dep.path(path),
            .flags = &.{},
        });
    }
    if (target_info.target.os.tag == .windows) {
        addWindowsOptions(bssl, winpthreads_dep);
    }
    b.installArtifact(bssl);

    const tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    const run_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}

inline fn addWindowsOptions(
    artifact: *std.Build.Step.Compile,
    winpthread: *std.Build.Dependency,
) void {
    artifact.defineCMacro("OPENSSL_NO_ASM", null);
    artifact.defineCMacro("WIN32_LEAN_AND_MEAN", null);
    artifact.linkLibrary(winpthread.artifact("winpthreads"));
}
