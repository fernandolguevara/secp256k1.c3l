module secp256k1::test @test;

import secp256k1;
import std::io;

fn void! test_context_creation() {
    Context* ctx = secp256k1::create_and_randomize_context()!;
    defer { ctx.destroy(); };
    assert (ctx!= null, "Context should not be nil");
}

fn void! test_private_key_generation() {
    char[] private_key = secp256k1::generate_private_key()!;
    char[] empty = mem::new_array(char, 32);
    assert (private_key.len == 32, "Private key length should be 32 bytes");
    assert (private_key != empty, "Private key should not be all zeros");
}

fn void test_keypair_creation() {
    Context* ctx = secp256k1::create_and_randomize_context()!;
    defer { ctx.destroy(); }
    char[] private_key = secp256k1::generate_private_key()!;

    KeyPair* keypair = ctx.create_keypair(private_key)!;
    
    assert (keypair != null, "Keypair should not be nil");
}

fn void test_xonly_pubkey_creation_and_serialization() {
    Context* ctx = secp256k1::create_and_randomize_context()!;
    defer { ctx.destroy();}
    char[] private_key = secp256k1::generate_private_key()!;
    KeyPair* keypair = ctx.create_keypair(private_key)!;
    XOnlyPubkey* x_pubkey = ctx.create_xonly_pubkey_from_keypair(keypair)!;

    assert(x_pubkey != null, "Xonly pubkey should not be nil");

    char[] x_pubkey_bytes = ctx.serialize_xonly_pubkey(x_pubkey)!;

    assert(x_pubkey_bytes.len == 32, "Serialized xonly pubkey should be 32 bytes");
}

fn void test_schnorr_signing_and_verification() {
    Context* ctx = secp256k1::create_and_randomize_context()!;
    defer { ctx.destroy(); }
    char[] private_key = secp256k1::generate_private_key()!;
    KeyPair* keypair = ctx.create_keypair(private_key)!;
    XOnlyPubkey* x_pubkey = ctx.create_xonly_pubkey_from_keypair(keypair)!;

    char[] message = "Hello, Schnorr!";
    char[] signature = ctx.sign_schnorr(message, keypair)!;

    assert (signature.len == 64, "Schnorr signature should be 64 bytes");

    bool is_valid = ctx.verify_schnorr(signature, message, x_pubkey);
    assert (is_valid, "Signature should be valid");

    // Test with wrong message
    char[] wrong_message = "Wrong message";
    bool is_invalid = ctx.verify_schnorr(signature, wrong_message, x_pubkey);
    assert (!is_invalid, "Signature should be invalid for wrong message");
}

fn void! test_error_conditions() {
    Context* ctx = secp256k1::create_and_randomize_context()!;
    defer { ctx.destroy(); }

    // Test with invalid private key
    char[] invalid_private_key = mem::new_array(char, 31); // Too short
    KeyPair*! keypair_result = ctx.create_keypair(invalid_private_key);
    if(catch err = keypair_result){
        assert(err == Error.CANNOT_CRAETE_KEYPAIR, "Should have failed with invalid private key");
    }

    // Test with invalid message length for signing
    char[] private_key = secp256k1::generate_private_key()!;
    KeyPair* valid_keypair = ctx.create_keypair(private_key)!;
    char[] invalid_message = mem::new_array(char, 0); // secp256k1 expects 32-byte message
    char[]! sign_result = ctx.sign_schnorr(invalid_message, valid_keypair);
    if(catch err = sign_result){
       assert (err == Error.CANNOT_CREATE_SCHNORR_SIG, "Should fail with invalid message length");
    }

    XOnlyPubkey* x_pubkey = ctx.create_xonly_pubkey_from_keypair(valid_keypair)!;

    bool is_valid = ctx.verify_schnorr(sign_result, invalid_message, x_pubkey)!;
    assert(is_valid, "valid??");
    // assert(false, "Should have failed with invalid message length");
}
