module secp256k1;

import std::os::process;
import std::core::dstring;
import std::io;

fault Error
{
    CANNOT_CRAETE_KEYPAIR,
    CANNOT_SECP256K1_CONTEXT,
    CANNOT_CRAETE_PUBKEY,
    CANNOT_PARSE_PUBKEY,
    CANNOT_SERIALIZE_PUBKEY,
    CANNOT_CREATE_SCHNORR_SIG,
    CANNOT_CRAETE_PRIVKEY,
    CANNOT_RANDOMIZE_SECP256K1_CONTEXT,
    INVALID_LENGTH
}

fn char[]! sha256sum(char[] msg){
    String command = "sha256";
    DString ds = dstring::temp_new();
    foreach(c:msg){
        ds.append(c);
    }
    SubProcess x = process::create({ command, "-s",  ds.str_view()}, { .search_user_path = true })!!;
    x.join()!;
    InStream stream = &&x.stdout();
    DString out = dstring::temp_new();

    while (try char b = stream.read_byte())
    {
        out.append(b);
    }

    return out.str_view();
}

fn void! rand_bytes(char[] b) {
    File file = file::open("/dev/urandom", "rb")!;
    defer { file.close()!!; };
    file.read(b)!;
}

const uint SECP256K1_FLAGS_TYPE_CONTEXT = (1 << 0);
const uint SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = (1 << 8);
const uint SECP256K1_FLAGS_BIT_CONTEXT_SIGN = (1 << 9);

const uint SECP256K1_CONTEXT_NONE = SECP256K1_FLAGS_TYPE_CONTEXT;
const uint SECP256K1_CONTEXT_VERIFY = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY);
const uint SECP256K1_CONTEXT_SIGN = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN);

def CSecp256k1_context = void;

struct CSecp256k1_xonly_pubkey {
    char[64] data;
}
struct CSecp256k1_keypair {
    char[96] data;
}
struct CSecp256k1_pubkey {
    char[64] data;
}
struct CSecp256k1_ecdsa_signature {
    char[64] data;
}
struct CSecp256k1_ecdsa_recoverable_signature {
    char[65] data;
}
struct CSecp256k1_schnorrsig_extraparams{
    char[4] magic;
    void* noncefp;
    void* ndata;
}

extern fn CSecp256k1_context* secp256k1_context_create(uint flags) @extern("secp256k1_context_create");  
extern fn CSecp256k1_context* secp256k1_context_clone(CSecp256k1_context* ctx) @extern("secp256k1_context_clone");  
extern fn void secp256k1_context_destroy(CSecp256k1_context* ctx) @extern("secp256k1_context_destroy");
extern fn void secp256k1_context_set_illegal_callback(CSecp256k1_context* ctx, void* fun, void* data) @extern("secp256k1_context_set_illegal_callback");
extern fn void secp256k1_context_set_error_callback(CSecp256k1_context* ctx, void* fun, void* data) @extern("secp256k1_context_set_error_callback");

extern fn int secp256k1_ec_pubkey_parse(CSecp256k1_context* ctx, CSecp256k1_pubkey* pubkey, char* input, int inputlen) @extern("secp256k1_ec_pubkey_parse");
extern fn int secp256k1_ec_pubkey_serialize(CSecp256k1_context* ctx, char* output, int* outputlen, CSecp256k1_pubkey* pubkey, uint flags) @extern("secp256k1_ec_pubkey_serialize");
extern fn int secp256k1_ec_pubkey_cmp(CSecp256k1_context* ctx, CSecp256k1_pubkey* pubkey0, CSecp256k1_pubkey* pubkey1) @extern("secp256k1_ec_pubkey_cmp");
extern fn int secp256k1_ec_pubkey_sort(CSecp256k1_context* ctx, CSecp256k1_pubkey** pubkeys, int npubkeys) @extern("secp256k1_ec_pubkey_sort");

extern fn int secp256k1_ecdsa_signature_parse_compact(CSecp256k1_context* ctx, CSecp256k1_ecdsa_signature* sig, char* input64) @extern("secp256k1_ecdsa_signature_parse_compact");
extern fn int secp256k1_ecdsa_signature_parse_der(CSecp256k1_context* ctx, CSecp256k1_ecdsa_signature* sig, char* input, int inputlen) @extern("secp256k1_ecdsa_signature_parse_der");
extern fn int secp256k1_ecdsa_signature_serialize_der(CSecp256k1_context* ctx, char* output, int* outputlen, CSecp256k1_ecdsa_signature* sig) @extern("secp256k1_ecdsa_signature_serialize_der");
extern fn int secp256k1_ecdsa_signature_serialize_compact(CSecp256k1_context* ctx, char* output64, CSecp256k1_ecdsa_signature* sig) @extern("secp256k1_ecdsa_signature_serialize_compact");
extern fn int secp256k1_ecdsa_verify(CSecp256k1_context* ctx, CSecp256k1_ecdsa_signature* sig, char* msghash32, CSecp256k1_pubkey* pubkey) @extern("secp256k1_ecdsa_verify");
extern fn int secp256k1_ecdsa_signature_normalize(CSecp256k1_context* ctx, CSecp256k1_ecdsa_signature* sigout, CSecp256k1_ecdsa_signature* sigin) @extern("secp256k1_ecdsa_signature_normalize");
extern fn int secp256k1_ecdsa_sign(CSecp256k1_context* ctx, CSecp256k1_ecdsa_signature* sig, char* msghash32, char* seckey, void* noncefp, void* noncedata) @extern("secp256k1_ecdsa_sign");

extern fn int secp256k1_ec_seckey_verify(CSecp256k1_context* ctx, char* seckey)  @extern("secp256k1_ec_seckey_verify");
extern fn int secp256k1_ec_pubkey_create(CSecp256k1_context* ctx, CSecp256k1_pubkey* pubkey, char* seckey) @extern("secp256k1_ec_pubkey_create");
extern fn int secp256k1_ec_seckey_negate(CSecp256k1_context* ctx, char* seckey) @extern("secp256k1_ec_seckey_negate");
extern fn int secp256k1_ec_seckey_tweak_add(CSecp256k1_context* ctx, char* seckey, char* tweak32) @extern("secp256k1_ec_seckey_tweak_add");
extern fn int secp256k1_ec_pubkey_tweak_add(CSecp256k1_context* ctx, CSecp256k1_pubkey* pubkey, char* tweak32) @extern("secp256k1_ec_pubkey_tweak_add");
extern fn int secp256k1_ec_seckey_tweak_mul(CSecp256k1_context* ctx, char* seckey, char* tweak32) @extern("secp256k1_ec_seckey_tweak_mul");
extern fn int secp256k1_ec_pubkey_tweak_mul(CSecp256k1_context* ctx, CSecp256k1_pubkey* pubkey, char* tweak32) @extern("secp256k1_ec_pubkey_tweak_mul");

extern fn int secp256k1_context_randomize(CSecp256k1_context* ctx, char* seed32) @extern("secp256k1_context_randomize");
extern fn int secp256k1_ec_pubkey_combine(CSecp256k1_context* ctx, CSecp256k1_pubkey* pubnonce, CSecp256k1_pubkey** pubnonces, int npubnonces) @extern("secp256k1_ec_pubkey_combine");
extern fn int secp256k1_tagged_sha256(CSecp256k1_context* ctx, char* hash32, char* tag, int taglen, char* msg, int msglen) @extern("secp256k1_tagged_sha256");

extern fn int secp256k1_ecdsa_recoverable_signature_parse_compact(CSecp256k1_context* ctx, CSecp256k1_ecdsa_recoverable_signature* sig, char* input64, int recid) @extern("secp256k1_ecdsa_recoverable_signature_parse_compact");
extern fn int secp256k1_ecdsa_recoverable_signature_convert(CSecp256k1_context* ctx, CSecp256k1_ecdsa_signature* sig, CSecp256k1_ecdsa_recoverable_signature* sigin) @extern("secp256k1_ecdsa_recoverable_signature_convert");
extern fn int secp256k1_ecdsa_recoverable_signature_serialize_compact(CSecp256k1_context* ctx, char* output64, int* recid, CSecp256k1_ecdsa_recoverable_signature* sigin) @extern("secp256k1_ecdsa_recoverable_signature_serialize_compact");
extern fn int secp256k1_ecdsa_sign_recoverable(CSecp256k1_context* ctx, CSecp256k1_ecdsa_recoverable_signature* signature, char* msghash32, char* seckey, void* noncefp, void* noncedata) @extern("secp256k1_ecdsa_sign_recoverable");
extern fn int secp256k1_ecdsa_recover(CSecp256k1_context* ctx, CSecp256k1_pubkey* pubkey, CSecp256k1_ecdsa_recoverable_signature* signature, char* msghash32) @extern("secp256k1_ecdsa_recover");

extern fn int secp256k1_ecdh(CSecp256k1_context* ctx, char* output, CSecp256k1_pubkey* point, char* scalar, void* hashfp, void* data) @extern("secp256k1_ecdh");

extern fn int secp256k1_xonly_pubkey_parse(CSecp256k1_context* ctx, CSecp256k1_xonly_pubkey* pubkey, char* input32) @extern("secp256k1_xonly_pubkey_parse");
extern fn int secp256k1_xonly_pubkey_serialize(CSecp256k1_context* ctx, char* output32, CSecp256k1_xonly_pubkey* pubkey) @extern("secp256k1_xonly_pubkey_serialize");
extern fn int secp256k1_xonly_pubkey_cmp(CSecp256k1_context* ctx, CSecp256k1_pubkey* pk0, CSecp256k1_pubkey* pk1) @extern("secp256k1_xonly_pubkey_cmp");
extern fn int secp256k1_xonly_pubkey_from_pubkey(CSecp256k1_context* ctx, CSecp256k1_xonly_pubkey* xonly_pubkey, int* pk_parity, CSecp256k1_pubkey* pubkey) @extern("secp256k1_xonly_pubkey_from_pubkey");
extern fn int secp256k1_xonly_pubkey_tweak_add(CSecp256k1_context* ctx, CSecp256k1_pubkey* output_pubkey, CSecp256k1_xonly_pubkey* internal_pubkey, char* tweak32) @extern("secp256k1_xonly_pubkey_tweak_add");
extern fn int secp256k1_xonly_pubkey_tweak_add_check(CSecp256k1_context* ctx, char* tweaked_pubkey32, int tweaked_pk_parity, CSecp256k1_xonly_pubkey* internal_pubkey, char* tweak32) @extern("secp256k1_xonly_pubkey_tweak_add");

extern fn int secp256k1_keypair_create(CSecp256k1_context* ctx, CSecp256k1_keypair* keypair, char* seckey32) @extern("secp256k1_keypair_create");
extern fn int secp256k1_keypair_sec(CSecp256k1_context* ctx, char* seckey, CSecp256k1_keypair* keypair) @extern("secp256k1_keypair_sec");
extern fn int secp256k1_keypair_pub(CSecp256k1_context* ctx, CSecp256k1_pubkey* pubkey, CSecp256k1_keypair* keypair) @extern("secp256k1_keypair_pub");
extern fn int secp256k1_keypair_xonly_pub(CSecp256k1_context* ctx, CSecp256k1_xonly_pubkey* pubkey, int* pk_parity, CSecp256k1_keypair* keypair) @extern("secp256k1_keypair_xonly_pub");
extern fn int secp256k1_keypair_xonly_tweak_add(CSecp256k1_context* ctx, CSecp256k1_keypair* keypair, char* tweak32) @extern("secp256k1_keypair_xonly_tweak_add");

extern fn int secp256k1_schnorrsig_sign32(CSecp256k1_context* ctx, char* sig64, char* msg32, CSecp256k1_keypair* keypair, char* aux_rand32) @extern("secp256k1_schnorrsig_sign32");
extern fn int secp256k1_schnorrsig_sign_custom(CSecp256k1_context* ctx, char* sig64, char* msg, int msglen, CSecp256k1_keypair* keypair, CSecp256k1_schnorrsig_extraparams* extraparams) @extern("secp256k1_schnorrsig_sign_custom");
extern fn int secp256k1_schnorrsig_verify(CSecp256k1_context* ctx, char* sig64, char* msg, int msglen, CSecp256k1_xonly_pubkey* pubkey) @extern("secp256k1_schnorrsig_verify");

def XOnlyPubkey = CSecp256k1_xonly_pubkey;

struct Context {
    CSecp256k1_context* ctx;
}

struct KeyPair {
    CSecp256k1_keypair keypair;
}

fn Context*! create_context() {
    CSecp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    
    if (ctx == null) {
        return Error.CANNOT_SECP256K1_CONTEXT?;
    }

    return mem::new(Context, {ctx});
}

fn Context*! create_and_randomize_context() {
    Context* ctx = create_context()!;
    
    char[] entropy = mem::temp_new_array(char, 32);
    rand_bytes(entropy)!;

    if (secp256k1_context_randomize(ctx.ctx, entropy) != 1) {
        return Error.CANNOT_RANDOMIZE_SECP256K1_CONTEXT?;
    }

    return ctx;
}

fn void Context.destroy(&self) {
    secp256k1_context_destroy(self.ctx);
}

fn char[]! generate_private_key() {
    Context* ctx = create_and_randomize_context()!;

    for(;;) {
        char[] private_key = mem::temp_new_array(char, 32);
        
        rand_bytes(private_key)!;

        if (secp256k1_ec_seckey_verify(ctx.ctx, private_key) == 1) {
            return private_key;
        }
    }
}

fn KeyPair*! Context.create_keypair(&self, char[] seckey)  {
    CSecp256k1_keypair keypair;
    if (secp256k1_keypair_create(self.ctx, &keypair, seckey) != 1) {
        return Error.CANNOT_CRAETE_KEYPAIR?;
    }
    return mem::new(KeyPair,{keypair});
}

fn XOnlyPubkey*! Context.create_xonly_pubkey_from_keypair(&self, KeyPair* keypair)  {
    XOnlyPubkey* pubkey = mem::new(XOnlyPubkey);
    if (secp256k1_keypair_xonly_pub(self.ctx, pubkey, null, &keypair.keypair) != 1) {
        return Error.CANNOT_CRAETE_PUBKEY?;
    }
    return pubkey;
}

fn XOnlyPubkey*! Context.create_xonly_pubkey_from_pubkey_bytes(&self, char* pubkey) {
    CSecp256k1_xonly_pubkey* pubkey_struct = mem::new(CSecp256k1_xonly_pubkey);
    if (secp256k1_xonly_pubkey_parse(self.ctx, pubkey_struct, pubkey) != 1) {
        return Error.CANNOT_PARSE_PUBKEY?;
    }
    return pubkey_struct;
}

fn char[]! Context.serialize_xonly_pubkey(&self, XOnlyPubkey* pubkey) {
    char[] serialized = mem::new_array(char, 32);
    if (secp256k1_xonly_pubkey_serialize(self.ctx, serialized, pubkey) != 1) {
        return Error.CANNOT_SERIALIZE_PUBKEY?;
    }
    return serialized;
}

 fn char[]! Context.sign_schnorr(&self, char[] msg, KeyPair* keypair) {
    char[] msg_hash = sha256sum(msg)!!;
    char[] sig = mem::new_array(char, 64);
    if (secp256k1_schnorrsig_sign32(self.ctx, sig, msg_hash, &keypair.keypair,
        null) != 1) {
        return Error.CANNOT_CREATE_SCHNORR_SIG?;
    }
    return sig;
}

fn bool Context.verify_schnorr(&self, char[] sig, char[] msg, XOnlyPubkey* pubkey) {
    char[] msg_hash = sha256sum(msg)!!;

    return secp256k1_schnorrsig_verify(self.ctx, sig, msg_hash, 32, pubkey) == 1;
}

