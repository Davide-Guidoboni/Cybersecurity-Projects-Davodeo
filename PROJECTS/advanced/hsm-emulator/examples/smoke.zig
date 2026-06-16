// ©AngelaMos | 2026
// smoke.zig

const std = @import("std");
const ck = @import("ck");

const GetFunctionList = *const fn (*?*ck.CK_FUNCTION_LIST) callconv(.c) ck.CK_RV;

const default_module = "zig-out/lib/libhsm.so";
const smoke_token = "/tmp/angelamos-hsm-smoke-token.bin";
const smoke_objects = "/tmp/angelamos-hsm-smoke-objects.bin";

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;

pub fn main() !void {
    _ = setenv("ANGELAMOS_HSM_TOKEN", smoke_token, 1);
    _ = setenv("ANGELAMOS_HSM_OBJECTS", smoke_objects, 1);
    _ = std.c.unlink(smoke_token);
    _ = std.c.unlink(smoke_objects);
    defer _ = std.c.unlink(smoke_token);
    defer _ = std.c.unlink(smoke_objects);

    var so_pin = "12345678".*;
    var user_pin = "1234".*;
    var new_user_pin = "5678".*;
    var wrong_pin = "0000".*;
    var short_pin = "12".*;
    var label: [32]u8 = @splat(' ');
    @memcpy(label[0..11], "smoke-token");

    var lib = try std.DynLib.open(default_module);
    defer lib.close();

    const getFunctionList = lib.lookup(GetFunctionList, "C_GetFunctionList") orelse {
        std.debug.print("smoke: C_GetFunctionList not exported\n", .{});
        return error.SymbolNotFound;
    };

    var list_ptr: ?*ck.CK_FUNCTION_LIST = null;
    try check("C_GetFunctionList", getFunctionList(&list_ptr));
    const f = list_ptr orelse return error.NullFunctionList;

    if (f.version.major != 2 or f.version.minor != 40) return error.UnexpectedVersion;

    try check("C_Initialize", f.C_Initialize.?(null));
    if (f.C_Initialize.?(null) != ck.CKR_CRYPTOKI_ALREADY_INITIALIZED) return error.DoubleInitNotRejected;

    var info: ck.CK_INFO = undefined;
    try check("C_GetInfo", f.C_GetInfo.?(&info));

    var count: ck.CK_ULONG = 0;
    try check("C_GetSlotList(size)", f.C_GetSlotList.?(ck.CK_FALSE, null, &count));
    if (count != 1) return error.UnexpectedSlotCount;
    var slots: [4]ck.CK_SLOT_ID = undefined;
    try check("C_GetSlotList(fill)", f.C_GetSlotList.?(ck.CK_FALSE, &slots, &count));
    const slot = slots[0];

    var slot_info: ck.CK_SLOT_INFO = undefined;
    try check("C_GetSlotInfo", f.C_GetSlotInfo.?(slot, &slot_info));

    var token_info: ck.CK_TOKEN_INFO = undefined;
    try check("C_GetTokenInfo", f.C_GetTokenInfo.?(slot, &token_info));
    if (token_info.flags & ck.CKF_TOKEN_INITIALIZED != 0) return error.TokenShouldStartUninitialized;

    var mech_count: ck.CK_ULONG = 0;
    try check("C_GetMechanismList(size)", f.C_GetMechanismList.?(slot, null, &mech_count));
    if (mech_count == 0) return error.NoMechanisms;

    if (f.C_InitToken.?(slot, &short_pin, short_pin.len, &label) != ck.CKR_PIN_LEN_RANGE) return error.ShortSoPinNotRejected;
    try check("C_InitToken", f.C_InitToken.?(slot, &so_pin, so_pin.len, &label));
    try check("C_GetTokenInfo(post-init)", f.C_GetTokenInfo.?(slot, &token_info));
    if (token_info.flags & ck.CKF_TOKEN_INITIALIZED == 0) return error.InitTokenDidNotInitialize;

    var h: ck.CK_SESSION_HANDLE = 0;
    try check("C_OpenSession", f.C_OpenSession.?(slot, ck.CKF_SERIAL_SESSION | ck.CKF_RW_SESSION, null, null, &h));

    var si: ck.CK_SESSION_INFO = undefined;
    try check("C_GetSessionInfo", f.C_GetSessionInfo.?(h, &si));
    if (si.state != ck.CKS_RW_PUBLIC_SESSION) return error.UnexpectedPublicState;

    try check("C_Login(SO)", f.C_Login.?(h, ck.CKU_SO, &so_pin, so_pin.len));
    try check("C_GetSessionInfo(SO)", f.C_GetSessionInfo.?(h, &si));
    if (si.state != ck.CKS_RW_SO_FUNCTIONS) return error.UnexpectedSoState;

    if (f.C_InitPIN.?(h, &short_pin, short_pin.len) != ck.CKR_PIN_LEN_RANGE) return error.ShortUserPinNotRejected;
    try check("C_InitPIN", f.C_InitPIN.?(h, &user_pin, user_pin.len));
    try check("C_Logout(SO)", f.C_Logout.?(h));

    try check("C_GetTokenInfo(post-initpin)", f.C_GetTokenInfo.?(slot, &token_info));
    if (token_info.flags & ck.CKF_USER_PIN_INITIALIZED == 0) return error.UserPinNotInitialized;

    try check("C_Login(USER)", f.C_Login.?(h, ck.CKU_USER, &user_pin, user_pin.len));
    try check("C_GetSessionInfo(USER)", f.C_GetSessionInfo.?(h, &si));
    if (si.state != ck.CKS_RW_USER_FUNCTIONS) return error.UnexpectedUserState;

    if (f.C_SetPIN.?(h, &user_pin, user_pin.len, &short_pin, short_pin.len) != ck.CKR_PIN_LEN_RANGE) return error.ShortNewPinNotRejected;
    try check("C_SetPIN", f.C_SetPIN.?(h, &user_pin, user_pin.len, &new_user_pin, new_user_pin.len));
    try check("C_Logout(USER)", f.C_Logout.?(h));

    try check("C_Login(USER,new)", f.C_Login.?(h, ck.CKU_USER, &new_user_pin, new_user_pin.len));

    var class_data: ck.CK_OBJECT_CLASS = ck.CKO_DATA;
    var ck_true: ck.CK_BBOOL = ck.CK_TRUE;
    var data_label = "smoke-data".*;
    var data_value = "hello-hsm".*;
    var create_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_CLASS, .pValue = &class_data, .ulValueLen = @sizeOf(ck.CK_OBJECT_CLASS) },
        .{ .type = ck.CKA_LABEL, .pValue = &data_label, .ulValueLen = data_label.len },
        .{ .type = ck.CKA_VALUE, .pValue = &data_value, .ulValueLen = data_value.len },
    };
    var h_data: ck.CK_OBJECT_HANDLE = 0;
    try check("C_CreateObject(data)", f.C_CreateObject.?(h, &create_tmpl, create_tmpl.len, &h_data));
    if (h_data == ck.CK_INVALID_HANDLE) return error.BadObjectHandle;

    var priv_label = "smoke-secret".*;
    var priv_value = "top-secret".*;
    var priv_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_CLASS, .pValue = &class_data, .ulValueLen = @sizeOf(ck.CK_OBJECT_CLASS) },
        .{ .type = ck.CKA_PRIVATE, .pValue = &ck_true, .ulValueLen = 1 },
        .{ .type = ck.CKA_LABEL, .pValue = &priv_label, .ulValueLen = priv_label.len },
        .{ .type = ck.CKA_VALUE, .pValue = &priv_value, .ulValueLen = priv_value.len },
    };
    var h_priv: ck.CK_OBJECT_HANDLE = 0;
    try check("C_CreateObject(private)", f.C_CreateObject.?(h, &priv_tmpl, priv_tmpl.len, &h_priv));

    var find_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_CLASS, .pValue = &class_data, .ulValueLen = @sizeOf(ck.CK_OBJECT_CLASS) },
    };
    var found: [8]ck.CK_OBJECT_HANDLE = undefined;
    var nfound: ck.CK_ULONG = 0;
    try check("C_FindObjectsInit", f.C_FindObjectsInit.?(h, &find_tmpl, find_tmpl.len));
    try check("C_FindObjects", f.C_FindObjects.?(h, &found, found.len, &nfound));
    try check("C_FindObjectsFinal", f.C_FindObjectsFinal.?(h));
    if (nfound != 2) return error.FindCountWrong;

    var probe = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_VALUE, .pValue = null, .ulValueLen = 0 },
    };
    try check("C_GetAttributeValue(len)", f.C_GetAttributeValue.?(h, h_data, &probe, probe.len));
    if (probe[0].ulValueLen != data_value.len) return error.LenProbeWrong;
    var valbuf: [64]u8 = undefined;
    probe[0].pValue = &valbuf;
    try check("C_GetAttributeValue(fetch)", f.C_GetAttributeValue.?(h, h_data, &probe, probe.len));
    if (!std.mem.eql(u8, valbuf[0..probe[0].ulValueLen], &data_value)) return error.ValueMismatch;

    var new_label = "relabeled!!".*;
    var set_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_LABEL, .pValue = &new_label, .ulValueLen = new_label.len },
    };
    try check("C_SetAttributeValue", f.C_SetAttributeValue.?(h, h_data, &set_tmpl, set_tmpl.len));
    var lblbuf: [32]u8 = undefined;
    var lblq = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_LABEL, .pValue = &lblbuf, .ulValueLen = lblbuf.len },
    };
    try check("C_GetAttributeValue(label)", f.C_GetAttributeValue.?(h, h_data, &lblq, lblq.len));
    if (!std.mem.eql(u8, lblbuf[0..lblq[0].ulValueLen], &new_label)) return error.RelabelFailed;

    var osize: ck.CK_ULONG = 0;
    try check("C_GetObjectSize", f.C_GetObjectSize.?(h, h_data, &osize));
    if (osize == 0) return error.ZeroObjectSize;

    try check("C_DestroyObject", f.C_DestroyObject.?(h, h_data));
    if (f.C_FindObjects.?(h, &found, found.len, &nfound) != ck.CKR_OPERATION_NOT_INITIALIZED) return error.FsmNotEnforced;

    try check("C_Logout(after-objects)", f.C_Logout.?(h));
    try check("C_FindObjectsInit(public)", f.C_FindObjectsInit.?(h, null, 0));
    try check("C_FindObjects(public)", f.C_FindObjects.?(h, &found, found.len, &nfound));
    try check("C_FindObjectsFinal(public)", f.C_FindObjectsFinal.?(h));
    if (nfound != 0) return error.PrivateObjectLeaked;
    if (f.C_GetAttributeValue.?(h, h_priv, &lblq, lblq.len) != ck.CKR_OBJECT_HANDLE_INVALID) return error.PrivateNotGated;

    var ck_false: ck.CK_BBOOL = ck.CK_FALSE;
    var undead_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_CLASS, .pValue = &class_data, .ulValueLen = @sizeOf(ck.CK_OBJECT_CLASS) },
        .{ .type = ck.CKA_DESTROYABLE, .pValue = &ck_false, .ulValueLen = 1 },
    };
    var h_undead: ck.CK_OBJECT_HANDLE = 0;
    try check("C_CreateObject(undestroyable)", f.C_CreateObject.?(h, &undead_tmpl, undead_tmpl.len, &h_undead));
    if (f.C_DestroyObject.?(h, h_undead) != ck.CKR_ACTION_PROHIBITED) return error.DestroyableGateBroken;

    var immut_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_CLASS, .pValue = &class_data, .ulValueLen = @sizeOf(ck.CK_OBJECT_CLASS) },
        .{ .type = ck.CKA_MODIFIABLE, .pValue = &ck_false, .ulValueLen = 1 },
    };
    var h_immut: ck.CK_OBJECT_HANDLE = 0;
    try check("C_CreateObject(immutable)", f.C_CreateObject.?(h, &immut_tmpl, immut_tmpl.len, &h_immut));
    var nope = "nope".*;
    var set_immut = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_LABEL, .pValue = &nope, .ulValueLen = nope.len },
    };
    if (f.C_SetAttributeValue.?(h, h_immut, &set_immut, set_immut.len) != ck.CKR_ACTION_PROHIBITED) return error.ModifiableGateBroken;

    if (f.C_FindObjectsInit.?(h, null, 3) != ck.CKR_ARGUMENTS_BAD) return error.ArgsBadNotEnforced;

    var attempt: u8 = 0;
    while (attempt < 3) : (attempt += 1) {
        if (f.C_Login.?(h, ck.CKU_USER, &wrong_pin, wrong_pin.len) != ck.CKR_PIN_INCORRECT) return error.WrongPinNotRejected;
    }
    if (f.C_Login.?(h, ck.CKU_USER, &new_user_pin, new_user_pin.len) != ck.CKR_PIN_LOCKED) return error.LockoutNotEnforced;
    try check("C_GetTokenInfo(locked)", f.C_GetTokenInfo.?(slot, &token_info));
    if (token_info.flags & ck.CKF_USER_PIN_LOCKED == 0) return error.LockFlagNotSet;

    var sha_mech = ck.CK_MECHANISM{ .mechanism = ck.CKM_SHA256, .pParameter = null, .ulParameterLen = 0 };
    try check("C_DigestInit", f.C_DigestInit.?(h, &sha_mech));
    var abc = "abc".*;
    var dg: [64]u8 = undefined;
    var dglen: ck.CK_ULONG = dg.len;
    try check("C_Digest", f.C_Digest.?(h, &abc, abc.len, &dg, &dglen));
    const sha_abc = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    if (dglen != 32 or !std.mem.eql(u8, dg[0..32], &sha_abc)) return error.DigestVectorMismatch;

    var class_secret: ck.CK_OBJECT_CLASS = ck.CKO_SECRET_KEY;
    var ck_yes: ck.CK_BBOOL = ck.CK_TRUE;
    var kt_generic: ck.CK_KEY_TYPE = ck.CKK_GENERIC_SECRET;
    var hkey_val = "secret-hmac-key".*;
    var hmac_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_CLASS, .pValue = &class_secret, .ulValueLen = @sizeOf(ck.CK_OBJECT_CLASS) },
        .{ .type = ck.CKA_KEY_TYPE, .pValue = &kt_generic, .ulValueLen = @sizeOf(ck.CK_KEY_TYPE) },
        .{ .type = ck.CKA_VALUE, .pValue = &hkey_val, .ulValueLen = hkey_val.len },
        .{ .type = ck.CKA_SIGN, .pValue = &ck_yes, .ulValueLen = 1 },
        .{ .type = ck.CKA_VERIFY, .pValue = &ck_yes, .ulValueLen = 1 },
    };
    var h_hmac: ck.CK_OBJECT_HANDLE = 0;
    try check("C_CreateObject(hmac key)", f.C_CreateObject.?(h, &hmac_tmpl, hmac_tmpl.len, &h_hmac));

    var hmac_mech = ck.CK_MECHANISM{ .mechanism = ck.CKM_SHA256_HMAC, .pParameter = null, .ulParameterLen = 0 };
    var hmsg = "authenticate me".*;
    var sig: [64]u8 = undefined;
    var siglen: ck.CK_ULONG = sig.len;
    try check("C_SignInit", f.C_SignInit.?(h, &hmac_mech, h_hmac));
    try check("C_Sign", f.C_Sign.?(h, &hmsg, hmsg.len, &sig, &siglen));
    if (siglen != 32) return error.HmacLenWrong;
    try check("C_VerifyInit", f.C_VerifyInit.?(h, &hmac_mech, h_hmac));
    try check("C_Verify", f.C_Verify.?(h, &hmsg, hmsg.len, &sig, siglen));
    try check("C_VerifyInit(tamper)", f.C_VerifyInit.?(h, &hmac_mech, h_hmac));
    sig[0] ^= 0xff;
    if (f.C_Verify.?(h, &hmsg, hmsg.len, &sig, siglen) != ck.CKR_SIGNATURE_INVALID) return error.HmacTamperNotDetected;

    var kt_aes: ck.CK_KEY_TYPE = ck.CKK_AES;
    var aes_val = [_]u8{0} ** 32;
    for (0..32) |j| aes_val[j] = @intCast(j);
    var aes_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_CLASS, .pValue = &class_secret, .ulValueLen = @sizeOf(ck.CK_OBJECT_CLASS) },
        .{ .type = ck.CKA_KEY_TYPE, .pValue = &kt_aes, .ulValueLen = @sizeOf(ck.CK_KEY_TYPE) },
        .{ .type = ck.CKA_VALUE, .pValue = &aes_val, .ulValueLen = aes_val.len },
        .{ .type = ck.CKA_ENCRYPT, .pValue = &ck_yes, .ulValueLen = 1 },
        .{ .type = ck.CKA_DECRYPT, .pValue = &ck_yes, .ulValueLen = 1 },
    };
    var h_aes: ck.CK_OBJECT_HANDLE = 0;
    try check("C_CreateObject(aes key)", f.C_CreateObject.?(h, &aes_tmpl, aes_tmpl.len, &h_aes));

    var iv = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    var cbc_mech = ck.CK_MECHANISM{ .mechanism = ck.CKM_AES_CBC_PAD, .pParameter = &iv, .ulParameterLen = iv.len };
    var aes_pt = "AES round-trip through the Cryptoki ABI".*;
    var aes_ct: [64]u8 = undefined;
    var ctlen: ck.CK_ULONG = aes_ct.len;
    try check("C_EncryptInit", f.C_EncryptInit.?(h, &cbc_mech, h_aes));
    try check("C_Encrypt", f.C_Encrypt.?(h, &aes_pt, aes_pt.len, &aes_ct, &ctlen));
    var aes_back: [64]u8 = undefined;
    var backlen: ck.CK_ULONG = aes_back.len;
    try check("C_DecryptInit", f.C_DecryptInit.?(h, &cbc_mech, h_aes));
    try check("C_Decrypt", f.C_Decrypt.?(h, &aes_ct, ctlen, &aes_back, &backlen));
    if (backlen != aes_pt.len or !std.mem.eql(u8, aes_back[0..backlen], &aes_pt)) return error.AesRoundTripFailed;

    var gen_keylen: ck.CK_ULONG = 32;
    var gen_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_VALUE_LEN, .pValue = &gen_keylen, .ulValueLen = @sizeOf(ck.CK_ULONG) },
    };
    var gen_mech = ck.CK_MECHANISM{ .mechanism = ck.CKM_AES_KEY_GEN, .pParameter = null, .ulParameterLen = 0 };
    var h_gen: ck.CK_OBJECT_HANDLE = 0;
    try check("C_GenerateKey", f.C_GenerateKey.?(h, &gen_mech, &gen_tmpl, gen_tmpl.len, &h_gen));
    var genval_q = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_VALUE, .pValue = null, .ulValueLen = 0 },
    };
    if (f.C_GetAttributeValue.?(h, h_gen, &genval_q, genval_q.len) != ck.CKR_ATTRIBUTE_SENSITIVE) return error.GeneratedKeyNotSensitive;

    var ec_params = [_]u8{ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
    var ec_kpgen = ck.CK_MECHANISM{ .mechanism = ck.CKM_EC_KEY_PAIR_GEN, .pParameter = null, .ulParameterLen = 0 };
    var ecpub_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_EC_PARAMS, .pValue = &ec_params, .ulValueLen = ec_params.len },
        .{ .type = ck.CKA_VERIFY, .pValue = &ck_yes, .ulValueLen = 1 },
    };
    var ecpriv_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_SIGN, .pValue = &ck_yes, .ulValueLen = 1 },
        .{ .type = ck.CKA_PRIVATE, .pValue = &ck_false, .ulValueLen = 1 },
    };
    var h_ecpub: ck.CK_OBJECT_HANDLE = 0;
    var h_ecpriv: ck.CK_OBJECT_HANDLE = 0;
    try check("C_GenerateKeyPair(EC)", f.C_GenerateKeyPair.?(h, &ec_kpgen, &ecpub_tmpl, ecpub_tmpl.len, &ecpriv_tmpl, ecpriv_tmpl.len, &h_ecpub, &h_ecpriv));

    var ecdsa_mech = ck.CK_MECHANISM{ .mechanism = ck.CKM_ECDSA_SHA256, .pParameter = null, .ulParameterLen = 0 };
    var ecmsg = "sign me over ECDSA P-256".*;
    var ecsig: [128]u8 = undefined;
    var ecsiglen: ck.CK_ULONG = ecsig.len;
    try check("C_SignInit(ECDSA)", f.C_SignInit.?(h, &ecdsa_mech, h_ecpriv));
    try check("C_Sign(ECDSA)", f.C_Sign.?(h, &ecmsg, ecmsg.len, &ecsig, &ecsiglen));
    if (ecsiglen != 64) return error.EcdsaSigLenWrong;
    try check("C_VerifyInit(ECDSA)", f.C_VerifyInit.?(h, &ecdsa_mech, h_ecpub));
    try check("C_Verify(ECDSA)", f.C_Verify.?(h, &ecmsg, ecmsg.len, &ecsig, ecsiglen));
    try check("C_VerifyInit(ECDSA tamper)", f.C_VerifyInit.?(h, &ecdsa_mech, h_ecpub));
    ecsig[0] ^= 0xff;
    if (f.C_Verify.?(h, &ecmsg, ecmsg.len, &ecsig, ecsiglen) != ck.CKR_SIGNATURE_INVALID) return error.EcdsaTamperNotDetected;

    var ecval_q = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_VALUE, .pValue = null, .ulValueLen = 0 },
    };
    if (f.C_GetAttributeValue.?(h, h_ecpriv, &ecval_q, ecval_q.len) != ck.CKR_ATTRIBUTE_SENSITIVE) return error.EcPrivNotSensitive;
    var ecpt_q = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_EC_POINT, .pValue = null, .ulValueLen = 0 },
    };
    try check("C_GetAttributeValue(EC_POINT)", f.C_GetAttributeValue.?(h, h_ecpub, &ecpt_q, ecpt_q.len));
    if (ecpt_q[0].ulValueLen != 67) return error.EcPointLenWrong;

    var rsa_bits: ck.CK_ULONG = 2048;
    var rsa_kpgen = ck.CK_MECHANISM{ .mechanism = ck.CKM_RSA_PKCS_KEY_PAIR_GEN, .pParameter = null, .ulParameterLen = 0 };
    var rsapub_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_MODULUS_BITS, .pValue = &rsa_bits, .ulValueLen = @sizeOf(ck.CK_ULONG) },
        .{ .type = ck.CKA_VERIFY, .pValue = &ck_yes, .ulValueLen = 1 },
        .{ .type = ck.CKA_VERIFY_RECOVER, .pValue = &ck_yes, .ulValueLen = 1 },
        .{ .type = ck.CKA_ENCRYPT, .pValue = &ck_yes, .ulValueLen = 1 },
        .{ .type = ck.CKA_WRAP, .pValue = &ck_yes, .ulValueLen = 1 },
    };
    var rsapriv_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_SIGN, .pValue = &ck_yes, .ulValueLen = 1 },
        .{ .type = ck.CKA_SIGN_RECOVER, .pValue = &ck_yes, .ulValueLen = 1 },
        .{ .type = ck.CKA_DECRYPT, .pValue = &ck_yes, .ulValueLen = 1 },
        .{ .type = ck.CKA_UNWRAP, .pValue = &ck_yes, .ulValueLen = 1 },
        .{ .type = ck.CKA_PRIVATE, .pValue = &ck_false, .ulValueLen = 1 },
    };
    var h_rsapub: ck.CK_OBJECT_HANDLE = 0;
    var h_rsapriv: ck.CK_OBJECT_HANDLE = 0;
    try check("C_GenerateKeyPair(RSA)", f.C_GenerateKeyPair.?(h, &rsa_kpgen, &rsapub_tmpl, rsapub_tmpl.len, &rsapriv_tmpl, rsapriv_tmpl.len, &h_rsapub, &h_rsapriv));

    var rsa_sha_pkcs = ck.CK_MECHANISM{ .mechanism = ck.CKM_SHA256_RSA_PKCS, .pParameter = null, .ulParameterLen = 0 };
    var rsamsg = "sign me over RSA PKCS#1 v1.5".*;
    var rsasig: [256]u8 = undefined;
    var rsasiglen: ck.CK_ULONG = rsasig.len;
    try check("C_SignInit(RSA)", f.C_SignInit.?(h, &rsa_sha_pkcs, h_rsapriv));
    try check("C_Sign(RSA)", f.C_Sign.?(h, &rsamsg, rsamsg.len, &rsasig, &rsasiglen));
    if (rsasiglen != 256) return error.RsaSigLenWrong;
    try check("C_VerifyInit(RSA)", f.C_VerifyInit.?(h, &rsa_sha_pkcs, h_rsapub));
    try check("C_Verify(RSA)", f.C_Verify.?(h, &rsamsg, rsamsg.len, &rsasig, rsasiglen));
    try check("C_VerifyInit(RSA tamper)", f.C_VerifyInit.?(h, &rsa_sha_pkcs, h_rsapub));
    rsasig[10] ^= 0xff;
    if (f.C_Verify.?(h, &rsamsg, rsamsg.len, &rsasig, rsasiglen) != ck.CKR_SIGNATURE_INVALID) return error.RsaTamperNotDetected;

    var rsa_pkcs = ck.CK_MECHANISM{ .mechanism = ck.CKM_RSA_PKCS, .pParameter = null, .ulParameterLen = 0 };
    var rsapt = "rsa secret".*;
    var rsact: [256]u8 = undefined;
    var rsactlen: ck.CK_ULONG = rsact.len;
    try check("C_EncryptInit(RSA)", f.C_EncryptInit.?(h, &rsa_pkcs, h_rsapub));
    try check("C_Encrypt(RSA)", f.C_Encrypt.?(h, &rsapt, rsapt.len, &rsact, &rsactlen));
    if (rsactlen != 256) return error.RsaCtLenWrong;
    var rsaback: [256]u8 = undefined;
    var rsabacklen: ck.CK_ULONG = rsaback.len;
    try check("C_DecryptInit(RSA)", f.C_DecryptInit.?(h, &rsa_pkcs, h_rsapriv));
    try check("C_Decrypt(RSA)", f.C_Decrypt.?(h, &rsact, rsactlen, &rsaback, &rsabacklen));
    if (rsabacklen != rsapt.len or !std.mem.eql(u8, rsaback[0..rsabacklen], &rsapt)) return error.RsaRoundTripFailed;

    var rsaval_q = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_PRIVATE_EXPONENT, .pValue = null, .ulValueLen = 0 },
    };
    if (f.C_GetAttributeValue.?(h, h_rsapriv, &rsaval_q, rsaval_q.len) != ck.CKR_ATTRIBUTE_SENSITIVE) return error.RsaPrivNotSensitive;

    var ecdh_kpgen = ck.CK_MECHANISM{ .mechanism = ck.CKM_EC_KEY_PAIR_GEN, .pParameter = null, .ulParameterLen = 0 };
    var derive_pub_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_EC_PARAMS, .pValue = &ec_params, .ulValueLen = ec_params.len },
    };
    var derive_priv_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_DERIVE, .pValue = &ck_yes, .ulValueLen = 1 },
        .{ .type = ck.CKA_PRIVATE, .pValue = &ck_false, .ulValueLen = 1 },
    };
    var h_pubA: ck.CK_OBJECT_HANDLE = 0;
    var h_privA: ck.CK_OBJECT_HANDLE = 0;
    var h_pubB: ck.CK_OBJECT_HANDLE = 0;
    var h_privB: ck.CK_OBJECT_HANDLE = 0;
    try check("C_GenerateKeyPair(ECDH A)", f.C_GenerateKeyPair.?(h, &ecdh_kpgen, &derive_pub_tmpl, derive_pub_tmpl.len, &derive_priv_tmpl, derive_priv_tmpl.len, &h_pubA, &h_privA));
    try check("C_GenerateKeyPair(ECDH B)", f.C_GenerateKeyPair.?(h, &ecdh_kpgen, &derive_pub_tmpl, derive_pub_tmpl.len, &derive_priv_tmpl, derive_priv_tmpl.len, &h_pubB, &h_privB));

    var ptA: [67]u8 = undefined;
    var ptB: [67]u8 = undefined;
    var ptA_q = [_]ck.CK_ATTRIBUTE{.{ .type = ck.CKA_EC_POINT, .pValue = &ptA, .ulValueLen = ptA.len }};
    var ptB_q = [_]ck.CK_ATTRIBUTE{.{ .type = ck.CKA_EC_POINT, .pValue = &ptB, .ulValueLen = ptB.len }};
    try check("C_GetAttributeValue(EC_POINT A)", f.C_GetAttributeValue.?(h, h_pubA, &ptA_q, ptA_q.len));
    try check("C_GetAttributeValue(EC_POINT B)", f.C_GetAttributeValue.?(h, h_pubB, &ptB_q, ptB_q.len));

    var derive_value_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_CLASS, .pValue = &class_secret, .ulValueLen = @sizeOf(ck.CK_OBJECT_CLASS) },
        .{ .type = ck.CKA_KEY_TYPE, .pValue = &kt_generic, .ulValueLen = @sizeOf(ck.CK_KEY_TYPE) },
        .{ .type = ck.CKA_SENSITIVE, .pValue = &ck_false, .ulValueLen = 1 },
        .{ .type = ck.CKA_EXTRACTABLE, .pValue = &ck_yes, .ulValueLen = 1 },
    };
    const lenB: usize = @intCast(ptB_q[0].ulValueLen);
    const ptB_raw = ptB[2..lenB];
    var paramsA = ck.CK_ECDH1_DERIVE_PARAMS{ .kdf = ck.CKD_NULL, .ulSharedDataLen = 0, .pSharedData = null, .ulPublicDataLen = ptB_raw.len, .pPublicData = ptB_raw.ptr };
    var paramsB = ck.CK_ECDH1_DERIVE_PARAMS{ .kdf = ck.CKD_NULL, .ulSharedDataLen = 0, .pSharedData = null, .ulPublicDataLen = ptA_q[0].ulValueLen, .pPublicData = &ptA };
    var ecdh_mechA = ck.CK_MECHANISM{ .mechanism = ck.CKM_ECDH1_DERIVE, .pParameter = &paramsA, .ulParameterLen = @sizeOf(ck.CK_ECDH1_DERIVE_PARAMS) };
    var ecdh_mechB = ck.CK_MECHANISM{ .mechanism = ck.CKM_ECDH1_DERIVE, .pParameter = &paramsB, .ulParameterLen = @sizeOf(ck.CK_ECDH1_DERIVE_PARAMS) };
    var h_secretA: ck.CK_OBJECT_HANDLE = 0;
    var h_secretB: ck.CK_OBJECT_HANDLE = 0;
    try check("C_DeriveKey(A uses raw peer point)", f.C_DeriveKey.?(h, &ecdh_mechA, h_privA, &derive_value_tmpl, derive_value_tmpl.len, &h_secretA));
    try check("C_DeriveKey(B uses DER peer point)", f.C_DeriveKey.?(h, &ecdh_mechB, h_privB, &derive_value_tmpl, derive_value_tmpl.len, &h_secretB));

    var dvA: [48]u8 = undefined;
    var dvB: [48]u8 = undefined;
    var dvA_q = [_]ck.CK_ATTRIBUTE{.{ .type = ck.CKA_VALUE, .pValue = &dvA, .ulValueLen = dvA.len }};
    var dvB_q = [_]ck.CK_ATTRIBUTE{.{ .type = ck.CKA_VALUE, .pValue = &dvB, .ulValueLen = dvB.len }};
    try check("C_GetAttributeValue(derived A)", f.C_GetAttributeValue.?(h, h_secretA, &dvA_q, dvA_q.len));
    try check("C_GetAttributeValue(derived B)", f.C_GetAttributeValue.?(h, h_secretB, &dvB_q, dvB_q.len));
    if (dvA_q[0].ulValueLen != 32 or dvB_q[0].ulValueLen != 32) return error.DerivedLenWrong;
    if (!std.mem.eql(u8, dvA[0..32], dvB[0..32])) return error.EcdhDisagree;

    var kek_val: [32]u8 = undefined;
    for (0..32) |j| kek_val[j] = @intCast(0xA0 + j);
    var kek_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_CLASS, .pValue = &class_secret, .ulValueLen = @sizeOf(ck.CK_OBJECT_CLASS) },
        .{ .type = ck.CKA_KEY_TYPE, .pValue = &kt_aes, .ulValueLen = @sizeOf(ck.CK_KEY_TYPE) },
        .{ .type = ck.CKA_VALUE, .pValue = &kek_val, .ulValueLen = kek_val.len },
        .{ .type = ck.CKA_WRAP, .pValue = &ck_yes, .ulValueLen = 1 },
        .{ .type = ck.CKA_UNWRAP, .pValue = &ck_yes, .ulValueLen = 1 },
    };
    var h_kek: ck.CK_OBJECT_HANDLE = 0;
    try check("C_CreateObject(KEK)", f.C_CreateObject.?(h, &kek_tmpl, kek_tmpl.len, &h_kek));

    var target_val = "0123456789abcdef".*;
    var target_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_CLASS, .pValue = &class_secret, .ulValueLen = @sizeOf(ck.CK_OBJECT_CLASS) },
        .{ .type = ck.CKA_KEY_TYPE, .pValue = &kt_aes, .ulValueLen = @sizeOf(ck.CK_KEY_TYPE) },
        .{ .type = ck.CKA_VALUE, .pValue = &target_val, .ulValueLen = target_val.len },
        .{ .type = ck.CKA_EXTRACTABLE, .pValue = &ck_yes, .ulValueLen = 1 },
        .{ .type = ck.CKA_SENSITIVE, .pValue = &ck_false, .ulValueLen = 1 },
    };
    var h_target: ck.CK_OBJECT_HANDLE = 0;
    try check("C_CreateObject(wrap target)", f.C_CreateObject.?(h, &target_tmpl, target_tmpl.len, &h_target));

    var keywrap_mech = ck.CK_MECHANISM{ .mechanism = ck.CKM_AES_KEY_WRAP, .pParameter = null, .ulParameterLen = 0 };
    var wsize: ck.CK_ULONG = 0;
    try check("C_WrapKey(size)", f.C_WrapKey.?(h, &keywrap_mech, h_kek, h_target, null, &wsize));
    if (wsize != target_val.len + 8) return error.WrapSizeWrong;
    var wrapped: [64]u8 = undefined;
    var wrappedlen: ck.CK_ULONG = wrapped.len;
    try check("C_WrapKey", f.C_WrapKey.?(h, &keywrap_mech, h_kek, h_target, &wrapped, &wrappedlen));
    if (wrappedlen != target_val.len + 8) return error.WrapLenWrong;

    var unwrap_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_CLASS, .pValue = &class_secret, .ulValueLen = @sizeOf(ck.CK_OBJECT_CLASS) },
        .{ .type = ck.CKA_KEY_TYPE, .pValue = &kt_aes, .ulValueLen = @sizeOf(ck.CK_KEY_TYPE) },
        .{ .type = ck.CKA_EXTRACTABLE, .pValue = &ck_yes, .ulValueLen = 1 },
        .{ .type = ck.CKA_SENSITIVE, .pValue = &ck_false, .ulValueLen = 1 },
    };
    var h_unwrapped: ck.CK_OBJECT_HANDLE = 0;
    try check("C_UnwrapKey", f.C_UnwrapKey.?(h, &keywrap_mech, h_kek, &wrapped, wrappedlen, &unwrap_tmpl, unwrap_tmpl.len, &h_unwrapped));

    var uwval: [32]u8 = undefined;
    var uwval_q = [_]ck.CK_ATTRIBUTE{.{ .type = ck.CKA_VALUE, .pValue = &uwval, .ulValueLen = uwval.len }};
    try check("C_GetAttributeValue(unwrapped)", f.C_GetAttributeValue.?(h, h_unwrapped, &uwval_q, uwval_q.len));
    const uwlen: usize = @intCast(uwval_q[0].ulValueLen);
    if (uwlen != target_val.len or !std.mem.eql(u8, uwval[0..uwlen], &target_val)) return error.UnwrapMismatch;

    var wrapped2: [64]u8 = undefined;
    var wrapped2len: ck.CK_ULONG = wrapped2.len;
    if (f.C_WrapKey.?(h, &keywrap_mech, h_kek, h_gen, &wrapped2, &wrapped2len) != ck.CKR_KEY_UNEXTRACTABLE) return error.UnextractableWrapNotRejected;

    var oaep_params = ck.CK_RSA_PKCS_OAEP_PARAMS{ .hashAlg = ck.CKM_SHA256, .mgf = ck.CKG_MGF1_SHA256, .source = ck.CKZ_DATA_SPECIFIED, .pSourceData = null, .ulSourceDataLen = 0 };
    var oaep_wrap_mech = ck.CK_MECHANISM{ .mechanism = ck.CKM_RSA_PKCS_OAEP, .pParameter = &oaep_params, .ulParameterLen = @sizeOf(ck.CK_RSA_PKCS_OAEP_PARAMS) };
    var rsawrapped: [256]u8 = undefined;
    var rsawrappedlen: ck.CK_ULONG = rsawrapped.len;
    try check("C_WrapKey(RSA-OAEP)", f.C_WrapKey.?(h, &oaep_wrap_mech, h_rsapub, h_target, &rsawrapped, &rsawrappedlen));
    if (rsawrappedlen != 256) return error.RsaWrapLenWrong;
    var h_rsaunwrapped: ck.CK_OBJECT_HANDLE = 0;
    try check("C_UnwrapKey(RSA-OAEP)", f.C_UnwrapKey.?(h, &oaep_wrap_mech, h_rsapriv, &rsawrapped, rsawrappedlen, &unwrap_tmpl, unwrap_tmpl.len, &h_rsaunwrapped));
    var ruwval: [32]u8 = undefined;
    var ruwval_q = [_]ck.CK_ATTRIBUTE{.{ .type = ck.CKA_VALUE, .pValue = &ruwval, .ulValueLen = ruwval.len }};
    try check("C_GetAttributeValue(rsa-unwrapped)", f.C_GetAttributeValue.?(h, h_rsaunwrapped, &ruwval_q, ruwval_q.len));
    const ruwlen: usize = @intCast(ruwval_q[0].ulValueLen);
    if (ruwlen != target_val.len or !std.mem.eql(u8, ruwval[0..ruwlen], &target_val)) return error.RsaUnwrapMismatch;

    var dk_val = "digest-this-key!".*;
    var dk_tmpl = [_]ck.CK_ATTRIBUTE{
        .{ .type = ck.CKA_CLASS, .pValue = &class_secret, .ulValueLen = @sizeOf(ck.CK_OBJECT_CLASS) },
        .{ .type = ck.CKA_KEY_TYPE, .pValue = &kt_generic, .ulValueLen = @sizeOf(ck.CK_KEY_TYPE) },
        .{ .type = ck.CKA_VALUE, .pValue = &dk_val, .ulValueLen = dk_val.len },
    };
    var h_dk: ck.CK_OBJECT_HANDLE = 0;
    try check("C_CreateObject(digestkey)", f.C_CreateObject.?(h, &dk_tmpl, dk_tmpl.len, &h_dk));

    var dk_mech = ck.CK_MECHANISM{ .mechanism = ck.CKM_SHA256, .pParameter = null, .ulParameterLen = 0 };
    var dk_d1: [32]u8 = undefined;
    var dk_d1len: ck.CK_ULONG = dk_d1.len;
    try check("C_DigestInit(key)", f.C_DigestInit.?(h, &dk_mech));
    try check("C_DigestKey", f.C_DigestKey.?(h, h_dk));
    try check("C_DigestFinal(key)", f.C_DigestFinal.?(h, &dk_d1, &dk_d1len));

    var dk_d2: [32]u8 = undefined;
    var dk_d2len: ck.CK_ULONG = dk_d2.len;
    try check("C_DigestInit(value)", f.C_DigestInit.?(h, &dk_mech));
    try check("C_Digest(value)", f.C_Digest.?(h, &dk_val, dk_val.len, &dk_d2, &dk_d2len));
    if (dk_d1len != 32 or !std.mem.eql(u8, dk_d1[0..32], dk_d2[0..32])) return error.DigestKeyMismatch;

    var gcm_iv = [_]u8{ 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB };
    var gcm_aad = "gcm-associated-data".*;
    var gcm_params = ck.CK_GCM_PARAMS{
        .pIv = &gcm_iv,
        .ulIvLen = gcm_iv.len,
        .ulIvBits = 96,
        .pAAD = &gcm_aad,
        .ulAADLen = gcm_aad.len,
        .ulTagBits = 128,
    };
    var gcm_mech = ck.CK_MECHANISM{ .mechanism = ck.CKM_AES_GCM, .pParameter = &gcm_params, .ulParameterLen = @sizeOf(ck.CK_GCM_PARAMS) };
    var gcm_pt = "GCM streaming over multiple update calls exceeds one block".*;

    var gcm_ct1: [128]u8 = undefined;
    var gcm_ct1len: ck.CK_ULONG = gcm_ct1.len;
    try check("C_EncryptInit(GCM one-shot)", f.C_EncryptInit.?(h, &gcm_mech, h_aes));
    try check("C_Encrypt(GCM one-shot)", f.C_Encrypt.?(h, &gcm_pt, gcm_pt.len, &gcm_ct1, &gcm_ct1len));

    var gcm_ct2: [128]u8 = undefined;
    var part_out: [128]u8 = undefined;
    var part_outlen: ck.CK_ULONG = part_out.len;
    try check("C_EncryptInit(GCM stream)", f.C_EncryptInit.?(h, &gcm_mech, h_aes));
    var off: usize = 0;
    while (off < gcm_pt.len) {
        const end = @min(off + 17, gcm_pt.len);
        part_outlen = part_out.len;
        try check("C_EncryptUpdate(GCM)", f.C_EncryptUpdate.?(h, gcm_pt[off..].ptr, @intCast(end - off), &part_out, &part_outlen));
        if (part_outlen != 0) return error.GcmUpdateEmittedEarly;
        off = end;
    }
    var gcm_ct2len: ck.CK_ULONG = gcm_ct2.len;
    try check("C_EncryptFinal(GCM)", f.C_EncryptFinal.?(h, &gcm_ct2, &gcm_ct2len));
    if (gcm_ct1len != gcm_ct2len or !std.mem.eql(u8, gcm_ct1[0..gcm_ct1len], gcm_ct2[0..gcm_ct2len])) return error.GcmStreamMismatch;

    var gcm_back: [128]u8 = undefined;
    try check("C_DecryptInit(GCM stream)", f.C_DecryptInit.?(h, &gcm_mech, h_aes));
    off = 0;
    while (off < gcm_ct1len) {
        const end = @min(off + 19, gcm_ct1len);
        part_outlen = part_out.len;
        try check("C_DecryptUpdate(GCM)", f.C_DecryptUpdate.?(h, gcm_ct1[off..].ptr, @intCast(end - off), &part_out, &part_outlen));
        if (part_outlen != 0) return error.GcmDecryptEmittedEarly;
        off = end;
    }
    var gcm_backlen: ck.CK_ULONG = gcm_back.len;
    try check("C_DecryptFinal(GCM)", f.C_DecryptFinal.?(h, &gcm_back, &gcm_backlen));
    if (gcm_backlen != gcm_pt.len or !std.mem.eql(u8, gcm_back[0..gcm_backlen], &gcm_pt)) return error.GcmStreamRoundTripFailed;

    var gcm_bad: [128]u8 = undefined;
    @memcpy(gcm_bad[0..gcm_ct1len], gcm_ct1[0..gcm_ct1len]);
    gcm_bad[0] ^= 0xff;
    var gcm_badlen: ck.CK_ULONG = gcm_back.len;
    try check("C_DecryptInit(GCM tamper)", f.C_DecryptInit.?(h, &gcm_mech, h_aes));
    if (f.C_Decrypt.?(h, &gcm_bad, gcm_ct1len, &gcm_back, &gcm_badlen) != ck.CKR_ENCRYPTED_DATA_INVALID) return error.GcmTamperNotDetected;

    var de_sha = ck.CK_MECHANISM{ .mechanism = ck.CKM_SHA256, .pParameter = null, .ulParameterLen = 0 };
    var dual_pt = "dual-function plaintext spanning blocks".*;
    var de_iv = [_]u8{1} ** 16;
    var de_cbcpad = ck.CK_MECHANISM{ .mechanism = ck.CKM_AES_CBC_PAD, .pParameter = &de_iv, .ulParameterLen = de_iv.len };
    try check("C_DigestInit(DigestEncrypt)", f.C_DigestInit.?(h, &de_sha));
    try check("C_EncryptInit(DigestEncrypt)", f.C_EncryptInit.?(h, &de_cbcpad, h_aes));
    var de_ct: [80]u8 = undefined;
    var de_ctlen: usize = 0;
    off = 0;
    while (off < dual_pt.len) {
        const end = @min(off + 16, dual_pt.len);
        var seg: ck.CK_ULONG = @intCast(de_ct.len - de_ctlen);
        try check("C_DigestEncryptUpdate", f.C_DigestEncryptUpdate.?(h, dual_pt[off..].ptr, @intCast(end - off), de_ct[de_ctlen..].ptr, &seg));
        de_ctlen += @intCast(seg);
        off = end;
    }
    var de_finlen: ck.CK_ULONG = @intCast(de_ct.len - de_ctlen);
    try check("C_EncryptFinal(DigestEncrypt)", f.C_EncryptFinal.?(h, de_ct[de_ctlen..].ptr, &de_finlen));
    de_ctlen += @intCast(de_finlen);
    var de_dig: [32]u8 = undefined;
    var de_diglen: ck.CK_ULONG = de_dig.len;
    try check("C_DigestFinal(DigestEncrypt)", f.C_DigestFinal.?(h, &de_dig, &de_diglen));
    var de_ref: [32]u8 = undefined;
    var de_reflen: ck.CK_ULONG = de_ref.len;
    try check("C_DigestInit(DigestEncrypt ref)", f.C_DigestInit.?(h, &de_sha));
    try check("C_Digest(DigestEncrypt ref)", f.C_Digest.?(h, &dual_pt, dual_pt.len, &de_ref, &de_reflen));
    if (!std.mem.eql(u8, de_dig[0..32], de_ref[0..32])) return error.DualDigestMismatch;
    var de_back: [80]u8 = undefined;
    var de_backlen: ck.CK_ULONG = de_back.len;
    try check("C_DecryptInit(DigestEncrypt verify)", f.C_DecryptInit.?(h, &de_cbcpad, h_aes));
    try check("C_Decrypt(DigestEncrypt verify)", f.C_Decrypt.?(h, &de_ct, @intCast(de_ctlen), &de_back, &de_backlen));
    if (de_backlen != dual_pt.len or !std.mem.eql(u8, de_back[0..de_backlen], &dual_pt)) return error.DualEncryptRoundTrip;

    var dd_pt = "thirty-two-byte aligned message!".*;
    var dd_iv = [_]u8{2} ** 16;
    var dd_cbc = ck.CK_MECHANISM{ .mechanism = ck.CKM_AES_CBC, .pParameter = &dd_iv, .ulParameterLen = dd_iv.len };
    var dd_ct: [48]u8 = undefined;
    var dd_ctlen: ck.CK_ULONG = dd_ct.len;
    try check("C_EncryptInit(DecryptDigest setup)", f.C_EncryptInit.?(h, &dd_cbc, h_aes));
    try check("C_Encrypt(DecryptDigest setup)", f.C_Encrypt.?(h, &dd_pt, dd_pt.len, &dd_ct, &dd_ctlen));
    try check("C_DecryptInit(DecryptDigest)", f.C_DecryptInit.?(h, &dd_cbc, h_aes));
    try check("C_DigestInit(DecryptDigest)", f.C_DigestInit.?(h, &de_sha));
    var dd_back: [48]u8 = undefined;
    var dd_seg: ck.CK_ULONG = dd_back.len;
    try check("C_DecryptDigestUpdate", f.C_DecryptDigestUpdate.?(h, &dd_ct, dd_ctlen, &dd_back, &dd_seg));
    var dd_backlen: usize = @intCast(dd_seg);
    var dd_finlen: ck.CK_ULONG = @intCast(dd_back.len - dd_backlen);
    try check("C_DecryptFinal(DecryptDigest)", f.C_DecryptFinal.?(h, dd_back[dd_backlen..].ptr, &dd_finlen));
    dd_backlen += @intCast(dd_finlen);
    var dd_dig: [32]u8 = undefined;
    var dd_diglen: ck.CK_ULONG = dd_dig.len;
    try check("C_DigestFinal(DecryptDigest)", f.C_DigestFinal.?(h, &dd_dig, &dd_diglen));
    if (dd_backlen != dd_pt.len or !std.mem.eql(u8, dd_back[0..dd_backlen], &dd_pt)) return error.DualDecryptRoundTrip;
    var dd_ref: [32]u8 = undefined;
    var dd_reflen: ck.CK_ULONG = dd_ref.len;
    try check("C_DigestInit(DecryptDigest ref)", f.C_DigestInit.?(h, &de_sha));
    try check("C_Digest(DecryptDigest ref)", f.C_Digest.?(h, &dd_pt, dd_pt.len, &dd_ref, &dd_reflen));
    if (!std.mem.eql(u8, dd_dig[0..32], dd_ref[0..32])) return error.DualDecryptDigestMismatch;

    var sv_pt = "verify-after-decrypt aligned!!!!".*;
    var sv_iv = [_]u8{3} ** 16;
    var sv_cbc = ck.CK_MECHANISM{ .mechanism = ck.CKM_AES_CBC, .pParameter = &sv_iv, .ulParameterLen = sv_iv.len };
    try check("C_SignInit(SignEncrypt)", f.C_SignInit.?(h, &hmac_mech, h_hmac));
    try check("C_EncryptInit(SignEncrypt)", f.C_EncryptInit.?(h, &sv_cbc, h_aes));
    var sv_ct: [48]u8 = undefined;
    var sv_seg: ck.CK_ULONG = sv_ct.len;
    try check("C_SignEncryptUpdate", f.C_SignEncryptUpdate.?(h, &sv_pt, sv_pt.len, &sv_ct, &sv_seg));
    var sv_ctlen: usize = @intCast(sv_seg);
    var sv_finlen: ck.CK_ULONG = @intCast(sv_ct.len - sv_ctlen);
    try check("C_EncryptFinal(SignEncrypt)", f.C_EncryptFinal.?(h, sv_ct[sv_ctlen..].ptr, &sv_finlen));
    sv_ctlen += @intCast(sv_finlen);
    var sv_mac: [32]u8 = undefined;
    var sv_maclen: ck.CK_ULONG = sv_mac.len;
    try check("C_SignFinal(SignEncrypt)", f.C_SignFinal.?(h, &sv_mac, &sv_maclen));
    try check("C_DecryptInit(DecryptVerify)", f.C_DecryptInit.?(h, &sv_cbc, h_aes));
    try check("C_VerifyInit(DecryptVerify)", f.C_VerifyInit.?(h, &hmac_mech, h_hmac));
    var sv_back: [48]u8 = undefined;
    var sv_bseg: ck.CK_ULONG = sv_back.len;
    try check("C_DecryptVerifyUpdate", f.C_DecryptVerifyUpdate.?(h, sv_ct[0..sv_ctlen].ptr, @intCast(sv_ctlen), &sv_back, &sv_bseg));
    var sv_backlen: usize = @intCast(sv_bseg);
    var sv_bfinlen: ck.CK_ULONG = @intCast(sv_back.len - sv_backlen);
    try check("C_DecryptFinal(DecryptVerify)", f.C_DecryptFinal.?(h, sv_back[sv_backlen..].ptr, &sv_bfinlen));
    sv_backlen += @intCast(sv_bfinlen);
    try check("C_VerifyFinal(DecryptVerify)", f.C_VerifyFinal.?(h, &sv_mac, sv_maclen));
    if (sv_backlen != sv_pt.len or !std.mem.eql(u8, sv_back[0..sv_backlen], &sv_pt)) return error.DualSignVerifyRoundTrip;

    var rec_mech = ck.CK_MECHANISM{ .mechanism = ck.CKM_RSA_PKCS, .pParameter = null, .ulParameterLen = 0 };
    var rec_msg = "recover me via RSA".*;
    var rec_sig: [256]u8 = undefined;
    var rec_siglen: ck.CK_ULONG = rec_sig.len;
    try check("C_SignRecoverInit", f.C_SignRecoverInit.?(h, &rec_mech, h_rsapriv));
    try check("C_SignRecover", f.C_SignRecover.?(h, &rec_msg, rec_msg.len, &rec_sig, &rec_siglen));
    if (rec_siglen != 256) return error.SignRecoverLenWrong;
    var rec_out: [256]u8 = undefined;
    var rec_outlen: ck.CK_ULONG = rec_out.len;
    try check("C_VerifyRecoverInit", f.C_VerifyRecoverInit.?(h, &rec_mech, h_rsapub));
    try check("C_VerifyRecover", f.C_VerifyRecover.?(h, &rec_sig, rec_siglen, &rec_out, &rec_outlen));
    if (rec_outlen != rec_msg.len or !std.mem.eql(u8, rec_out[0..rec_outlen], &rec_msg)) return error.VerifyRecoverMismatch;

    var os_sha = ck.CK_MECHANISM{ .mechanism = ck.CKM_SHA256, .pParameter = null, .ulParameterLen = 0 };
    var os_p1 = "operation-".*;
    var os_p2 = "state".*;
    try check("C_DigestInit(opstate)", f.C_DigestInit.?(h, &os_sha));
    try check("C_DigestUpdate(opstate p1)", f.C_DigestUpdate.?(h, &os_p1, os_p1.len));
    var os_blob: [256]u8 = undefined;
    var os_bloblen: ck.CK_ULONG = 0;
    try check("C_GetOperationState(size)", f.C_GetOperationState.?(h, null, &os_bloblen));
    if (os_bloblen == 0 or os_bloblen > os_blob.len) return error.OpStateSizeWrong;
    try check("C_GetOperationState(fill)", f.C_GetOperationState.?(h, &os_blob, &os_bloblen));
    try check("C_DigestUpdate(opstate p2)", f.C_DigestUpdate.?(h, &os_p2, os_p2.len));
    var os_dA: [32]u8 = undefined;
    var os_dAlen: ck.CK_ULONG = os_dA.len;
    try check("C_DigestFinal(opstate A)", f.C_DigestFinal.?(h, &os_dA, &os_dAlen));
    try check("C_SetOperationState", f.C_SetOperationState.?(h, &os_blob, os_bloblen, ck.CK_INVALID_HANDLE, ck.CK_INVALID_HANDLE));
    try check("C_DigestUpdate(opstate p2 restored)", f.C_DigestUpdate.?(h, &os_p2, os_p2.len));
    var os_dB: [32]u8 = undefined;
    var os_dBlen: ck.CK_ULONG = os_dB.len;
    try check("C_DigestFinal(opstate B)", f.C_DigestFinal.?(h, &os_dB, &os_dBlen));
    if (!std.mem.eql(u8, os_dA[0..32], os_dB[0..32])) return error.OpStateRestoreMismatch;

    var slot_evt: ck.CK_SLOT_ID = 0;
    var reserved_probe: u8 = 0;
    const reserved_ptr: ?*anyopaque = &reserved_probe;
    if (f.C_WaitForSlotEvent.?(ck.CKF_DONT_BLOCK, &slot_evt, null) != ck.CKR_NO_EVENT) return error.WaitSlotEventNotNoEvent;
    if (f.C_WaitForSlotEvent.?(0, &slot_evt, null) != ck.CKR_FUNCTION_NOT_SUPPORTED) return error.WaitSlotEventBlockingNotRefused;
    if (f.C_WaitForSlotEvent.?(ck.CKF_DONT_BLOCK, &slot_evt, reserved_ptr) != ck.CKR_ARGUMENTS_BAD) return error.WaitSlotEventReservedNotChecked;
    if (f.C_GetFunctionStatus.?(h) != ck.CKR_FUNCTION_NOT_PARALLEL) return error.GetFunctionStatusNotParallel;
    if (f.C_CancelFunction.?(h) != ck.CKR_FUNCTION_NOT_PARALLEL) return error.CancelFunctionNotParallel;
    var seed_probe = "seed-material".*;
    if (f.C_SeedRandom.?(h, &seed_probe, seed_probe.len) != ck.CKR_RANDOM_SEED_NOT_SUPPORTED) return error.SeedRandomNotRefused;

    try check("C_CloseSession", f.C_CloseSession.?(h));
    try check("C_Finalize", f.C_Finalize.?(null));

    if (f.C_WaitForSlotEvent.?(ck.CKF_DONT_BLOCK, &slot_evt, null) != ck.CKR_CRYPTOKI_NOT_INITIALIZED) return error.WaitSlotEventUninitNotRejected;

    std.debug.print("smoke: OK\n", .{});
    std.debug.print("  cryptokiVersion = {d}.{d}\n", .{ info.cryptokiVersion.major, info.cryptokiVersion.minor });
    std.debug.print("  slots           = {d}\n", .{count});
    std.debug.print("  token label     = {s}\n", .{token_info.label});
    std.debug.print("  mechanisms      = {d}\n", .{mech_count});
    std.debug.print("  login + PIN     = init/login/initpin/setpin OK; lockout trips after 3 wrong\n", .{});
    std.debug.print("  objects         = create/find/get(2-call)/set/size/destroy OK; CKA_PRIVATE hidden after logout\n", .{});
    std.debug.print("  object gates    = CKA_DESTROYABLE/CKA_MODIFIABLE=false enforced; FindObjectsInit arg-check OK\n", .{});
    std.debug.print("  crypto          = SHA-256 vector OK; HMAC sign/verify (+tamper) OK; AES-CBC-PAD round-trip OK\n", .{});
    std.debug.print("  keygen          = C_GenerateKey AES OK; generated key CKA_VALUE is sensitive (unextractable)\n", .{});
    std.debug.print("  ecdsa           = C_GenerateKeyPair EC P-256 OK; ECDSA-SHA256 sign/verify (+tamper) OK; priv scalar sensitive\n", .{});
    std.debug.print("  rsa             = C_GenerateKeyPair RSA-2048 OK; SHA256-RSA-PKCS sign/verify (+tamper) + RSA-PKCS enc/dec OK; priv sensitive\n", .{});
    std.debug.print("  derive          = C_DeriveKey ECDH1 P-256: both parties agree (raw + DER-wrapped peer point)\n", .{});
    std.debug.print("  keywrap         = C_WrapKey/C_UnwrapKey AES-KEY-WRAP + RSA-OAEP round-trips; unextractable target refused\n", .{});
    std.debug.print("  digestkey       = C_DigestKey digest equals C_Digest of the same key bytes\n", .{});
    std.debug.print("  gcmstream       = AES-GCM multipart enc/dec == one-shot (chunked); tamper -> ENCRYPTED_DATA_INVALID\n", .{});
    std.debug.print("  dual            = DigestEncrypt/SignEncrypt + DecryptDigest/DecryptVerify lock-step round-trips\n", .{});
    std.debug.print("  recover         = RSA C_SignRecover -> C_VerifyRecover recovers the exact message\n", .{});
    std.debug.print("  opstate         = C_GetOperationState -> C_SetOperationState resumes the digest identically\n", .{});
    std.debug.print("  conformance     = WaitForSlotEvent(DONT_BLOCK)->NO_EVENT, blocking->NOT_SUPPORTED, pReserved->ARGS_BAD; Get/CancelFunction->NOT_PARALLEL; SeedRandom->SEED_NOT_SUPPORTED\n", .{});
}

fn check(name: []const u8, rv: ck.CK_RV) !void {
    if (rv != ck.CKR_OK) {
        std.debug.print("smoke: {s} -> 0x{X}\n", .{ name, rv });
        return error.CryptokiError;
    }
}
