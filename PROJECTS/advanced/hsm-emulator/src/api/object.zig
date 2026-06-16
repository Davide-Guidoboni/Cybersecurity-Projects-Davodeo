// ©AngelaMos | 2026
// object.zig

const std = @import("std");
const ck = @import("../ck.zig");
const config = @import("../config.zig");
const state = @import("../core/state.zig");
const session = @import("../core/session.zig");
const object_store = @import("../core/object_store.zig");

const Object = object_store.Object;
const mapSetErr = object_store.mapSetErr;

fn inputTemplate(p: ?[*]ck.CK_ATTRIBUTE, count: ck.CK_ULONG) []ck.CK_ATTRIBUTE {
    if (count == 0) return &.{};
    return (p orelse return &.{})[0..@intCast(count)];
}

fn attrBytes(a: ck.CK_ATTRIBUTE) []const u8 {
    const ptr = a.pValue orelse return &.{};
    return @as([*]const u8, @ptrCast(ptr))[0..@intCast(a.ulValueLen)];
}

fn ulongAttr(obj: *const Object, t: ck.CK_ATTRIBUTE_TYPE) ?ck.CK_ULONG {
    const v = obj.get(t) orelse return null;
    if (v.len != @sizeOf(ck.CK_ULONG)) return null;
    return std.mem.bytesToValue(ck.CK_ULONG, v[0..@sizeOf(ck.CK_ULONG)]);
}

const visible = object_store.visible;

fn matches(obj: *Object, template: []ck.CK_ATTRIBUTE) bool {
    for (template) |a| {
        const have = obj.get(a.type) orelse return false;
        if (!std.mem.eql(u8, have, attrBytes(a))) return false;
    }
    return true;
}

fn readOnlyAttr(t: ck.CK_ATTRIBUTE_TYPE) bool {
    return switch (t) {
        ck.CKA_CLASS,
        ck.CKA_TOKEN,
        ck.CKA_PRIVATE,
        ck.CKA_KEY_TYPE,
        ck.CKA_LOCAL,
        ck.CKA_KEY_GEN_MECHANISM,
        ck.CKA_ALWAYS_SENSITIVE,
        ck.CKA_NEVER_EXTRACTABLE,
        ck.CKA_MODULUS,
        ck.CKA_PUBLIC_EXPONENT,
        ck.CKA_PRIVATE_EXPONENT,
        ck.CKA_PRIME_1,
        ck.CKA_PRIME_2,
        ck.CKA_EXPONENT_1,
        ck.CKA_EXPONENT_2,
        ck.CKA_COEFFICIENT,
        ck.CKA_EC_PARAMS,
        ck.CKA_EC_POINT,
        => true,
        else => false,
    };
}

fn sensitiveProtected(obj: *const Object, t: ck.CK_ATTRIBUTE_TYPE) bool {
    const secret_material = switch (t) {
        ck.CKA_VALUE,
        ck.CKA_PRIVATE_EXPONENT,
        ck.CKA_PRIME_1,
        ck.CKA_PRIME_2,
        ck.CKA_EXPONENT_1,
        ck.CKA_EXPONENT_2,
        ck.CKA_COEFFICIENT,
        => true,
        else => false,
    };
    if (!secret_material) return false;
    if (!obj.has(t)) return false;
    if (obj.getBool(ck.CKA_SENSITIVE)) return true;
    return obj.has(ck.CKA_EXTRACTABLE) and !obj.getBool(ck.CKA_EXTRACTABLE);
}

pub fn materializeDefaults(obj: *Object, allocator: std.mem.Allocator, class: ck.CK_OBJECT_CLASS) !void {
    if (!obj.has(ck.CKA_TOKEN)) try obj.set(allocator, ck.CKA_TOKEN, &[_]u8{ck.CK_FALSE});
    if (!obj.has(ck.CKA_PRIVATE)) {
        const def: u8 = if (class == ck.CKO_PRIVATE_KEY) ck.CK_TRUE else ck.CK_FALSE;
        try obj.set(allocator, ck.CKA_PRIVATE, &[_]u8{def});
    }
    switch (class) {
        ck.CKO_PUBLIC_KEY => {
            const attrs = [_]ck.CK_ATTRIBUTE_TYPE{ ck.CKA_ENCRYPT, ck.CKA_VERIFY, ck.CKA_VERIFY_RECOVER, ck.CKA_WRAP, ck.CKA_DERIVE };
            for (attrs) |a| if (!obj.has(a)) try obj.set(allocator, a, &[_]u8{ck.CK_FALSE});
        },
        ck.CKO_PRIVATE_KEY => {
            const attrs = [_]ck.CK_ATTRIBUTE_TYPE{ ck.CKA_DECRYPT, ck.CKA_SIGN, ck.CKA_SIGN_RECOVER, ck.CKA_UNWRAP, ck.CKA_DERIVE, ck.CKA_ALWAYS_AUTHENTICATE };
            for (attrs) |a| if (!obj.has(a)) try obj.set(allocator, a, &[_]u8{ck.CK_FALSE});
        },
        ck.CKO_SECRET_KEY => {
            const attrs = [_]ck.CK_ATTRIBUTE_TYPE{ ck.CKA_ENCRYPT, ck.CKA_DECRYPT, ck.CKA_SIGN, ck.CKA_VERIFY, ck.CKA_WRAP, ck.CKA_UNWRAP, ck.CKA_DERIVE };
            for (attrs) |a| if (!obj.has(a)) try obj.set(allocator, a, &[_]u8{ck.CK_FALSE});
        },
        else => {},
    }
}

pub fn insertNew(inst: *state.Instance, sess: *session.Session, obj_in: Object, phObject: *ck.CK_OBJECT_HANDLE) ck.CK_RV {
    var obj = obj_in;
    const allocator = inst.allocator();
    const is_token = obj.isToken();
    if (is_token and (sess.flags & ck.CKF_RW_SESSION) == 0) {
        obj.deinit(allocator);
        return ck.CKR_SESSION_READ_ONLY;
    }
    if (obj.isPrivate() and inst.logged_in != ck.CKU_USER) {
        obj.deinit(allocator);
        return ck.CKR_USER_NOT_LOGGED_IN;
    }
    if (is_token and inst.mk == null and obj.hasSealable()) {
        obj.deinit(allocator);
        return ck.CKR_USER_NOT_LOGGED_IN;
    }
    const h = inst.objects.insert(obj) orelse {
        obj.deinit(allocator);
        return ck.CKR_DEVICE_MEMORY;
    };
    phObject.* = h;
    persistIfToken(inst, is_token);
    return ck.CKR_OK;
}

fn worse(cur: ck.CK_RV, new: ck.CK_RV) ck.CK_RV {
    if (cur == ck.CKR_OK) return new;
    if (cur == ck.CKR_ATTRIBUTE_SENSITIVE or new == ck.CKR_ATTRIBUTE_SENSITIVE) return ck.CKR_ATTRIBUTE_SENSITIVE;
    if (cur == ck.CKR_ATTRIBUTE_TYPE_INVALID or new == ck.CKR_ATTRIBUTE_TYPE_INVALID) return ck.CKR_ATTRIBUTE_TYPE_INVALID;
    return new;
}

fn persistIfToken(inst: *state.Instance, is_token: bool) void {
    if (is_token) object_store.save(inst.io(), inst.allocator(), &inst.objects, inst.mk) catch {};
}

pub fn C_CreateObject(hSession: ck.CK_SESSION_HANDLE, pTemplate: [*]ck.CK_ATTRIBUTE, ulCount: ck.CK_ULONG, phObject: *ck.CK_OBJECT_HANDLE) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();

    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    const allocator = inst.allocator();
    const template = inputTemplate(pTemplate, ulCount);

    var obj: Object = .{};
    var moved = false;
    defer if (!moved) obj.deinit(allocator);

    for (template) |a| {
        obj.set(allocator, a.type, attrBytes(a)) catch |e| return mapSetErr(e);
    }

    if (!obj.has(ck.CKA_CLASS)) return ck.CKR_TEMPLATE_INCOMPLETE;
    const class = ulongAttr(&obj, ck.CKA_CLASS) orelse return ck.CKR_ATTRIBUTE_VALUE_INVALID;
    materializeDefaults(&obj, allocator, class) catch |e| return mapSetErr(e);

    moved = true;
    return insertNew(inst, sess, obj, phObject);
}

pub fn C_CopyObject(hSession: ck.CK_SESSION_HANDLE, hObject: ck.CK_OBJECT_HANDLE, pTemplate: [*]ck.CK_ATTRIBUTE, ulCount: ck.CK_ULONG, phNewObject: *ck.CK_OBJECT_HANDLE) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();

    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    const src = inst.objects.getPtr(hObject) orelse return ck.CKR_OBJECT_HANDLE_INVALID;
    if (!visible(src, inst.logged_in)) return ck.CKR_OBJECT_HANDLE_INVALID;

    const allocator = inst.allocator();
    var obj = src.clone(allocator) catch |e| return mapSetErr(e);
    var inserted = false;
    defer if (!inserted) obj.deinit(allocator);

    const template = inputTemplate(pTemplate, ulCount);
    for (template) |a| {
        if (readOnlyAttr(a.type) and a.type != ck.CKA_TOKEN and a.type != ck.CKA_PRIVATE) return ck.CKR_ATTRIBUTE_READ_ONLY;
    }
    for (template) |a| {
        obj.set(allocator, a.type, attrBytes(a)) catch |e| return mapSetErr(e);
    }

    const is_token = obj.isToken();
    if (is_token and (sess.flags & ck.CKF_RW_SESSION) == 0) return ck.CKR_SESSION_READ_ONLY;
    if (obj.isPrivate() and inst.logged_in != ck.CKU_USER) return ck.CKR_USER_NOT_LOGGED_IN;

    const h = inst.objects.insert(obj) orelse return ck.CKR_DEVICE_MEMORY;
    inserted = true;
    phNewObject.* = h;
    persistIfToken(inst, is_token);
    return ck.CKR_OK;
}

pub fn C_DestroyObject(hSession: ck.CK_SESSION_HANDLE, hObject: ck.CK_OBJECT_HANDLE) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();

    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    const obj = inst.objects.getPtr(hObject) orelse return ck.CKR_OBJECT_HANDLE_INVALID;
    if (!visible(obj, inst.logged_in)) return ck.CKR_OBJECT_HANDLE_INVALID;

    const was_token = obj.isToken();
    if (was_token and (sess.flags & ck.CKF_RW_SESSION) == 0) return ck.CKR_SESSION_READ_ONLY;
    if (obj.has(ck.CKA_DESTROYABLE) and !obj.getBool(ck.CKA_DESTROYABLE)) return ck.CKR_ACTION_PROHIBITED;

    _ = inst.objects.destroy(inst.allocator(), hObject);
    persistIfToken(inst, was_token);
    return ck.CKR_OK;
}

pub fn C_GetObjectSize(hSession: ck.CK_SESSION_HANDLE, hObject: ck.CK_OBJECT_HANDLE, pulSize: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();

    _ = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    const obj = inst.objects.getPtr(hObject) orelse return ck.CKR_OBJECT_HANDLE_INVALID;
    if (!visible(obj, inst.logged_in)) return ck.CKR_OBJECT_HANDLE_INVALID;

    pulSize.* = obj.sizeBytes();
    return ck.CKR_OK;
}

pub fn C_GetAttributeValue(hSession: ck.CK_SESSION_HANDLE, hObject: ck.CK_OBJECT_HANDLE, pTemplate: [*]ck.CK_ATTRIBUTE, ulCount: ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();

    _ = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    const obj = inst.objects.getPtr(hObject) orelse return ck.CKR_OBJECT_HANDLE_INVALID;
    if (!visible(obj, inst.logged_in)) return ck.CKR_OBJECT_HANDLE_INVALID;

    const template = inputTemplate(pTemplate, ulCount);
    var rv: ck.CK_RV = ck.CKR_OK;
    for (template) |*a| {
        if (sensitiveProtected(obj, a.type)) {
            a.ulValueLen = ck.CK_UNAVAILABLE_INFORMATION;
            rv = worse(rv, ck.CKR_ATTRIBUTE_SENSITIVE);
            continue;
        }
        const val = obj.get(a.type) orelse {
            a.ulValueLen = ck.CK_UNAVAILABLE_INFORMATION;
            rv = worse(rv, ck.CKR_ATTRIBUTE_TYPE_INVALID);
            continue;
        };
        if (a.pValue) |ptr| {
            if (a.ulValueLen < val.len) {
                a.ulValueLen = ck.CK_UNAVAILABLE_INFORMATION;
                rv = worse(rv, ck.CKR_BUFFER_TOO_SMALL);
            } else {
                @memcpy(@as([*]u8, @ptrCast(ptr))[0..val.len], val);
                a.ulValueLen = @intCast(val.len);
            }
        } else {
            a.ulValueLen = @intCast(val.len);
        }
    }
    return rv;
}

pub fn C_SetAttributeValue(hSession: ck.CK_SESSION_HANDLE, hObject: ck.CK_OBJECT_HANDLE, pTemplate: [*]ck.CK_ATTRIBUTE, ulCount: ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();

    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    const obj = inst.objects.getPtr(hObject) orelse return ck.CKR_OBJECT_HANDLE_INVALID;
    if (!visible(obj, inst.logged_in)) return ck.CKR_OBJECT_HANDLE_INVALID;
    if (obj.isToken() and (sess.flags & ck.CKF_RW_SESSION) == 0) return ck.CKR_SESSION_READ_ONLY;
    if (obj.has(ck.CKA_MODIFIABLE) and !obj.getBool(ck.CKA_MODIFIABLE)) return ck.CKR_ACTION_PROHIBITED;

    const template = inputTemplate(pTemplate, ulCount);
    for (template) |a| {
        if (readOnlyAttr(a.type)) return ck.CKR_ATTRIBUTE_READ_ONLY;
    }

    const allocator = inst.allocator();
    var staged = obj.clone(allocator) catch |e| return mapSetErr(e);
    var swapped = false;
    defer if (!swapped) staged.deinit(allocator);
    for (template) |a| {
        staged.set(allocator, a.type, attrBytes(a)) catch |e| return mapSetErr(e);
    }
    obj.deinit(allocator);
    obj.* = staged;
    swapped = true;
    persistIfToken(inst, obj.isToken());
    return ck.CKR_OK;
}

pub fn C_FindObjectsInit(hSession: ck.CK_SESSION_HANDLE, pTemplate: ?[*]ck.CK_ATTRIBUTE, ulCount: ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();

    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.find.active) return ck.CKR_OPERATION_ACTIVE;
    if (pTemplate == null and ulCount != 0) return ck.CKR_ARGUMENTS_BAD;

    const template = inputTemplate(pTemplate, ulCount);
    sess.find.count = 0;
    sess.find.cursor = 0;
    for (&inst.objects.slots) |*slot| {
        if (slot.*) |*e| {
            if (!visible(&e.obj, inst.logged_in)) continue;
            if (matches(&e.obj, template)) {
                sess.find.matches[sess.find.count] = e.handle;
                sess.find.count += 1;
            }
        }
    }
    sess.find.active = true;
    return ck.CKR_OK;
}

pub fn C_FindObjects(hSession: ck.CK_SESSION_HANDLE, phObject: [*]ck.CK_OBJECT_HANDLE, ulMaxObjectCount: ck.CK_ULONG, pulObjectCount: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();

    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (!sess.find.active) return ck.CKR_OPERATION_NOT_INITIALIZED;

    const max: usize = @intCast(ulMaxObjectCount);
    var n: usize = 0;
    while (n < max and sess.find.cursor < sess.find.count) : (n += 1) {
        phObject[n] = sess.find.matches[sess.find.cursor];
        sess.find.cursor += 1;
    }
    pulObjectCount.* = @intCast(n);
    return ck.CKR_OK;
}

pub fn C_FindObjectsFinal(hSession: ck.CK_SESSION_HANDLE) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();

    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (!sess.find.active) return ck.CKR_OPERATION_NOT_INITIALIZED;
    sess.find.active = false;
    sess.find.count = 0;
    sess.find.cursor = 0;
    return ck.CKR_OK;
}
