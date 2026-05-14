#pragma once

#include <jni.h>
#include <jvmti.h>

namespace j2c::jni_hook {

// Save the original JNI function table for delegation. Called from VMInit.
void capture_original(JNIEnv* env);

// Build (once) and return our hooked function table.
const struct JNINativeInterface_* hooked_table();

// Install the hooked table into a thread's JNIEnv.
void install(JNIEnv* env);

// Per-thread reentrancy / native-frame depth — controls whether wrappers log.
void enter_native_frame();
void exit_native_frame();
bool in_native_frame();

// Suspend / resume emission while inside JDK-native methods invoked from
// within a user native frame (their JNI calls are noise from the
// reverse-engineering POV).
void enter_suppress_frame();
void exit_suppress_frame();

// Current method being entered (for "fn" field of enter/exit events).
void set_current_native_method(const char* sig);
const char* current_native_method();

} // namespace j2c::jni_hook
