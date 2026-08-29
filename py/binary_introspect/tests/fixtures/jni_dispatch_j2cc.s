// x86-64 PE (Microsoft x64 ABI) fixture for the NAMED `j2cc` profile detector
// plus its `shared_dispatch` harvest — the Windows sibling of the ELF
// shared-dispatch fixture (libjni_dispatch_shared.so).
//
// The ELF fixture proves the GENERIC `harvest_strategy="auto"` fallback picking
// up a shared dispatcher on a real binary. This PE fixture proves the other
// honest gap: the named `j2cc` profile detector (_detect_j2cc) firing on a REAL
// Windows image, after which `find_jni_method_tables` takes the
// `harvest_strategy="shared_dispatch"` path (which ALWAYS calls
// `_harvest_dispatch`, not the `auto` fallback).
//
// _detect_j2cc requires ALL of: PE format, <=4 Java_* exports, a Java_* name
// containing "initClass", a Java_* name containing "bootstrap", and (for a 0.9
// vs 0.6 score) a "Cannot invoke " literal in a mapped section. So exactly two
// Java_* exports are declared — Java_com_example_Boot_initClass and
// Java_com_example_Boot_bootstrap — and the five method bodies are exported
// under non-Java_* names (fixture_alpha … fixture_epsilon), exactly as a shared
// dispatcher registers its natives through tables rather than by export name.
//
// Microsoft x64 ABI: env in RCX, RegisterNatives gets methods* in R8 and
// nMethods in R9D. `_harvest_dispatch` treats every `mov <nMethods-reg>, imm`
// (here `mov $imm, %r9d`) as a branch boundary, records RIP-relative `lea`
// targets that land in executable ranges (the fnPtrs — the name/sig `lea`s hit
// .rdata and are ignored), and closes a branch on each stack store. BOTH
// branches are laid out BEFORE the single shared `call *0x6b8(%rax)`
// (RegisterNatives = JNI slot 215; 215*8 = 0x6b8), so the whole dispatcher sits
// inside the back-scan window.
//
// This is hand-written assembly on purpose. A C compiler will not preserve this
// shape (PIC function-pointer materialisation, vectorised stores, and one
// if/else branch laid out AFTER the merged call, out of the back-scan window),
// exactly as noted for the ELF sibling. Assembling a fixed sequence keeps the
// committed DLL a faithful, reproducible model: both branches precede the shared
// call, each fnPtr is reached with a direct `lea sym(%rip)` + stack store, and
// each branch's nMethods is a `mov $imm, %r9d` boundary.
//
// Exports are declared through a linker `.drectve` section so that exactly the
// intended symbols are exported (Java_* pair + fixture_* bodies) with no CRT
// noise, keeping the Java_* export count at 2 (<=4) for the detector. Built by
// fixtures/build.sh with x86_64-w64-mingw32-gcc; the committed
// jni_dispatch_j2cc.dll lets the pytest suite run with no cross toolchain.

	.text

	// Five native method bodies. Exported under fixture_* (NOT Java_*) names,
	// so they do not count toward the detector's Java_* budget; they are
	// registered through the stack tables the dispatcher builds. Distinct
	// bodies give distinct addresses so the recovered fnAddrs can be
	// cross-checked against the export table.
	.globl	fixture_alpha
fixture_alpha:
	xor	%eax, %eax
	ret

	.globl	fixture_beta
fixture_beta:
	lea	1(%rdx), %eax
	ret

	.globl	fixture_gamma
fixture_gamma:
	lea	2(%rdx), %eax
	ret

	.globl	fixture_delta
fixture_delta:
	lea	3(%rdx), %eax
	ret

	.globl	fixture_epsilon
fixture_epsilon:
	lea	4(%rdx), %rax
	ret

	// int Java_com_example_Boot_initClass(JNIEnv *env, jclass clazz, int id)
	// Microsoft x64: RCX=env, RDX=clazz, R8D=id. One RegisterNatives call
	// site, two branches; each builds its own stack JNINativeMethod[] and sets
	// its own nMethods in R9D.
	.globl	Java_com_example_Boot_initClass
Java_com_example_Boot_initClass:
	sub	$0x88, %rsp
	test	%r8d, %r8d
	jne	.Lbranch1
.Lbranch0:                              // class A: {alpha, beta}, nMethods = 2
	lea	.Lname_alpha(%rip), %rax
	mov	%rax, 0x20(%rsp)
	lea	.Lsig_void(%rip), %rax
	mov	%rax, 0x28(%rsp)
	lea	fixture_alpha(%rip), %rax
	mov	%rax, 0x30(%rsp)
	lea	.Lname_beta(%rip), %rax
	mov	%rax, 0x38(%rsp)
	lea	.Lsig_ii(%rip), %rax
	mov	%rax, 0x40(%rsp)
	lea	fixture_beta(%rip), %rax
	mov	%rax, 0x48(%rsp)
	mov	$2, %r9d
	lea	0x20(%rsp), %r8
	jmp	.Lcall
.Lbranch1:                              // class B: {gamma, delta, epsilon}, nMethods = 3
	lea	.Lname_gamma(%rip), %rax
	mov	%rax, 0x20(%rsp)
	lea	.Lsig_void(%rip), %rax
	mov	%rax, 0x28(%rsp)
	lea	fixture_gamma(%rip), %rax
	mov	%rax, 0x30(%rsp)
	lea	.Lname_delta(%rip), %rax
	mov	%rax, 0x38(%rsp)
	lea	.Lsig_ii(%rip), %rax
	mov	%rax, 0x40(%rsp)
	lea	fixture_delta(%rip), %rax
	mov	%rax, 0x48(%rsp)
	lea	.Lname_epsilon(%rip), %rax
	mov	%rax, 0x50(%rsp)
	lea	.Lsig_jj(%rip), %rax
	mov	%rax, 0x58(%rsp)
	lea	fixture_epsilon(%rip), %rax
	mov	%rax, 0x60(%rsp)
	mov	$3, %r9d
	lea	0x20(%rsp), %r8
.Lcall:
	// RCX = env on Windows; load the env vtable, then call slot 215 (215*8 = 0x6b8).
	mov	(%rcx), %rax
	call	*0x6b8(%rax)
	add	$0x88, %rsp
	ret

	// int Java_com_example_Boot_bootstrap(JNIEnv *env, jclass clazz)
	// Registers both classes through the shared dispatcher above: initClass
	// with id 0 then id 1. RDI/RSI are callee-saved on Windows x64, so env and
	// clazz survive the first call.
	.globl	Java_com_example_Boot_bootstrap
Java_com_example_Boot_bootstrap:
	push	%rsi
	push	%rdi
	sub	$0x28, %rsp
	// Save env (RCX) and clazz (RDX) in callee-saved registers, then call
	// initClass with id 0.
	mov	%rcx, %rsi
	mov	%rdx, %rdi
	xor	%r8d, %r8d
	call	Java_com_example_Boot_initClass
	// Second class: same env/clazz, id 1.
	mov	%rsi, %rcx
	mov	%rdi, %rdx
	mov	$1, %r8d
	call	Java_com_example_Boot_initClass
	add	$0x28, %rsp
	pop	%rdi
	pop	%rsi
	ret

	.section	.rdata,"dr"
.Lname_alpha:	.asciz	"alpha"
.Lname_beta:	.asciz	"beta"
.Lname_gamma:	.asciz	"gamma"
.Lname_delta:	.asciz	"delta"
.Lname_epsilon:	.asciz	"epsilon"
.Lsig_void:	.asciz	"()V"
.Lsig_ii:	.asciz	"(I)I"
.Lsig_jj:	.asciz	"(J)J"
	// A throw-reason literal the j2cc detector scores on (0.9 vs 0.6). Kept in a
	// mapped, non-executable section so it is not mistaken for a fnPtr target.
.Lmsg_cannot:	.asciz	"Cannot invoke com.example.Boot.method()"

	// Linker directives: export exactly the two Java_* dispatcher entry points
	// and the five fixture_* method bodies — nothing else.
	.section	.drectve
	.ascii	" -export:Java_com_example_Boot_initClass"
	.ascii	" -export:Java_com_example_Boot_bootstrap"
	.ascii	" -export:fixture_alpha"
	.ascii	" -export:fixture_beta"
	.ascii	" -export:fixture_gamma"
	.ascii	" -export:fixture_delta"
	.ascii	" -export:fixture_epsilon"
