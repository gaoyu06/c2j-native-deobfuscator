// x86-64 ELF fixture for generic-first JNI method discovery: the
// shared-dispatch registration family (a second obfuscator shape, distinct
// from the per-class one-table registrar the other fixtures model).
//
// A single RegisterNatives call site (a shared initClass()-style dispatcher)
// is reached by two branches. Each branch builds its OWN JNINativeMethod[] on
// the stack and sets its OWN nMethods immediate, so one call site registers two
// classes with different method counts (2 and 3). The generic harvest
// (harvest_strategy="auto") must recover BOTH branches from the shared site
// rather than collapsing them into a single silent bind.
//
// This is hand-written assembly on purpose. A stack-built shared dispatcher's
// exact instruction shape is not stable across C compilers or optimisation
// levels (PIC function-pointer materialisation goes through the GOT, stores get
// vectorised, and one if/else branch is laid out AFTER the merged call, out of
// the back-scan window). Assembling a fixed sequence keeps the committed binary
// a faithful, reproducible model of the shared-dispatch shape: both branches
// precede the shared call, each fnPtr is reached with a direct `lea` + stack
// store, and each branch's nMethods is a `mov $imm, %ecx` boundary.
//
// The five method implementations are exported with PROTECTED visibility: they
// stay in the dynamic symbol table (so the test can cross-check each recovered
// fnAddr against its export address) while remaining non-preemptible, which
// lets the linker resolve the `lea fixture_x(%rip)` references locally instead
// of routing them through the GOT. Only initClass/bootstrap carry Java_* names
// (the dispatcher's own exports); the per-method natives are registered through
// the tables, exactly as a shared dispatcher does.
//
// Built by fixtures/build.sh with the host cc/gcc. The committed
// libjni_dispatch_shared.so lets the pytest suite run with no assembler step.

	.text

	.globl	fixture_alpha
	.protected fixture_alpha
	.type	fixture_alpha, @function
fixture_alpha:
	endbr64
	xor	%eax, %eax
	ret
	.size	fixture_alpha, .-fixture_alpha

	.globl	fixture_beta
	.protected fixture_beta
	.type	fixture_beta, @function
fixture_beta:
	endbr64
	lea	1(%rdx), %eax
	ret
	.size	fixture_beta, .-fixture_beta

	.globl	fixture_gamma
	.protected fixture_gamma
	.type	fixture_gamma, @function
fixture_gamma:
	endbr64
	xor	%eax, %eax
	ret
	.size	fixture_gamma, .-fixture_gamma

	.globl	fixture_delta
	.protected fixture_delta
	.type	fixture_delta, @function
fixture_delta:
	endbr64
	lea	2(%rdx), %eax
	ret
	.size	fixture_delta, .-fixture_delta

	.globl	fixture_epsilon
	.protected fixture_epsilon
	.type	fixture_epsilon, @function
fixture_epsilon:
	endbr64
	lea	3(%rdx), %rax
	ret
	.size	fixture_epsilon, .-fixture_epsilon

	// int Java_com_example_Boot_initClass(JNIEnv *env, jclass clazz, int id)
	// rdi=env, rsi=clazz, edx=id. One RegisterNatives call site, two branches;
	// each builds its own stack JNINativeMethod[] and sets its own nMethods.
	.globl	Java_com_example_Boot_initClass
	.type	Java_com_example_Boot_initClass, @function
Java_com_example_Boot_initClass:
	endbr64
	sub	$0x58, %rsp
	test	%edx, %edx
	jne	.Lbranch1
.Lbranch0:                              // class A: {alpha, beta}, nMethods = 2
	lea	.Lname_alpha(%rip), %rax
	mov	%rax, 0x00(%rsp)
	lea	.Lsig_void(%rip), %rax
	mov	%rax, 0x08(%rsp)
	lea	fixture_alpha(%rip), %rax
	mov	%rax, 0x10(%rsp)
	lea	.Lname_beta(%rip), %rax
	mov	%rax, 0x18(%rsp)
	lea	.Lsig_ii(%rip), %rax
	mov	%rax, 0x20(%rsp)
	lea	fixture_beta(%rip), %rax
	mov	%rax, 0x28(%rsp)
	mov	$2, %ecx
	lea	(%rsp), %rdx
	jmp	.Lcall
.Lbranch1:                              // class B: {gamma, delta, epsilon}, nMethods = 3
	lea	.Lname_gamma(%rip), %rax
	mov	%rax, 0x00(%rsp)
	lea	.Lsig_void(%rip), %rax
	mov	%rax, 0x08(%rsp)
	lea	fixture_gamma(%rip), %rax
	mov	%rax, 0x10(%rsp)
	lea	.Lname_delta(%rip), %rax
	mov	%rax, 0x18(%rsp)
	lea	.Lsig_ii(%rip), %rax
	mov	%rax, 0x20(%rsp)
	lea	fixture_delta(%rip), %rax
	mov	%rax, 0x28(%rsp)
	lea	.Lname_epsilon(%rip), %rax
	mov	%rax, 0x30(%rsp)
	lea	.Lsig_jj(%rip), %rax
	mov	%rax, 0x38(%rsp)
	lea	fixture_epsilon(%rip), %rax
	mov	%rax, 0x40(%rsp)
	mov	$3, %ecx
	lea	(%rsp), %rdx
.Lcall:
	mov	(%rdi), %rax                    // env vtable
	call	*0x6b8(%rax)                   // (*env)->RegisterNatives (215 * 8 = 0x6b8)
	add	$0x58, %rsp
	ret
	.size	Java_com_example_Boot_initClass, .-Java_com_example_Boot_initClass

	// int Java_com_example_Boot_bootstrap(JNIEnv *env, jclass clazz)
	// Registers both classes through the shared dispatcher above.
	.globl	Java_com_example_Boot_bootstrap
	.type	Java_com_example_Boot_bootstrap, @function
Java_com_example_Boot_bootstrap:
	endbr64
	sub	$8, %rsp
	xor	%edx, %edx
	call	Java_com_example_Boot_initClass
	mov	$1, %edx
	call	Java_com_example_Boot_initClass
	add	$8, %rsp
	ret
	.size	Java_com_example_Boot_bootstrap, .-Java_com_example_Boot_bootstrap

	.section	.rodata
.Lname_alpha:	.string	"alpha"
.Lname_beta:	.string	"beta"
.Lname_gamma:	.string	"gamma"
.Lname_delta:	.string	"delta"
.Lname_epsilon:	.string	"epsilon"
.Lsig_void:	.string	"()V"
.Lsig_ii:	.string	"(I)I"
.Lsig_jj:	.string	"(J)J"

	.section	.note.GNU-stack, "", @progbits
