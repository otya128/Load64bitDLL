#include "Load64bitDll.h"
/**
 *
 * WOW64Ext Library
 *
 * Copyright (c) 2014 ReWolf
 * http://blog.rewolf.pl/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#define EMIT(a) __asm __emit (a)

#define X64_Start_with_CS(_cs) \
    { \
    EMIT(0x6A) EMIT(_cs)                         /*  push   _cs             */ \
    EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)   /*  call   $+5             */ \
    EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(5)        /*  add    dword [esp], 5  */ \
    EMIT(0xCB)                                   /*  retf                   */ \
    }

#define X64_End_with_CS(_cs) \
    { \
    EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)                                 /*  call   $+5                   */ \
    EMIT(0xC7) EMIT(0x44) EMIT(0x24) EMIT(4) EMIT(_cs) EMIT(0) EMIT(0) EMIT(0) /*  mov    dword [rsp + 4], _cs  */ \
    EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(0xD)                                    /*  add    dword [rsp], 0xD      */ \
    EMIT(0xCB)                                                                 /*  retf                         */ \
    }

#define X64_Start() X64_Start_with_CS(0x33)
#define X64_End() X64_End_with_CS(0x23)

#define _RAX  0
#define _RCX  1
#define _RDX  2
#define _RBX  3
#define _RSP  4
#define _RBP  5
#define _RSI  6
#define _RDI  7
#define _R8   8
#define _R9   9
#define _R10 10
#define _R11 11
#define _R12 12
#define _R13 13
#define _R14 14
#define _R15 15

#define X64_Push(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x50 | ((r) & 7))
#define X64_Pop(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x58 | ((r) & 7))

#define REX_W EMIT(0x48) __asm


 //to fool M$ inline asm compiler I'm using 2 DWORDs instead of DWORD64
 //use of DWORD64 will generate wrong 'pop word ptr[]' and it will break stack
union reg64
{
    DWORD64 v;
    DWORD dw[2];
};
#pragma warning(push)
#pragma warning(disable : 4409)

//r14: stack pointer
//r13: ptr to state
#define STATE_OFF_ESP 0x48
#define XCHG_R14_RSP() EMIT(0x49) EMIT(0x87) EMIT (0xE6)
#define SAVE_R14(off) EMIT(0x45) EMIT(0x89) EMIT(0x75) EMIT(off) //mov dword ptr[r13 + off], r14d
#define MOV_R14_RSP() EMIT(0x4c) EMIT(0x8b) EMIT(0xf4)
#define RESTORE_RSP(off) EMIT(0x41) EMIT(0x8b) EMIT(0x65) EMIT(off) //mov esp, dword ptr[r13 + off]
#define SWITCH_X64_STACK 1
extern "C" __declspec(dllexport) DWORD64 __cdecl X64Call(DWORD64 func, int argC, const DWORD64 *args)
{

    reg64 _rcx = { (argC > 0) ? argC--, *args++ : 0 };
    reg64 _rdx = { (argC > 0) ? argC--, *args++ : 0 };
    reg64 _r8 = { (argC > 0) ? argC--, *args++ : 0 };
    reg64 _r9 = { (argC > 0) ? argC--, *args++ : 0 };
    reg64 _rax = { 0 };

    reg64 restArgs = { (DWORD64)&(*args++) };

    // conversion to QWORD for easier use in inline assembly
    reg64 _argC = { (DWORD64)argC };
    DWORD back_esp = 0;
    WORD back_fs = 0;

    __asm
    {
        ;// reset FS segment, to properly handle RFG
        mov    back_fs, fs;
        mov    eax, 0x2B;
        mov    fs, ax;

        ;// keep original esp in back_esp variable
        mov    back_esp, esp
            ;// align esp to 0x10, without aligned stack some syscalls may return errors !
        ;// (actually, for syscalls it is sufficient to align to 8, but SSE opcodes 
        ;// requires 0x10 alignment), it will be further adjusted according to the
        ;// number of arguments above 4
        and    esp, 0xFFFFFFF0;

        X64_Start();

#ifdef SWITCH_X64_STACK
        XCHG_R14_RSP();
        SAVE_R14(STATE_OFF_ESP);
#endif
        //----
        ;// below code is compiled as x86 inline asm, but it is executed as x64 code
        ;// that's why it need sometimes REX_W() macro, right column contains detailed
        ;// transcription how it will be interpreted by CPU

        ;// fill first four arguments
        REX_W mov    ecx, _rcx.dw[0];// mov     rcx, qword ptr [_rcx]
        REX_W mov    edx, _rdx.dw[0];// mov     rdx, qword ptr [_rdx]
        push   _r8.v;// push    qword ptr [_r8]
        X64_Pop(_R8); ;// pop     r8
        push   _r9.v;// push    qword ptr [_r9]
        X64_Pop(_R9); ;// pop     r9
        ;//
        REX_W mov    eax, _argC.dw[0];// mov     rax, qword ptr [_argC]
        ;// 
        ;// final stack adjustment, according to the    ;//
        ;// number of arguments above 4                 ;// 
        test   al, 1;// test    al, 1
        jnz    _no_adjust;// jnz     _no_adjust
        sub    esp, 8;// sub     rsp, 8
    _no_adjust:;//
        ;// 
        push   edi;// push    rdi
        REX_W mov    edi, restArgs.dw[0];// mov     rdi, qword ptr [restArgs]
        ;// 
        ;// put rest of arguments on the stack          ;// 
        REX_W test   eax, eax;// test    rax, rax
        jz     _ls_e;// je      _ls_e
        REX_W lea    edi, dword ptr[edi + 8 * eax - 8];// lea     rdi, [rdi + rax*8 - 8]
        ;// 
    _ls:;// 
        REX_W test   eax, eax;// test    rax, rax
        jz     _ls_e;// je      _ls_e
        push   dword ptr[edi];// push    qword ptr [rdi]
        REX_W sub    edi, 8;// sub     rdi, 8
        REX_W sub    eax, 1;// sub     rax, 1
        jmp    _ls;// jmp     _ls
    _ls_e:;// 
        ;// 
        ;// create stack space for spilling registers   ;// 
        REX_W sub    esp, 0x20;// sub     rsp, 20h
        ;// 
        call   func;// call    qword ptr [func]
        ;// 
        ;// cleanup stack                               ;// 
        REX_W mov    ecx, _argC.dw[0];// mov     rcx, qword ptr [_argC]
        REX_W lea    esp, dword ptr[esp + 8 * ecx + 0x20];// lea     rsp, [rsp + rcx*8 + 20h]
        ;// 
        pop    edi;// pop     rdi
        ;// 
// set return value                             ;// 
        REX_W mov    _rax.dw[0], eax;// mov     qword ptr [_rax], rax
#ifdef SWITCH_X64_STACK
        REX_W mov    eax, _argC.dw[0];
        test   al, 1;
        jnz    _no_adjust2;
        add    esp, 8;
    _no_adjust2:;
        //----
        MOV_R14_RSP();
        RESTORE_RSP(STATE_OFF_ESP);
#endif
        //----
        X64_End();

        mov    ax, ds;
        mov    ss, ax;
        mov    esp, back_esp;

        ;// restore FS segment
        mov    ax, back_fs;
        mov    fs, ax;
    }
    return _rax.v;
}
