; https://github.com/x86ptr/apiresolver

.386
.model flat, stdcall

.data

.code
_GetModuleHandle PROC ModuleName:DWORD
    sub esp, 8h
    pushad
    ; calculates the length of the module string name
    push dword ptr ModuleName
    call _strlen
    mov dword ptr [ebp - 4h], eax
    ; computes BaseAddress of module
    push dword ptr [ebp + 8h]
    ASSUME FS:NOTHING
    mov eax, fs:[30h] ; PEB
    ASSUME FS:ERROR
    mov eax, dword ptr [eax + 0Ch] ; PEB_LDR_DATA
    mov eax, dword ptr [eax + 14h] ; LIST_ENTRY InMemoryOrderModuleList (process.exe)
    xor ecx, ecx
    push eax
    ; counts the number of loaded modules
    counter:
        mov edx, [eax + 10h]
        cmp edx, 0h
        jz find
        inc ecx
        mov eax, [eax]
        jmp counter 
    ; goes to compare and find module
    find:
        pop eax
        _loop:
            mov edi, dword ptr [ebp + 8h]
            lea esi, dword ptr [eax + 24h]
            mov esi, dword ptr [esi + 4h]
            push ecx
            mov ecx, dword ptr [ebp - 4h]
            dec ecx
            lowercase:
                ; converts uppercase letters to lowercase letters
                mov bl, 61h
                mov bh, 39h ; scapes ASCII numbers
                cmp bh, [esi]
                ja compare
                cmp bl, [esi]
                jna compare
                add byte ptr [esi], 20h
                compare:
                    ; compares the string with the name of the loaded module
                    cmpsb
                    jnz nextModule
                    cmp ecx, 1h
                    jz found
                    inc esi ; scapes unicode bytes
                    loop lowercase
            nextModule:
                mov eax, [eax]
                pop ecx
                loop _loop 
                jmp endproc
    found:
        pop ecx
    endproc:
        mov eax, dword ptr [eax + 10h] 
        cmp eax, 0h
        jz GetError
        jmp exit
    GetError:
        mov eax, 0FFFFFFFFh
    exit:
        add esp, 4h
        mov dword ptr [ebp - 8h], eax
        popad
        mov eax, dword ptr [ebp - 8h]
        ret 4h
_GetModuleHandle ENDP

_GetProcAddress PROC hModule:DWORD, ProcName:DWORD
    sub esp, 1Ch
    pushad
    ; calculates the length of the API name
    push dword ptr [ebp + 0Ch]
    call _strlen
    mov dword ptr [ebp - 4h], eax
    mov eax, dword ptr [ebp + 8h] 
    ; Export directory
    mov eax, dword ptr [eax + 3Ch] ; e_lfanew
    add eax, dword ptr [ebp + 8h]  ; PE signature
    mov eax, dword ptr [eax + 78h] ; RVA of Export directory
    add eax, dword ptr [ebp + 8h]  ; Address of Export directory
    mov dword ptr [ebp - 8h], eax  ; Stores address of Export directory into stack 
    ; NumberOfFunctions
    mov eax, dword ptr [eax + 14h] ;    
    mov dword ptr [ebp - 0Ch], eax
    ; AddressOfFunctions
    mov eax, dword ptr [ebp - 8h] ; VA of Export directory    
    mov eax, dword ptr [eax + 1Ch] 
    add eax, dword ptr [ebp + 8h] ; adds with BaseAddress
    mov dword ptr [ebp - 10h], eax    
    ; AddressOfNames
    mov eax, dword ptr [ebp - 8h] 
    mov eax, dword ptr [eax + 20h]
    add eax, dword ptr [ebp + 8h]    
    mov dword ptr [ebp - 14h], eax 
    ; AddressOfNameOrdinals
    mov eax, dword ptr [ebp - 8h]    
    mov eax, dword ptr [eax + 24h]         
    add eax, dword ptr [ebp + 8h]
    mov dword ptr [ebp - 18h], eax 
    ; Find VA of API
    mov ecx, dword ptr [ebp - 0Ch] ; loop counter (number of functions)
    xor eax, eax
    xor edx, edx
    mov ebx, 4h
    compareNames:
        ; at each run it loads the address of each API into the names table in the ESI register
        mov esi, dword ptr [ebp - 14h]
        add esi, eax
        mov esi, dword ptr [esi]
        add esi, dword ptr [ebp + 8h]
        ; loads the address of the target API name into the EDI register
        mov edi, dword ptr [ebp + 0Ch]
        mov dword ptr [ebp - 0Ch], ecx
        mov ecx, dword ptr [ebp - 4h] ; length of module string name
        repe cmpsb ; compare ESI and EDI
        jz endproc ; jump is taken if (found or not found)
        mov ecx, dword ptr [ebp - 0Ch]
        add eax, 4h
        loop compareNames
    endproc:
        mov ecx, dword ptr [ebp - 0Ch]
        cmp ecx, 1h ; if the API name is not found, it will throw an error
        jz GetError
        div ebx
        ; find API name ordinal position
        mov edx, dword ptr [ebp - 18h]   ; AddressOfNameOrdinals
        mov cx, word ptr [edx + eax * 2] ; NameOrdinal position
        ; find VA of API
        mov edx, dword ptr [ebp - 10h]     ; AddressOfFunctions
        mov edx, dword ptr [edx + ecx * 4] ; RVA of API
        add edx, dword ptr [ebp + 8h]      ; VA of API
        mov eax, edx
        jmp exit
        GetError:
            mov eax, 0FFFFFFFFh
        exit:
            mov dword ptr [ebp - 1Ch], eax
            popad
            mov eax, dword ptr [ebp - 1Ch]
            ret 8

_GetProcAddress ENDP

_strlen PROC string:DWORD
    sub esp, 4
    pushad
    cld
    mov edi, string
    xor ecx, ecx
    mov ecx, 0FFFFFFFFh
    mov al, 0h
    repne scasb
    mov eax, string
    sub edi, eax
    xchg eax, edi
    mov dword ptr [ebp - 4], eax
    popad
    mov eax, dword ptr [ebp - 4]
    ret
_strlen ENDP

END
