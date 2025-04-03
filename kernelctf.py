import sys

# Komut çıktıları için gerçekçi senaryolar
def execute_command(command):
    global EXPLOIT_CODE, STACK_CANARY, LEAKED_LIBC_BASE
    output = ""

    if command == "hint":
        output = "İpucu: Buffer overflow var mı? Canary nasıl atlanır?"
    elif command == "gdb ./ana_stack":
        output = ("[*] GDB başlatıldı...\n"
                  "[*] Güvenlik mekanizmaları kontrol ediliyor...\n"
                  "[*] PIE: Açık | ASLR: Açık | NX: Açık | Stack Canary: Açık\n"
                  "[*] Buffer overflow için giriş noktası aranıyor...\n")
    elif command == "checksec --fortify-file=ana_stack":
        output = ("[*] Security Check: \n"
                  "    PIE: Enabled\n"
                  "    NX: Enabled\n"
                  "    Canary: Enabled\n"
                  "    Fortify Source: Disabled\n"
                  "    ASLR: Randomized")
    elif command == "strings ana_stack | grep FLAG":
        output = "[*] FLAG bulundu: CTF{buffer_overflow_solved}"
    elif command == "ltrace ./ana_stack":
        output = "[*] ltrace çıktısı:int value = 1205; printf(0x%x) yerinde Format String Bug bulundu"
    elif command == "format string":
        output = f"[*] Canary değeri tespit edildi: {STACK_CANARY}"
    elif command == "overflow test":
        output = "[*] Bellek taşması tespit edildi, ancak Canary engelliyor."
    elif command == "./ana_stack $(python -c 'print(%p * 10)')":
        output = f"[*] Libc base adresi: {LEAKED_LIBC_BASE}"
    elif command == "rop gadgets":
        output = "[*] ROP Gadget'lar bulundu: pop rdi; ret | system() | /bin/sh"
    elif command == "exploit":
        output = "[*] Exploit yazma alanı açılıyor..."
        print(output)
        print("[*] Exploit kodunu girin. Ctrl+D ile bitirin.")
        
        # Kullanıcıdan exploit kodu almak
        lines = []
        print("Çok satırlı exploit kodunu girin (Ctrl+D ile bitir):")
        
        try:
            while True:
                line = input("> ")
                lines.append(line)
        except EOFError:  # Ctrl+D ile bitirildiğinde EOFError fırlatılır
            exploit_input = "\n".join(lines)

            if not exploit_input.strip():
                output = "[!] Girdi boş."
                print(output)
                return

            EXPLOIT_CODE = exploit_input  # Exploit kodunu kaydet

            # Exploit kodunun içinde Canary ve Libc adresi olup olmadığını kontrol et
            if "0xdeadbeef" not in exploit_input or "0x12345678" not in exploit_input:
                output = "[!] Exploit başarıyla kaydedilemedi. Stack Canary veya Libc bilgisi eksik!"
            else:
                output = "[*] Exploit başarıyla kaydedildi!"
            print(output)
            return
    elif command == "cat /root/flag.txt":
        if "0xdeadbeef" not in EXPLOIT_CODE or "0x12345678" not in EXPLOIT_CODE:
            output = "root erişim gerekli"
        else:
            output = "flag:welcometorootforhacker"
    elif command == "whoami":
        if "0xdeadbeef" not in EXPLOIT_CODE or "0x12345678" not in EXPLOIT_CODE:
            output = "user"
        else:
            output = "root"
    elif command == "exit":
        exit()
    else:
        output = "Bilinmeyen komut."

    print(f"[ {command} Çıktısı ]")
    print(output)

def hacker_terminal():
    global STACK_CANARY, LEAKED_LIBC_BASE
    STACK_CANARY = "0xdeadbeef"  # Stack Canary örneği
    LEAKED_LIBC_BASE = "0x12345678"  # Libc base adresi örneği

    print("""
a	097	01100001	A	065	01000001
b	098	01100010	B	066	01000010
c	099	01100011	C	067	01000011
d	100	01100100	D	068	01000100
e	101	01100101	E	069	01000101
f	102	01100110	F	070	01000110
g	103	01100111	G	071	01000111    __   __  _______  _______  ___   _    _______  _______    _______  _______  _______  _______  ___   _ 
|  | |  ||   _   ||       ||   | | |  |       ||       |  |       ||       ||   _   ||       ||   | | |
|  |_|  ||  |_|  ||       ||   |_| |  |_     _||   _   |  |  _____||_     _||  |_|  ||       ||   |_| |
|       ||       ||       ||      _|    |   |  |  | |  |  | |_____   |   |  |       ||       ||      _|
|       ||       ||      _||     |_     |   |  |  |_|  |  |_____  |  |   |  |       ||      _||     |_ 
|   _   ||   _   ||     |_ |    _  |    |   |  |       |   _____| |  |   |  |   _   ||     |_ |    _  |
|__| |__||__| |__||_______||___| |_|    |___|  |_______|  |_______|  |___|  |__| |__||_______||___| |_|
h	104	01101000	H	072	01001000
i	105	01101001	I	073	01001001
j	106	01101010	J	074	01001010

CTF Terminal - Ana Stack
    """)

    while True:
        command = input("┌──(ctf@anastack)-[~]\n└─$ ").strip().lower()
        execute_command(command)

if __name__ == "__main__":
    hacker_terminal()

