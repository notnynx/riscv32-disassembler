#include<fcntl.h>
#include<unistd.h>
#define MAX 102400      // 100KiB
#define BITS 32         // arquitetura de 32 bits
#define BYTES_LEN 8     // tamanho de 1 byte em bits
#define SECTION_LEN 40  // tamanho de um section header


char registers_name[32][5] = {"zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", 
                              "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5", 
                              "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", 
                              "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"};


typedef struct ELFheader{
    unsigned int e_shoff,    // comeco da section header
                 e_shnum,    // num de secoes
                 e_shstrndx; // indice da secao com os nomes
} ELFheader;

typedef struct Section{
    unsigned int sh_offset, // endereco da secao
                 sh_size,   // tamanho da secao
                 sh_name,   // offset do nome
                 sh_addr,   // endereco na memoria
                 index;     // indice da secao
} Section;


typedef struct symbol {
    unsigned int st_name,  // offset do nome (uint_32 4 bytes)
                 st_value, // endereco (uint_32 4 bytes)
                 st_size,  // tamanho (uint_32 4 bytes)
                 st_info,  // localidade (1 byte) >>4=0 ->local
                           // st_other (1 byte)
                 st_shndx; // secao associada (uint16 2 bytes)
    
    char local; // indica se eh local ou nao
    int lenght;

} Symbol;

unsigned int pointerHack(int input){
    /* retorna o valor de um int de 32 bits
    considerando representacao sem sinal */

    unsigned int i = * (unsigned int *) &input; 
    return i;
}

int power(int a, int exp){
    // retorna a ^ exp
    if(exp == 0)
        return 1;
    return a * power(a, exp - 1);
}


void swapEndiannessBit(char bitStr[], int bytes, char base){
    /* troca o tipo de endianness de uma string de bits
     * com base da forma 2 ^ num
     * base = b -> binario
     * base = x -> hexadecimal
     * base = o -> octal
     */
    unsigned char temp;
    int i, j, k, w;
    int bytes_len;

    switch (base) {
        case 'b' : bytes_len = 8; break;
        case 'x' : bytes_len = 2; break;
        case 'o' : bytes_len = 3; break;
        default: bytes_len = 8;
    }

    for (i = 0; i < bytes / 2; i++){
        for (j = 0; j < bytes_len; j++){
            k = i*bytes_len + j;
            w = (bytes - i - 1) * bytes_len +j;

            temp = bitStr[k];
            bitStr[k] = bitStr[w];
            bitStr[w] = temp;
        }
        
    }
    
}

void swapEndiannessByte(unsigned char byteStr[], int bytes){
    /* Troca o endianness de uma string de bytes */
    int i, j;
    unsigned char temp;
    for (i = 0; i < bytes / 2; i++){
        j = bytes - 1 - i;
        temp = byteStr[i];
        byteStr[i] = byteStr[j];
        byteStr[j] = temp;
    }
}


int BytesToInt(unsigned char string[], int bytes){
    int i, number = 0;
    for (i = 0; i < bytes; i++){
       number += string[i] * power(2, BYTES_LEN * (bytes - 1 -i));
    }
    return number;

}

char intTochar(int num){
    if (num > 9 && num < 16) // digitos hexadecimais
        return num + 87;
    return num + 48;
}

void IntToStr(char str[], int value, int base, int len){
    unsigned int quotient;
    unsigned int remainder;
    int i = 0;

    for (quotient = value; quotient != 0; quotient /= base){
        remainder = quotient % base;
        str[len - 1 - i] = intTochar(remainder);
        i++;
    }

    // zero fill
    if (len - 2 - i != 0){
        for (int j = 0; j < len - i; j++)
            str[j] = '0';
    }

}


void sliceBytes(unsigned char slice[], unsigned char bytes[], int ini, int end){
    int i;
    for (i = 0; i < end - ini; i++)
        slice[i] = bytes[ini + i];
}

int getBytesVal(unsigned char binary[], int ini, int bytes){
    int end = ini + bytes;
    unsigned char target[bytes];
    sliceBytes(target, binary, ini, end);
    swapEndiannessByte(target, bytes);
    return BytesToInt(target, bytes);
}

ELFheader readELFheader(unsigned char binary[]){
    ELFheader header;
    header.e_shoff = getBytesVal(binary, 32, 4);
    header.e_shnum = getBytesVal(binary, 48, 2);
    header.e_shstrndx = getBytesVal(binary, 50, 2);
    return header;
}

unsigned int getShstrtabAddress(unsigned char binary[], ELFheader file_header){
    int start_index = file_header.e_shoff +  (SECTION_LEN * file_header.e_shstrndx);
    return pointerHack(getBytesVal(binary, start_index + 16, 4));
}


int copyStr(char original[], char target[], int start){
    int i; 
    for (i = start; original[i] != '\0'; i++)
        target[i - start] = original[i];
    target[i - start] = '\0';
    return (i - start) + 1; // len + 1
}

int strComp(char str0[], char str1[]){
    int i;
    for (i = 0; str0[i] != '\0'; i++){
        if (str0[i] != str1[i])
            return 0; // sao diferentes
    }
    if (str1[i] == '\0') // string termina juntas
        return 1; // sao iguais
    return 0; // tamanhos diferentes
}

int getNameIndex(unsigned char binary[], int index, int max_size, char section_name[]){
    int i = index, len = -1;
    char name[max_size];

    do {
        i+= copyStr( (char *) binary, name, i);
        len+=1;
        if (strComp(section_name, name))
            return len;
    } while (i < index + max_size);
    
    return -1; // ?????

}

void readSections(unsigned char binary[], ELFheader elf_header, Section sections[]){
    int start_index;

    for (int i = 0; i < elf_header.e_shnum; i++){ // itera pelas secoes
        start_index = elf_header.e_shoff +  (SECTION_LEN * i);
        sections[i].index = i;
        sections[i].sh_name = getBytesVal(binary, start_index, 4);
        sections[i].sh_addr = getBytesVal(binary, start_index + 12, 4);
        sections[i].sh_offset = getBytesVal(binary, start_index + 16, 4);
        sections[i].sh_size = getBytesVal(binary, start_index + 20, 4);

    }
    

}

void writeFrom(char num[], int len, int digits){
    for (int i = 0; i < len; i++){
        if (i > len - digits - 1)
            write(1, &num[i], 1);
    }
}

void writeNullString(char str[], int space){
    for (int i = 0; str[i] != '\0'; i++){
        write(1, &str[i], 1);
    }
    if (str[0] != '\0' && space)
        write(1, " ", 1);
}

void writeNum(char num[], int val, int base,  int digits, int len, int space){
        IntToStr(num, val, base, len);
        writeFrom(num , len , digits);
        if (space)
            write(1, " ", 1);
}

void writeImm(int imm, int base){
    int len = 32;
    char num[len];

    int first_digit = imm>>31;

    if (first_digit && base == 10){
        write(1, "-", 1);
        imm = (~imm)+1;
    }

    IntToStr(num, imm, base, len);

    if (base == 16)
        write(1, "0x", 2);

    int shouldPrint = 0;
    for (int i = 0; i < len; i++){
        if (num[i] != '0'){
            write(1, &num[i], 1);
            shouldPrint = 1;
            continue;
        }

        if (i == len - 1)
            shouldPrint = 1;

        if (shouldPrint)
            write(1, &num[i], 1);
    }



}

void splitWrite(char str[], int len){

    for (int i = 0; i < len; i++){
        write(1, &str[i], 1);
        if (i % 2 != 0)
            write(1, " ", 1);
    }

}

void writeName(unsigned char binary[], int offset, int start, int max_size, int space){
    char section_name[max_size];
    int i = start; // endereco da secao 0

    while (i < start + max_size) {
        if (i == start + offset){
            copyStr( (char *) binary, section_name, i);
            writeNullString(section_name, space);
            return;
        }

        i++;
    }
}

void writeFileInfo(char file_name[]){
    write(1, "\n", 1);
    for (int i = 0; file_name[i] != '\0'; i++)
        write(1, &file_name[i], 1);
    write(1, ": file format elf32-littleriscv\n", 32);
    write(1, "\n", 1);
}

void showHeaders(unsigned char binary[], Section sections[], int len, int shstrtAdd, int shstrtLen){
    // flag "-h"
    int lenght = 11;
    char num[lenght];
    write(1, "Sections:\n", 10);
    write(1, "Idx Name Size VMA\n", 18);

    for (int i = 0; i < len; i++){
        writeNum(num, sections[i].index, 10, 1, lenght, 1);
        writeName(binary, sections[i].sh_name, shstrtAdd, shstrtLen, 1);
        writeNum(num, sections[i].sh_size, 16, 8, lenght, 1);
        writeNum(num, sections[i].sh_addr, 16, 8, lenght, 1);
        write(1, "\n", 1);

    }

    write(1, "\n", 1);

}

void readSymTab(unsigned char binary[], int symtabAdd, Symbol symtab[], int len){
    for (int i = 0; i < len; i++){
        symtab[i].st_name = getBytesVal(binary, symtabAdd + 16*i, 4);
        symtab[i].st_value = getBytesVal(binary, symtabAdd + 16*i + 4, 4);
        symtab[i].st_size = getBytesVal(binary, symtabAdd + 16*i + 8, 4);
        symtab[i].st_info = getBytesVal(binary, symtabAdd + 16*i + 12, 1);
        symtab[i].st_shndx = getBytesVal(binary, symtabAdd + 16*i + 14, 2);

        if (symtab[i].st_info>>4 == 1)
            symtab[i].local = 'g';
        else if (symtab[i].st_info>>4 == 0)
            symtab[i].local = 'l';
    }
}

void showTable(unsigned char binary[], Symbol symtab[], int symLen, int strtabAdd, int strtabLen, 
               int shstrtabAdd, int shstrtabLen, Section sections[]){
    // flag "-t"
    write(1, "SYMBOL TABLE:\n", 14);
    char hex[8];
    for (int i = 0; i < symLen; i++){
        if (symtab[i].st_value != 0){
            writeNum(hex, symtab[i].st_value, 16, 8, 8, 1);

            write(1, &symtab[i].local, 1);
            write(1, " ", 1);

            if (symtab[i].st_shndx == 0xfff1) {
                write(1, "*ABS* ", 6);
            } else if (symtab[i].st_shndx == 0) {
                write(1, "*UND* ", 6);
            } else {
                writeName(binary, sections[symtab[i].st_shndx].sh_name, 
                          shstrtabAdd, shstrtabLen, 1);
            }

            writeNum(hex, symtab[i].st_size, 16, 8, 8, 1);

            writeName(binary, symtab[i].st_name, strtabAdd, strtabLen, 0);

            write(1, "\n", 1);

        } 
    } 

}

void sortByAddress(Symbol symtab[], int len){
    Symbol temp;
    for (int i = 0; i < len; i++){
        for (int j = i + 1; j < len; j++)
            if (symtab[i].st_value > symtab[j].st_value) { 
                temp = symtab[i];
                symtab[i] = symtab[j];
                symtab[j] = temp;
            }
    }

}

void getSymLen(Symbol ord_symtab[], int len, int roof){
    int i;
    for (i = 0; i < len - 1; i++){
       ord_symtab[i].lenght = ord_symtab[i + 1].st_value 
                              - ord_symtab[i].st_value;
    }
    ord_symtab[i].lenght = roof - ord_symtab[i].st_value;
}

void showInstructions(unsigned char binary[], Symbol sym){
    char hex[8];

    for (int i = sym.st_value; i < sym.st_value + sym.lenght; i+=4){
       writeNum(hex, i, 16, 5, 8, 0);
       write(1, ":\n", 2);

    }
}

void showSymbols(unsigned char binary[], Symbol ord_symtab[], int symLen, int pos,
                 int strtabAdd, int strtabLen){
    char hex[8];
    int num = 0;

    for (int i = 0; i < symLen; i++){
        if (ord_symtab[i].st_value == pos){
            num++;
            write(1, "\n", 1);
            writeNum(hex, pos, 16, 8, 8, 1);
            write(1, "<", 1);
            writeName(binary, ord_symtab[i].st_name, strtabAdd, strtabLen, 0);
            write(1, ">:", 2);
            break; 
        }
    }

    if (num == 1)
        write(1, "\n", 1);
}

void decodeRType(unsigned instruction_code){
    char instructions_name[8][5] = {"add", "sll", "slt", "sltu", "xor",
                                     "srl", "or", "and"};

    int rd = (instruction_code>>7) & 0b11111; // destination register
    int rs2 = (instruction_code>>20) & 0b11111;
    int rs1 = (instruction_code>>15) & 0b11111;
    int funct3 = (instruction_code>>12) & 0b111;
    int funct7 = (instruction_code>>25) & 0b1111111;

    if ((funct3 > 7 || funct3 < 0) ||  (funct7 != 0 && funct7 != 0b0100000)){
        write(1, "<unknonw>", 9);
        return;
    }

    if (funct7 != 0){ // add -> sub, srl -> sra
        copyStr("sub", instructions_name[0], 0);
        copyStr("sra", instructions_name[5], 0);
    }
    
    writeNullString(instructions_name[funct3], 1);
    writeNullString(registers_name[rd], 0);
    write(1, ", ", 2);
    writeNullString(registers_name[rs1], 0);
    write(1, ", ", 2);
    writeNullString(registers_name[rs2], 0);


}


void decodeSType(unsigned int instruction_code){
    char instructions_name[3][3] = {"sb", "sh", "sw"};

    int rs1 = (instruction_code>>15) & 0b11111;
    int rs2 = (instruction_code>>20) & 0b11111;
    int funct3 = (instruction_code>>12) & 0b111;
    int immediate_ini = (instruction_code>>7) & 0b11111;
    int immediate_middle = (instruction_code>>25)<<5;
    int first_digit = instruction_code>>31;
    int immediate_end = 0;

    if (funct3 > 2 || funct3 < 0){
        write(1, "<unknonw>", 9);
        return;
    }


    for (int i = 0; i < 20; i++){
        immediate_end+=first_digit<<(12+i);
    }

    int immediate = immediate_end + immediate_middle + immediate_ini;
    //immediate = ~(immediate) + 1;

    writeNullString(instructions_name[funct3], 1);
    writeNullString(registers_name[rs2], 0);
    write(1, ", ", 2);
    writeImm(immediate, 10);
    write(1, "(", 1);
    writeNullString(registers_name[rs1], 0);
    write(1, ")", 1);

}

void writeBJaddress(int adress, int immediate, int symLen, Symbol symtab[], 
                    unsigned char binary[], int strtabAdd, int strtabLen){
    for (int i = 0; i < symLen; i++){
        if (symtab[i].st_value == adress + immediate){
            write(1, "<", 1);
            writeName(binary, symtab[i].st_name, strtabAdd, strtabLen, 0);
            write(1, ">", 1);
            return;
        }
    }
}

void decodeBType(unsigned int instruction_code, int adress, int symLen, Symbol symtab[],
                 unsigned char binary[], int strtabAdd, int strtabLen){
    char instructions_name[8][5] = {"beq", "bne", "", "", "blt", "bge", "bltu", "bgeu"};

    int rs1 = (instruction_code>>15) & 0b11111;
    int rs2 = (instruction_code>>20) & 0b11111;
    int funct3 = (instruction_code>>12) & 0b111;

    if (funct3 == 2 || funct3 == 4 || funct3 > 7  || funct3 < 0 ){
        write(1, "<unknonw>", 9);
        return;
    }

    int first_digit = instruction_code>>31;
    int eight_digit = (instruction_code & 0b10000000)>>7;
    int lower_imm = (instruction_code>>8) & 0b1111 ; // 8 -11
    int higher_imm = (instruction_code<<1)>>26; //25 - 30

    int immediate_end = 0;
    for (int i = 0; i < 20; i++){
        immediate_end+=first_digit<<(12+i);
    }

    int immediate = immediate_end + (eight_digit<<11) + (higher_imm<<5) + (lower_imm<<1);

    
    writeNullString(instructions_name[funct3], 1);
    writeNullString(registers_name[rs1], 0);
    write(1, ", ", 2);
    writeNullString(registers_name[rs2], 0);
    write(1, ", ", 2);
    writeImm(immediate + adress, 16);
    write(1, " ", 1);

    writeBJaddress(adress, immediate, symLen, symtab, binary, strtabAdd, strtabLen);

}

void decodeUType(int instruction_code, char flag){
    char instructions_name[2][6] = {"lui", "auipc"};
    int rd = (instruction_code>>7) & 0b11111;
    int immediate = (instruction_code>>12);  //<<12;

    if (flag == 'U')
        writeNullString(instructions_name[0], 1);
    else if (flag == 'u')
        writeNullString(instructions_name[1], 1);

    writeNullString(registers_name[rd], 0);
    write(1, ", ", 2);
    writeImm(immediate, 10);

}

void decodeJType(unsigned int instruction_code, int address, int symLen, Symbol symtab[],
                 unsigned char binary[], int strtabAdd, int strtabLen ){
    char instruction_name[4] = "jal";
    int rd = (instruction_code>>7) & 0b11111;
    int weird_L = (instruction_code>>20)&0b1;
    int lower_immediate = (instruction_code<<1)>>22 & 0b1111111111;
    int midlle_imediate = (instruction_code>>12) & 0b11111111;
    int first_digit = instruction_code>>31;

    int immediate_end = 0;
    for (int i = 0; i < 12; i++){
        immediate_end+=first_digit<<(20+i);
    }

    int immediate = immediate_end + (midlle_imediate<<12) + (weird_L<<11) + (lower_immediate<<1);

    writeNullString(instruction_name, 1);
    writeNullString(registers_name[rd], 0);
    write(1, ", ", 2);

    writeImm(immediate + address , 16);
    write(1, " ", 1);

    writeBJaddress(address, immediate, symLen, symtab, binary, strtabAdd, strtabLen);

}

int getBit(int bin, int ind){
    return (bin>>ind)&0b1;
}

void writeFenceArgs(int imm, char io_str[]){
    for (int w = 0; w < 4; w++){
        if (getBit(imm, 3 - w)){
            write(1, &io_str[w], 1);
        }
    }  
}

void decodeIType(int instruction_code, int opcode){
    char sub_type;
    switch (opcode){
        case 0b1100111: sub_type = 'a'; break; // jalr
        case 0b0000011: sub_type = 'b'; break;
        case 0b0010011: sub_type = 'c'; break;
        case 0b0001111: sub_type = 'd'; break;
        case 0b1110011: sub_type = 'e'; break;
    }

    int rd = (instruction_code>>7) & 0b11111;
    int funct3 = (instruction_code>>12) & 0b111;
    int rs1 = (instruction_code>>15) & 0b11111;
    int high_imm = instruction_code>>20;
    int first_digit = instruction_code>>31;

    int immediate_end = 0;
    for (int i = 0; i < 12; i++){
        immediate_end+=first_digit<<(20+i);
    }

    int imm_i = immediate_end + high_imm;

    if (sub_type == 'a'){
        if (funct3 != 0) {
            write(1, "<unknown>", 9);
            return;
        }
        char nameA[5] = "jalr"; 
        writeNullString(nameA, 1);
        writeNullString(registers_name[rd], 0);
        write(1, ", ", 2);
        writeImm(high_imm, 10);
        write(1, "(", 1);
        writeNullString(registers_name[rs1], 0);
        write(1, ")", 1);

    } else if (sub_type == 'b'){
        if (funct3 == 3 || funct3 < 0 || funct3 > 5){
            write(1, "<unknown>", 9);
        }
        char namesB[6][4] = {"lb", "lh", "lw", "", "lbu", "lhu"};
        writeNullString(namesB[funct3], 1);
        writeNullString(registers_name[rd], 0);
        write(1, ", ", 2);
        writeImm(high_imm, 10);
        write(1, "(", 1);
        writeNullString(registers_name[rs1], 0);
        write(1, ")", 1);
    } else if (sub_type == 'c'){
        int funct7 = ((instruction_code>>25)&0b1111111);
        if ((funct3 == 5 && ( funct7 != 0 && funct7 != 0b0100000)) 
            || (funct3 == 1 && funct7  != 0) || (funct3 < 0 || funct3 > 7) ){
                write(1, "<unknown>", 9);
                return;
        }
        char namesC[8][6] = {"addi", "slli", "slti", "sltiu", "xori", "srli", "ori", "andi"};
        int second_digit = (instruction_code>>30) & 0b1;

        if (second_digit == 1)
            copyStr("srai", namesC[5], 0);

        writeNullString(namesC[funct3], 1);
        writeNullString(registers_name[rd], 0);
        write(1, ", ", 2);
        writeNullString(registers_name[rs1], 0);
        write(1, ", ", 2);
        writeImm(high_imm, 10);
    } else if (sub_type == 'd'){
        char namesD[2][8] = {"fence", "fence.i"};
        int pred = (imm_i>>4) & 0b1111;
        int succ = imm_i & 0b1111;
        
        char io_str[5] = "iorw";

        writeNullString(namesD[funct3], 0);

        if (funct3 == 0) { // fence
                write(1, " ", 1);

                writeFenceArgs(pred, io_str);
                write(1, ", ", 2);
                writeFenceArgs(succ, io_str);
           
        }
        
    } else if (sub_type == 'e'){
        char namesE[8][7] = {"ecall", "csrrw", "csrrs", "csrrc", "",
                             "csrrwi", "csrrsi", "csrrci"};
        int weird_bit = high_imm&0b1;

        if ( (((high_imm != 0 && high_imm != 1) || rs1 != 0 || rd != 0 )&& funct3 == 0)  || 
              (funct3 < 0) || (funct3 == 4) || (funct3 > 7)){
            write(1, "<unknown>", 9);
            return;
        }

        if (weird_bit == 1){
            copyStr("ebreak", namesE[0], 0);
        }

        if (funct3 == 0){
            writeNullString(namesE[0], 0);
        } else {
            writeNullString(namesE[funct3], 1);
            writeNullString(registers_name[rd], 0);
            write(1, ", ", 2);
            writeImm(high_imm, 10);
            write(1, ", ", 2);

            if (funct3 > 4){
                writeImm(rs1, 10);
            } else {
                writeNullString(registers_name[rs1], 0);
            }
        }

    }

}





void decodeInstruction(unsigned int instruction_code, int address, int symLen, Symbol symtab[],
                       unsigned char binary[], int strtabAdd, int strtabLen){
    
    int opcode = instruction_code & 0b1111111; // 32 bits
    char instruction_type;

    switch (opcode){
    case 0b0110011: instruction_type = 'R'; break;
    case 0b0100011: instruction_type = 'S'; break;
    case 0b1100011: instruction_type = 'B'; break;
    case 0b0110111: instruction_type = 'U'; break;
    case 0b0010111: instruction_type = 'u'; break;
    case 0b1101111: instruction_type = 'J'; break;
    case 0b1100111: instruction_type = 'I'; break;
    case 0b0000011: instruction_type = 'I'; break;
    case 0b0010011:instruction_type = 'I'; break;
    case 0b0001111:instruction_type = 'I'; break;
    case 0b1110011:instruction_type = 'I'; break;
    default: instruction_type = 'e'; break;
    }

    if (instruction_type == 'R')
        decodeRType(instruction_code);
    else if (instruction_type == 'S')
        decodeSType(instruction_code);
    else if (instruction_type == 'B')
        decodeBType(instruction_code, address, symLen, symtab,
                    binary, strtabAdd, strtabLen);
    else if (instruction_type == 'U' || instruction_type == 'u')
        decodeUType(instruction_code, instruction_type);
    else if (instruction_type == 'J')
        decodeJType(instruction_code, address, symLen, symtab,
                    binary, strtabAdd, strtabLen);
    else if (instruction_type == 'I')
        decodeIType(instruction_code, opcode);
    else // unknow
        write(1, "<unknown>", 9);

}




void disassemble(unsigned char binary[], Symbol symtab[], int symLen, int section_index, int section_len, int section_addr, int section_offset, int strtabAdd, int strtabLen){
    // flag "-d"
    char hex[8];

    write(1, "\nDisassembly of section .text:\n", 31);

    for (int i = 0; i < section_len; i+=4){
        showSymbols(binary, symtab, symLen, section_addr+i, strtabAdd, strtabLen);
        writeNum(hex, section_addr+ i, 16, 5, 8, 0);
        write(1, ": ", 2);
        unsigned int instruction_code = getBytesVal(binary, section_offset + i, 4);
        IntToStr(hex, instruction_code, 16, 8);
        swapEndiannessBit(hex, 4, 'x');
        splitWrite(hex, 8);
        
        decodeInstruction(instruction_code, section_addr + i, symLen, symtab,
                          binary, strtabAdd, strtabLen);
        
        write(1, "\n", 1);
    }


}


int main(int argc, char *argv[]){

    // breaks
    if (argc > 2){ // 3 args
        unsigned char file_content[MAX]; // 1 byte por posicao
        int file_descriptor = open(argv[2], O_RDONLY);
        read(file_descriptor, file_content, MAX);

        ELFheader elf_header = readELFheader(file_content);
        Section sections[elf_header.e_shnum];

        readSections(file_content, elf_header, sections);

        int shstrtabAdd = sections[elf_header.e_shstrndx].sh_offset,
            shstrtabLen = sections[elf_header.e_shstrndx].sh_size,
            symtabIndex = getNameIndex(file_content, shstrtabAdd, shstrtabLen, ".symtab"),
            strttabIndex = getNameIndex(file_content, shstrtabAdd, shstrtabLen, ".strtab"),
            textIndex = getNameIndex(file_content, shstrtabAdd, shstrtabLen, ".text"),
            textLen = sections[textIndex].sh_size,
            textAddr = sections[textIndex].sh_addr,
            textOffset = sections[textIndex].sh_offset,
            symtabAdd = sections[symtabIndex].sh_offset,
            strttabAdd = sections[strttabIndex].sh_offset,
            symNum = sections[symtabIndex].sh_size / 16,
            strttabLen = sections[strttabIndex].sh_size;

        Symbol symbols[symNum];

        readSymTab(file_content, symtabAdd, symbols, symNum); 

        writeFileInfo(argv[2]);

        if (strComp(argv[1],"-h")){
            showHeaders(file_content, sections, elf_header.e_shnum, 
                        shstrtabAdd, shstrtabLen);
        } else if (strComp(argv[1],"-t")){
            showTable(file_content, symbols, symNum, strttabAdd, strttabLen,  shstrtabAdd, 
                    shstrtabLen, sections);
        } else if (strComp(argv[1],"-d")){
            sortByAddress(symbols, symNum);
            getSymLen(symbols, symNum, elf_header.e_shoff);
            disassemble(file_content, symbols, symNum, textIndex, textLen, textAddr,
                            textOffset, strttabAdd, strttabLen);
        }

        close(file_descriptor);
    }
    return 0;
}
