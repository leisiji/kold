#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
// 假设的模块加载基地址
// 实际上内核会动态分配这个地址，这里为了演示设为 0xbf000000
#define MODULE_LOAD_BASE 0xbf000000
// ARM32 重定位类型定义
#define R_ARM_NONE     0
#define R_ARM_ABS32    2
#define R_ARM_REL32    3
#define R_ARM_THM_CALL 10
#ifndef R_ARM_THM_JUMP24
#define R_ARM_THM_JUMP24 30
#endif
// 辅助宏
// #define ELF32_R_SYM(info)  ((info) >> 8)
// #define ELF32_R_TYPE(info) ((uint8_t)(info))
/**
 * 查找指定名称的 Section Header
 */
static Elf32_Shdr *find_section_header(char *shstrtab, Elf32_Ehdr *ehdr, const char *name)
{
    Elf32_Shdr *shdrs = (Elf32_Shdr *)((char *)ehdr + ehdr->e_shoff);
    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *sec_name = shstrtab + shdrs[i].sh_name;
        if (strcmp(sec_name, name) == 0) {
            return &shdrs[i];
        }
    }
    return NULL;
}

#define __mem_to_opcode_thumb16(x) (x)
#define __opcode_to_mem_thumb16(x) (x)

#define u32 uint32_t
#define s32 int
#define u16 uint16_t

static int sign_extend32(uint32_t value, int index)
{
    uint8_t shift = 31 - index;
    return (int)(value << shift) >> shift;
}

static void relocate_thumb(Elf32_Ehdr *ehdr, Elf32_Shdr *dstsec, Elf32_Sym *sym, unsigned long loc)
{
    u32 upper, lower, sign, j1, j2;
    s32 offset;

    upper = __mem_to_opcode_thumb16(*(u16 *)loc);
    lower = __mem_to_opcode_thumb16(*(u16 *)(loc + 2));

    /*
     * 25 bit signed address range (Thumb-2 BL and B.W
     * instructions):
     *   S:I1:I2:imm10:imm11:0
     * where:
     *   S     = upper[10]   = offset[24]
     *   I1    = ~(J1 ^ S)   = offset[23]
     *   I2    = ~(J2 ^ S)   = offset[22]
     *   imm10 = upper[9:0]  = offset[21:12]
     *   imm11 = lower[10:0] = offset[11:1]
     *   J1    = lower[13]
     *   J2    = lower[11]
     */
    sign = (upper >> 10) & 1;
    j1 = (lower >> 13) & 1;
    j2 = (lower >> 11) & 1;
    offset = (sign << 24) | ((~(j1 ^ sign) & 1) << 23) | ((~(j2 ^ sign) & 1) << 22) |
             ((upper & 0x03ff) << 12) | ((lower & 0x07ff) << 1);
    offset = sign_extend32(offset, 24);

    uint32_t sym_addr = (uint32_t)(unsigned long long)ehdr + dstsec->sh_offset + sym->st_value;
    offset += sym_addr - loc;

    sign = (offset >> 24) & 1;
    j1 = sign ^ (~(offset >> 23) & 1);
    j2 = sign ^ (~(offset >> 22) & 1);
    upper = (u16)((upper & 0xf800) | (sign << 10) | ((offset >> 12) & 0x03ff));
    lower = (u16)((lower & 0xd000) | (j1 << 13) | (j2 << 11) | ((offset >> 1) & 0x07ff));

    *(u16 *)loc = __opcode_to_mem_thumb16(upper);
    *(u16 *)(loc + 2) = __opcode_to_mem_thumb16(lower);
}

/**
 * 执行静态重定位的核心函数
 */
void apply_relocations(Elf32_Ehdr *ehdr)
{
    Elf32_Shdr *shdrs = (Elf32_Shdr *)((char *)ehdr + ehdr->e_shoff);
    // 1. 获取 Section Header String Table
    Elf32_Shdr *shstrtab_sec = &shdrs[ehdr->e_shstrndx];
    char *shstrtab = (char *)ehdr + shstrtab_sec->sh_offset;
    // 2. 查找关键段
    Elf32_Shdr *text_sec = find_section_header(shstrtab, ehdr, ".text");
    Elf32_Shdr *rel_text_sec = find_section_header(shstrtab, ehdr, ".rel.text");
    Elf32_Shdr *symtab_sec = find_section_header(shstrtab, ehdr, ".symtab");
    Elf32_Shdr *strtab_sec = &shdrs[symtab_sec->sh_link];
    char *strtab = (char *)ehdr + strtab_sec->sh_offset;

    if (!rel_text_sec || !symtab_sec) {
        printf("Missing critical sections (.data, .rel.data, .symtab). Exiting.\n");
        return;
    }

    // 3. 准备指针
    // .rel.text 中的重定位项数组
    Elf32_Rel *rels = (Elf32_Rel *)((char *)ehdr + rel_text_sec->sh_offset);
    int rel_count = rel_text_sec->sh_size / sizeof(Elf32_Rel);
    // 符号表
    Elf32_Sym *symtab = (Elf32_Sym *)((char *)ehdr + symtab_sec->sh_offset);
    printf("Found %d relocations in .rel.text.\n", rel_count);
    // 4. 遍历重定位项
    for (int i = 0; i < rel_count; i++) {
        Elf32_Rel *rel = &rels[i];
        uint32_t r_info = rel->r_info;
        uint32_t sym_idx = ELF32_R_SYM(r_info);
        uint32_t rel_type = ELF32_R_TYPE(r_info);
        Elf32_Sym *sym = &symtab[sym_idx];

        if (sym->st_value == 0 || sym->st_size == 0) {
            continue;
        }
        // 5. 根据 ARM32 类型进行重定位计算
        if (rel_type == R_ARM_THM_CALL || rel_type == R_ARM_THM_JUMP24) {
            uint32_t r_offset = rel->r_offset;
            uint32_t *patch_loc = (uint32_t *)((char *)ehdr + text_sec->sh_offset + r_offset);
            uint32_t old_val = *patch_loc;
            relocate_thumb(ehdr, text_sec, sym, (unsigned long)patch_loc);
            printf("relocate %s %x -> %x\n", sym->st_name + strtab, old_val, *patch_loc);
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <module.o>\n", argv[0]);
        return 1;
    }
    const char *filename = argv[1];
    int fd = open(filename, O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    // 获取文件大小
    struct stat st;
    fstat(fd, &st);
    size_t file_size = st.st_size;
    // 将 ELF 文件映射到内存
    char *map_base = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map_base == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }
    // 检查 ELF有效性
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)map_base;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 || ehdr->e_ident[EI_CLASS] != ELFCLASS32) {
        printf("Not a valid 32-bit ELF file.\n");
        munmap(map_base, file_size);
        close(fd);
        return 1;
    }
    printf("Applying static relocations for ARM32...\n");
    printf("Assuming Load Base Address: 0x%x\n\n", MODULE_LOAD_BASE);
    // 执行重定位
    apply_relocations(ehdr);
    // 清理

    msync(map_base, file_size, MS_SYNC);  // 将修改写回文件
    munmap(map_base, file_size);
    close(fd);
    printf("\nDone. Relocations applied and file updated.\n");
    return 0;
}
