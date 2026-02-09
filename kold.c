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

        printf("sym %s %d %d %d\n", sym->st_name + strtab, ELF32_R_TYPE(r_info),
               sym->st_value, sym->st_value);
        if (sym->st_value == 0 || sym->st_size == 0) {
            continue;
        }
        // 5. 根据 ARM32 类型进行重定位计算
        if (rel_type == R_ARM_THM_CALL || rel_type == R_ARM_THM_JUMP24) {
            uint8_t new_bind = STB_LOCAL;
            sym->st_info = (new_bind << 4) | (sym->st_info & 0x0F);
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
