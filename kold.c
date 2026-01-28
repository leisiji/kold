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
#define R_ARM_NONE  0
#define R_ARM_ABS32 2
#define R_ARM_REL32 3
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
 * 模拟符号解析
 * 在实际内核中，这需要查找内核导出的符号表 或模块自身的符号表。
 * 这里我们简化处理：如果是全局定义的符号，假设其地址为 基址 + 符号值。
 * 如果是外部符号，这里仅打印并返回 0（模拟未解析或需要内核导出的情况）。
 */
static uint32_t resolve_symbol(Elf32_Sym *sym, Elf32_Ehdr *ehdr, uint32_t load_base)
{
    uint8_t sym_bind = ELF32_ST_BIND(sym->st_info);
    uint8_t sym_type = ELF32_ST_TYPE(sym->st_info);
    // 如果是局部定义的符号 (STB_LOCAL)，地址 = 基址 + 符号值
    if (sym_bind == STB_LOCAL) {
        // 注意：在 .o 文件中，st_value 通常是其所在 Section 的偏移量
        // 真实的加载器需要知道该符号所在的 Section 被加载到了哪个地址
        // 这里为了演示，简单粗暴地加上 MODULE_LOAD_BASE
        // 更严谨的做法是：找到 sym->st_shndx 对应的 Section Header，
        // 获取该 Section 的 sh_addr (也就是相对于 MODULE_LOAD_BASE 的偏移)
        // 假设符号就在某个段内，其值为偏移
        return load_base + sym->st_value;
    }
    // 如果是全局符号，且不是 SECTION (5) 或 FILE (4)
    if (sym_type != STT_SECTION && sym_type != STT_FILE) {
        // 在真实场景下，这里应该调用 kernel kallsyms_lookup_name 或者查找模块的 .symtab
        printf(
            "  [!] Symbol resolution: Global symbol found (Index: %d), pretending to resolve to "
            "base+val for demo.\n",
            (int)(sym - (Elf32_Sym *)((char *)ehdr + ehdr->e_shoff)));  // Debug print
        return load_base + sym->st_value;
    }
    return 0;
}
/**
 * 执行静态重定位的核心函数
 */
void apply_relocations(Elf32_Ehdr *ehdr, uint32_t load_base)
{
    Elf32_Shdr *shdrs = (Elf32_Shdr *)((char *)ehdr + ehdr->e_shoff);
    // 1. 获取 Section Header String Table
    Elf32_Shdr *shstrtab_sec = &shdrs[ehdr->e_shstrndx];
    char *shstrtab = (char *)ehdr + shstrtab_sec->sh_offset;
    // 2. 查找关键段
    Elf32_Shdr *data_sec = find_section_header(shstrtab, ehdr, ".data");
    Elf32_Shdr *rel_data_sec =
        find_section_header(shstrtab, ehdr, ".rel.data");  // 注意：可能是 .rel.data 或 .rela.data
    Elf32_Shdr *symtab_sec = find_section_header(shstrtab, ehdr, ".symtab");
    Elf32_Shdr *strtab_sec = &shdrs[symtab_sec->sh_link];
    char *strtab = (char *)ehdr + strtab_sec->sh_offset;

    if (!data_sec || !rel_data_sec || !symtab_sec) {
        printf("Missing critical sections (.data, .rel.data, .symtab). Exiting.\n");
        return;
    }

    // 3. 准备指针
    // .rel.data 中的重定位项数组
    Elf32_Rel *rels = (Elf32_Rel *)((char *)ehdr + rel_data_sec->sh_offset);
    int rel_count = rel_data_sec->sh_size / sizeof(Elf32_Rel);
    // 符号表
    Elf32_Sym *symtab = (Elf32_Sym *)((char *)ehdr + symtab_sec->sh_offset);
    printf("Found %d relocations in .rel.data.\n", rel_count);
    // 4. 遍历重定位项
    for (int i = 0; i < rel_count; i++) {
        Elf32_Rel *rel = &rels[i];
        uint32_t r_offset = rel->r_offset;
        uint32_t r_info = rel->r_info;
        uint32_t sym_idx = ELF32_R_SYM(r_info);
        uint32_t rel_type = ELF32_R_TYPE(r_info);
        Elf32_Sym *sym = &symtab[sym_idx];
        // 获取符号对应的运行时地址 (S)
        uint32_t S = resolve_symbol(sym, ehdr, load_base);

        if (sym->st_value == 0 || sym->st_size == 0) {
            printf("skip %s\n", sym->st_name + strtab);
            continue;
        }
        // 获取 Addend (A)
        // 如果使用 Elf32_Rel (不带显式 addend)，Addend 存储在被重定位位置的当前值中
        // 如果使用 Elf32_Rela (带显式 addend)，Addend 存在 rel->r_addend 中
        // Linux kernel module 通常使用 Elf32_Rel
        uint32_t *patch_loc = (uint32_t *)((char *)ehdr + data_sec->sh_offset + r_offset);
        uint32_t A = *patch_loc;
        // 获取被重定位位置的运行时地址 (P)
        uint32_t P = load_base + data_sec->sh_addr + r_offset;
        printf("Processing Rel %d: Type=%d, Offset=0x%x, SymVal=0x%x, OriginalMem=0x%x, Name: %s\n",
               i, rel_type, r_offset, S, A, sym->st_name + strtab);
        // 5. 根据 ARM32 类型进行重定位计算
        /*
        if (rel_type == R_ARM_ABS32) {
            // 公式: (S + A)
            *patch_loc = S + A;
            printf("  -> R_ARM_ABS32: Patching memory at 0x%x with 0x%x\n", (uint32_t)patch_loc,
                   *patch_loc);
        } else if (rel_type == R_ARM_REL32) {
            // 公式: (S + A) - P
            *patch_loc = (S + A) - P;
            printf("  -> R_ARM_REL32: Patching memory at 0x%x with 0x%x\n", (uint32_t)patch_loc,
                   *patch_loc);
        } else if (rel_type == R_ARM_NONE) {
            // Do nothing
        } else {
            printf("  [!] Unsupported relocation type: %d\n", rel_type);
        }
        */
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
    apply_relocations(ehdr, MODULE_LOAD_BASE);
    // 清理

    msync(map_base, file_size, MS_SYNC);  // 将修改写回文件
    munmap(map_base, file_size);
    close(fd);
    printf("\nDone. Relocations applied and file updated.\n");
    return 0;
}
