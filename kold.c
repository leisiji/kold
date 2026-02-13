#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define R_ARM_NONE     0
#define R_ARM_ABS32    2
#define R_ARM_REL32    3
#define R_ARM_THM_CALL 10
#ifndef R_ARM_THM_JUMP24
#define R_ARM_THM_JUMP24 30
#endif

#define u32 uint32_t
#define s32 int
#define u16 uint16_t

// Record information about processed relocation entries
typedef struct {
    int rel_sec_index;
    int entry_index;
} RelocatedEntry;

static RelocatedEntry *relocated_entries = NULL;
static int relocated_count = 0;
static int relocated_capacity = 0;

static Elf32_Shdr *find_section_header(char *shstrtab, Elf32_Ehdr *ehdr, const char *name,
                                       int *index)
{
    Elf32_Shdr *shdrs = (Elf32_Shdr *)((char *)ehdr + ehdr->e_shoff);
    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *sec_name = shstrtab + shdrs[i].sh_name;
        if (strcmp(sec_name, name) == 0) {
            if (index != NULL) {
                *index = i;
            }
            return &shdrs[i];
        }
    }
    return NULL;
}

#define __mem_to_opcode_thumb16(x) (x)
#define __opcode_to_mem_thumb16(x) (x)

static int sign_extend32(uint32_t value, int index)
{
    uint8_t shift = 31 - index;
    return (int)(value << shift) >> shift;
}

// copy from linux kernel
static void relocate_thumb(Elf32_Ehdr *ehdr, Elf32_Shdr *dstsec, Elf32_Sym *sym, unsigned long loc)
{
    u32 upper, lower, sign, j1, j2;
    s32 offset;

    upper = __mem_to_opcode_thumb16(*(u16 *)loc);
    lower = __mem_to_opcode_thumb16(*(u16 *)(loc + 2));

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

static void add_relocated_entry(int rel_sec_index, int entry_index)
{
    if (relocated_count >= relocated_capacity) {
        relocated_capacity = relocated_capacity == 0 ? 128 : relocated_capacity * 2;
        relocated_entries = realloc(relocated_entries, relocated_capacity * sizeof(RelocatedEntry));
    }
    relocated_entries[relocated_count].rel_sec_index = rel_sec_index;
    relocated_entries[relocated_count].entry_index = entry_index;
    relocated_count++;
}

static int compare_relocated_entries(const void *a, const void *b)
{
    const RelocatedEntry *ea = (const RelocatedEntry *)a;
    const RelocatedEntry *eb = (const RelocatedEntry *)b;
    if (ea->rel_sec_index != eb->rel_sec_index)
        return ea->rel_sec_index - eb->rel_sec_index;
    return eb->entry_index - ea->entry_index;
}

// Forward declaration
static void apply_relocations(Elf32_Ehdr *ehdr, const char *text_sec_name, int rel_sec_index);

// Create new ELF file, excluding processed relocation entries
static int create_new_elf(const char *input_file, const char *output_file)
{
    // If input and output are the same file, use a temporary file
    char temp_file[256];
    int use_temp = 0;
    if (strcmp(input_file, output_file) == 0) {
        snprintf(temp_file, sizeof(temp_file), "%s.tmp.XXXXXX", input_file);
        int fd_temp = mkstemp(temp_file);
        if (fd_temp < 0) {
            perror("mkstemp");
            return -1;
        }
        close(fd_temp);
        use_temp = 1;
        output_file = temp_file;
    }

    int fd_in = open(input_file, O_RDONLY);
    if (fd_in < 0) {
        perror("open input file");
        if (use_temp)
            unlink(temp_file);
        return -1;
    }

    struct stat st;
    fstat(fd_in, &st);
    size_t file_size = st.st_size;

    char *map_in = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd_in, 0);
    if (map_in == MAP_FAILED) {
        perror("mmap input file");
        close(fd_in);
        if (use_temp)
            unlink(temp_file);
        return -1;
    }

    Elf32_Ehdr *ehdr_in = (Elf32_Ehdr *)map_in;
    if (memcmp(ehdr_in->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr_in->e_ident[EI_CLASS] != ELFCLASS32) {
        printf("Not a valid 32-bit ELF file.\n");
        munmap(map_in, file_size);
        close(fd_in);
        if (use_temp)
            unlink(temp_file);
        return -1;
    }

    Elf32_Shdr *shdrs_in = (Elf32_Shdr *)(map_in + ehdr_in->e_shoff);
    Elf32_Shdr *shstrtab_sec_in = &shdrs_in[ehdr_in->e_shstrndx];
    char *shstrtab_in = map_in + shstrtab_sec_in->sh_offset;

    // Determine which sections need to be shrunk
    int *needs_resize = calloc(ehdr_in->e_shnum, sizeof(int));
    size_t *new_sizes = calloc(ehdr_in->e_shnum, sizeof(size_t));
    size_t total_saved = 0;

    for (int i = 0; i < ehdr_in->e_shnum; i++) {
        Elf32_Shdr *sh_in = &shdrs_in[i];
        const char *name = shstrtab_in + sh_in->sh_name;

        if (strncmp(name, ".rel.", 5) == 0 &&
            (strcmp(name + 5, "text") == 0 || strcmp(name + 5, "init.text") == 0 ||
             strcmp(name + 5, "exit.text") == 0)) {
            int processed_count = 0;
            for (int k = 0; k < relocated_count; k++) {
                if (relocated_entries[k].rel_sec_index == i) {
                    processed_count++;
                }
            }

            int old_count = sh_in->sh_size / sizeof(Elf32_Rel);
            int new_count = old_count - processed_count;

            if (new_count >= 0) {
                needs_resize[i] = 1;
                new_sizes[i] = new_count * sizeof(Elf32_Rel);
                total_saved += (sh_in->sh_size - new_sizes[i]);
            }
        }
    }

    if (total_saved == 0) {
        printf("No relocation entries to remove.\n");
        free(needs_resize);
        free(new_sizes);
        munmap(map_in, file_size);
        close(fd_in);
        return 0;
    }

    printf("Total bytes saved: %zu\n", total_saved);

    // 按 offset 排序所有 section
    typedef struct {
        int idx;
        size_t old_offset;
        size_t old_size;
    } SecSort;

    SecSort *sorted = malloc(ehdr_in->e_shnum * sizeof(SecSort));
    for (int i = 0; i < ehdr_in->e_shnum; i++) {
        sorted[i].idx = i;
        sorted[i].old_offset = shdrs_in[i].sh_offset;
        sorted[i].old_size = shdrs_in[i].sh_size;
    }

    for (int i = 0; i < ehdr_in->e_shnum - 1; i++) {
        for (int j = 0; j < ehdr_in->e_shnum - i - 1; j++) {
            if (sorted[j].old_offset > sorted[j + 1].old_offset) {
                SecSort tmp = sorted[j];
                sorted[j] = sorted[j + 1];
                sorted[j + 1] = tmp;
            }
        }
    }

    // 计算新的 offsets
    size_t new_file_size = file_size - total_saved;

    // 创建输出文件
    int fd_out = open(output_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd_out < 0) {
        perror("create output file");
        free(sorted);
        free(needs_resize);
        free(new_sizes);
        munmap(map_in, file_size);
        close(fd_in);
        return -1;
    }

    if (ftruncate(fd_out, new_file_size) < 0) {
        perror("ftruncate");
        close(fd_out);
        free(sorted);
        free(needs_resize);
        free(new_sizes);
        munmap(map_in, file_size);
        close(fd_in);
        return -1;
    }

    char *map_out = mmap(NULL, new_file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_out, 0);
    if (map_out == MAP_FAILED) {
        perror("mmap output file");
        close(fd_out);
        free(sorted);
        free(needs_resize);
        free(new_sizes);
        munmap(map_in, file_size);
        close(fd_in);
        return -1;
    }

    // 分配新的 offset 映射
    size_t *new_offsets = calloc(ehdr_in->e_shnum, sizeof(size_t));

    // Start after ELF header
    size_t write_pos = sizeof(Elf32_Ehdr);

    for (int i = 0; i < ehdr_in->e_shnum; i++) {
        int idx = sorted[i].idx;
        Elf32_Shdr *sh = &shdrs_in[idx];

        if (sh->sh_type == SHT_NULL) {
            new_offsets[idx] = sh->sh_offset;
            continue;
        }

        // Align
        size_t align = sh->sh_addralign;
        if (align > 1) {
            write_pos = (write_pos + align - 1) & ~(align - 1);
        }

        new_offsets[idx] = write_pos;

        if (needs_resize[idx]) {
            write_pos += new_sizes[idx];
        } else {
            write_pos += sh->sh_size;
        }
    }

    // Copy ELF header
    memcpy(map_out, map_in, sizeof(Elf32_Ehdr));

    // Copy section data
    for (int i = 0; i < ehdr_in->e_shnum; i++) {
        if (shdrs_in[i].sh_type == SHT_NULL)
            continue;

        size_t src_offset = shdrs_in[i].sh_offset;
        size_t dst_offset = new_offsets[i];

        if (needs_resize[i]) {
            // This is a relocation section that needs to be shrunk, only copy unprocessed entries
            Elf32_Rel *rels_in = (Elf32_Rel *)(map_in + src_offset);
            Elf32_Rel *rels_out = (Elf32_Rel *)(map_out + dst_offset);
            int old_count = shdrs_in[i].sh_size / sizeof(Elf32_Rel);
            int write_idx = 0;

            // Create a fast lookup set
            int *is_processed = calloc(old_count, sizeof(int));
            for (int k = 0; k < relocated_count; k++) {
                if (relocated_entries[k].rel_sec_index == i) {
                    is_processed[relocated_entries[k].entry_index] = 1;
                }
            }

            for (int j = 0; j < old_count; j++) {
                if (!is_processed[j]) {
                    rels_out[write_idx++] = rels_in[j];
                }
            }

            free(is_processed);
        } else {
            // Regular section, copy directly
            memcpy(map_out + dst_offset, map_in + src_offset, shdrs_in[i].sh_size);
        }
    }

    // Calculate new section header table position
    size_t shdr_table_size = ehdr_in->e_shnum * sizeof(Elf32_Shdr);
    size_t new_shoff = (write_pos + 3) & ~3;

    // Check if file needs to be extended to accommodate section header table
    if (new_shoff + shdr_table_size > new_file_size) {
        size_t needed_size = new_shoff + shdr_table_size;
        munmap(map_out, new_file_size);
        if (ftruncate(fd_out, needed_size) < 0) {
            perror("ftruncate extend");
            free(new_offsets);
            free(sorted);
            free(needs_resize);
            free(new_sizes);
            munmap(map_in, file_size);
            close(fd_out);
            close(fd_in);
            return -1;
        }
        new_file_size = needed_size;
        map_out = mmap(NULL, new_file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_out, 0);
        if (map_out == MAP_FAILED) {
            perror("mmap extended");
            free(new_offsets);
            free(sorted);
            free(needs_resize);
            free(new_sizes);
            munmap(map_in, file_size);
            close(fd_out);
            close(fd_in);
            return -1;
        }
        // Re-copy ELF header
        memcpy(map_out, map_in, sizeof(Elf32_Ehdr));
    }

    // Update ELF header's e_shoff
    Elf32_Ehdr *ehdr_out = (Elf32_Ehdr *)map_out;
    ehdr_out->e_shoff = new_shoff;

    // Ensure .shstrtab section data is copied (string table)
    // Find the index of .shstrtab section
    Elf32_Shdr *shstrtab_hdr_in = &shdrs_in[ehdr_in->e_shstrndx];
    size_t shstrtab_old_offset = shstrtab_hdr_in->sh_offset;
    size_t shstrtab_new_offset = new_offsets[ehdr_in->e_shstrndx];

    // If the position of .shstrtab has changed, its data needs to be copied
    if (shstrtab_new_offset != shstrtab_old_offset && needs_resize[ehdr_in->e_shstrndx] == 0) {
        memcpy(map_out + shstrtab_new_offset, map_in + shstrtab_old_offset,
               shstrtab_hdr_in->sh_size);
    }

    // Write updated section headers to new position
    Elf32_Shdr *shdrs_out = (Elf32_Shdr *)(map_out + new_shoff);
    for (int i = 0; i < ehdr_in->e_shnum; i++) {
        // Copy original section header
        memcpy(&shdrs_out[i], &shdrs_in[i], sizeof(Elf32_Shdr));
        // Update offset
        shdrs_out[i].sh_offset = new_offsets[i];
        // If this is a section that needs resizing, update size
        if (needs_resize[i]) {
            shdrs_out[i].sh_size = new_sizes[i];
        }
    }

    // Cleanup
    free(new_offsets);
    free(sorted);
    free(needs_resize);
    free(new_sizes);

    munmap(map_out, new_file_size);
    munmap(map_in, file_size);
    close(fd_out);
    close(fd_in);

    printf("Successfully created new ELF file with %d processed relocation entries removed.\n",
           relocated_count);
    return 0;
}

static void apply_relocations(Elf32_Ehdr *ehdr, const char *text_sec_name, int rel_sec_index)
{
    Elf32_Shdr *shdrs = (Elf32_Shdr *)((char *)ehdr + ehdr->e_shoff);
    Elf32_Shdr *shstrtab_sec = &shdrs[ehdr->e_shstrndx];
    char *shstrtab = (char *)ehdr + shstrtab_sec->sh_offset;

    char rel_sec_name[128] = {0};
    snprintf(rel_sec_name, sizeof(rel_sec_name), ".rel%s", text_sec_name);

    int text_sec_index = 0;
    Elf32_Shdr *text_sec = find_section_header(shstrtab, ehdr, text_sec_name, &text_sec_index);
    Elf32_Shdr *rel_text_sec = find_section_header(shstrtab, ehdr, rel_sec_name, NULL);
    Elf32_Shdr *symtab_sec = find_section_header(shstrtab, ehdr, ".symtab", NULL);

    if (!rel_text_sec || !symtab_sec) {
        printf("Missing critical sections (.data, .rel.data, .symtab). Exiting.\n");
        return;
    }

    Elf32_Rel *rels = (Elf32_Rel *)((char *)ehdr + rel_text_sec->sh_offset);
    int rel_count = rel_text_sec->sh_size / sizeof(Elf32_Rel);
    Elf32_Sym *symtab = (Elf32_Sym *)((char *)ehdr + symtab_sec->sh_offset);

    for (int i = 0; i < rel_count; i++) {
        Elf32_Rel *rel = &rels[i];
        uint32_t r_info = rel->r_info;
        uint32_t sym_idx = ELF32_R_SYM(r_info);
        uint32_t rel_type = ELF32_R_TYPE(r_info);
        Elf32_Sym *sym = &symtab[sym_idx];

        /* linux kernel will not load ko section in the order of ko's layout, so do not relocate
         * across section */
        if (sym->st_value == 0 || sym->st_size == 0 || sym->st_shndx != text_sec_index) {
            continue;
        }

        if (rel_type == R_ARM_THM_CALL || rel_type == R_ARM_THM_JUMP24) {
            uint32_t r_offset = rel->r_offset;
            uint32_t *patch_loc = (uint32_t *)((char *)ehdr + text_sec->sh_offset + r_offset);
            relocate_thumb(ehdr, text_sec, sym, (unsigned long)patch_loc);
            add_relocated_entry(rel_sec_index, i);
        }
    }
}

int main(int argc, char *argv[])
{
    const char *filename = NULL;
    const char *output_file = NULL;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: -o requires an argument\n");
                return 1;
            }
            output_file = argv[i + 1];
            i++;  // Skip next argument
        } else if (!filename) {
            filename = argv[i];
        } else {
            fprintf(stderr, "Error: unexpected argument: %s\n", argv[i]);
            return 1;
        }
    }

    if (!filename) {
        fprintf(stderr, "Usage: %s <module.o> -o <output.o>\n", argv[0]);
        fprintf(stderr, "  -o <output.o>  Required: output file path\n");
        return 1;
    }

    if (!output_file) {
        fprintf(stderr, "Error: -o option is required\n");
        fprintf(stderr, "Usage: %s <module.o> -o <output.o>\n", argv[0]);
        return 1;
    }

    char temp_file[256];
    int use_temp = 0;

    // If input and output are the same file, use a temporary file
    if (strcmp(filename, output_file) == 0) {
        snprintf(temp_file, sizeof(temp_file), "%s.tmp.XXXXXX", filename);
        int fd_temp = mkstemp(temp_file);
        if (fd_temp < 0) {
            perror("mkstemp");
            return 1;
        }
        close(fd_temp);
        use_temp = 1;
        output_file = temp_file;
    }

    // First open the file for processing and information collection
    int fd = open(filename, O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    struct stat st;
    fstat(fd, &st);
    size_t file_size = st.st_size;

    char *map_base = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map_base == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    // Check ELF validity
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)map_base;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 || ehdr->e_ident[EI_CLASS] != ELFCLASS32) {
        printf("Not a valid 32-bit ELF file.\n");
        munmap(map_base, file_size);
        close(fd);
        return 1;
    }

    // Find indices of all relocation sections
    Elf32_Shdr *shdrs = (Elf32_Shdr *)(map_base + ehdr->e_shoff);
    Elf32_Shdr *shstrtab_sec = &shdrs[ehdr->e_shstrndx];
    char *shstrtab = map_base + shstrtab_sec->sh_offset;

    int rel_text_idx = -1, rel_init_text_idx = -1, rel_exit_text_idx = -1;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *name = shstrtab + shdrs[i].sh_name;
        if (strcmp(name, ".rel.text") == 0)
            rel_text_idx = i;
        else if (strcmp(name, ".rel.init.text") == 0)
            rel_init_text_idx = i;
        else if (strcmp(name, ".rel.exit.text") == 0)
            rel_exit_text_idx = i;
    }

    // Process relocations and collect information
    apply_relocations(ehdr, ".text", rel_text_idx);
    apply_relocations(ehdr, ".init.text", rel_init_text_idx);
    apply_relocations(ehdr, ".exit.text", rel_exit_text_idx);

    printf("Total relocated entries: %d\n", relocated_count);

    munmap(map_base, file_size);
    close(fd);

    if (relocated_count == 0) {
        printf("No relocations processed, creating output file with same content.\n");
        // No relocation entries were processed, copy file directly
        int fd_in = open(filename, O_RDONLY);
        if (fd_in < 0) {
            perror("open input");
            return 1;
        }
        int fd_out = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd_out < 0) {
            perror("open output");
            close(fd_in);
            return 1;
        }
        char buf[4096];
        ssize_t n;
        while ((n = read(fd_in, buf, sizeof(buf))) > 0) {
            write(fd_out, buf, n);
        }
        close(fd_in);
        close(fd_out);
        return 0;
    }

    // Sort relocated_entries for easier processing
    qsort(relocated_entries, relocated_count, sizeof(RelocatedEntry), compare_relocated_entries);

    // Create new ELF file
    int ret = create_new_elf(filename, output_file);

    if (ret == 0 && use_temp) {
        // Rename temporary file to final output file
        if (rename(output_file, filename) != 0) {
            perror("rename temp file");
            ret = -1;
        }
    } else if (ret != 0 && use_temp) {
        // Delete temporary file on failure
        unlink(output_file);
    }

    free(relocated_entries);
    relocated_entries = NULL;
    relocated_count = 0;
    relocated_capacity = 0;

    return ret == 0 ? 0 : 1;
}
