#define _GNU_SOURCE
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

#define __opcode_to_mem_arm(x) (u32)(x)
#define __mem_to_opcode_arm(x) (u32)(x)

static int sign_extend32(uint32_t value, int index)
{
    uint8_t shift = 31 - index;
    return (int)(value << shift) >> shift;
}

// copy from linux kernel
static void relocate_thumb(Elf32_Ehdr *ehdr, uint32_t sym_addr, unsigned long loc)
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

    offset += sym_addr - loc;

    sign = (offset >> 24) & 1;
    j1 = sign ^ (~(offset >> 23) & 1);
    j2 = sign ^ (~(offset >> 22) & 1);
    upper = (u16)((upper & 0xf800) | (sign << 10) | ((offset >> 12) & 0x03ff));
    lower = (u16)((lower & 0xd000) | (j1 << 13) | (j2 << 11) | ((offset >> 1) & 0x07ff));

    *(u16 *)loc = __opcode_to_mem_thumb16(upper);
    *(u16 *)(loc + 2) = __opcode_to_mem_thumb16(lower);
}

static void relocate_arm_call(Elf32_Ehdr *ehdr, uint32_t sym_addr, unsigned long loc)
{
    s32 offset;

    offset = __mem_to_opcode_arm(*(u32 *)loc);
    offset = (offset & 0x00ffffff) << 2;
    offset = sign_extend32(offset, 25);

    offset += sym_addr - loc;

    offset >>= 2;
    offset &= 0x00ffffff;

    *(u32 *)loc &= __opcode_to_mem_arm(0xff000000);
    *(u32 *)loc |= __opcode_to_mem_arm(offset);
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

typedef struct {
    uint32_t start;  // Original offset where adjustment starts
    uint32_t delta;  // Cumulative adjustment at this point
} OffsetAdjust;

static uint32_t adjust_offset(uint32_t orig_off, OffsetAdjust *adjusts, int num_adjusts)
{
    uint32_t delta = 0;
    for (int i = 0; i < num_adjusts; i++) {
        if (orig_off >= adjusts[i].start) {
            delta = adjusts[i].delta;
        } else {
            break;
        }
    }
    return orig_off - delta;
}

static int write_output_elf(Elf32_Ehdr *ehdr, size_t orig_file_size, const char *output_file)
{
    Elf32_Shdr *shdrs = (Elf32_Shdr *)((char *)ehdr + ehdr->e_shoff);

    // Calculate total bytes to remove and record size reduction per section
    size_t total_removed = 0;
    uint32_t *sec_removed = calloc(ehdr->e_shnum, sizeof(uint32_t));
    if (!sec_removed) {
        perror("calloc");
        return -1;
    }

    if (relocated_count > 0) {
        // Sort entries by section index (ascending) and entry index (descending)
        qsort(relocated_entries, relocated_count, sizeof(RelocatedEntry),
              compare_relocated_entries);

        // Remove relocated entries from each relocation section
        for (int i = 0; i < relocated_count; i++) {
            int sec_idx = relocated_entries[i].rel_sec_index;
            int entry_idx = relocated_entries[i].entry_index;

            if (sec_idx < 0 || sec_idx >= ehdr->e_shnum) {
                continue;
            }

            Elf32_Shdr *rel_sec = &shdrs[sec_idx];
            Elf32_Rel *rels = (Elf32_Rel *)((char *)ehdr + rel_sec->sh_offset);
            int rel_count = rel_sec->sh_size / sizeof(Elf32_Rel);

            // Remove entry by shifting subsequent entries
            for (int j = entry_idx; j < rel_count - 1; j++) {
                rels[j] = rels[j + 1];
            }

            // Update section size
            rel_sec->sh_size -= sizeof(Elf32_Rel);
            sec_removed[sec_idx] += sizeof(Elf32_Rel);
            total_removed += sizeof(Elf32_Rel);
        }
    }

    size_t new_file_size = orig_file_size - total_removed;

    // Build offset adjustment map: collect modified sections' end positions
    int num_adjusts = 0;
    OffsetAdjust *adjusts = malloc((ehdr->e_shnum + 1) * sizeof(OffsetAdjust));
    if (!adjusts) {
        perror("malloc");
        free(sec_removed);
        return -1;
    }

    // Collect adjustment points from modified sections
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (sec_removed[i] > 0) {
            adjusts[num_adjusts].start = shdrs[i].sh_offset + shdrs[i].sh_size;
            adjusts[num_adjusts].delta = sec_removed[i];
            num_adjusts++;
        }
    }

    // Sort adjustment points by offset (simple bubble sort, num_adjusts is small)
    for (int i = 0; i < num_adjusts - 1; i++) {
        for (int j = i + 1; j < num_adjusts; j++) {
            if (adjusts[i].start > adjusts[j].start) {
                OffsetAdjust tmp = adjusts[i];
                adjusts[i] = adjusts[j];
                adjusts[j] = tmp;
            }
        }
    }

    // Convert to cumulative deltas
    uint32_t cumulative = 0;
    for (int i = 0; i < num_adjusts; i++) {
        cumulative += adjusts[i].delta;
        adjusts[i].delta = cumulative;
    }

    // Allocate output buffer
    char *output_buf = calloc(1, new_file_size);
    if (!output_buf) {
        perror("calloc output");
        free(adjusts);
        free(sec_removed);
        return -1;
    }

    // Copy ELF header
    memcpy(output_buf, ehdr, ehdr->e_ehsize);
    Elf32_Ehdr *out_ehdr = (Elf32_Ehdr *)output_buf;
    out_ehdr->e_shoff = adjust_offset(ehdr->e_shoff, adjusts, num_adjusts);

    // Copy section data with adjusted offsets
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_size > 0 && shdrs[i].sh_type != SHT_NOBITS && shdrs[i].sh_offset > 0) {
            uint32_t new_off = adjust_offset(shdrs[i].sh_offset, adjusts, num_adjusts);
            memcpy(output_buf + new_off, (char *)ehdr + shdrs[i].sh_offset, shdrs[i].sh_size);
        }
    }

    // Write section header table with updated offsets
    Elf32_Shdr *out_shdrs = (Elf32_Shdr *)(output_buf + out_ehdr->e_shoff);
    for (int i = 0; i < ehdr->e_shnum; i++) {
        out_shdrs[i] = shdrs[i];
        if (shdrs[i].sh_offset > 0) {
            out_shdrs[i].sh_offset = adjust_offset(shdrs[i].sh_offset, adjusts, num_adjusts);
        }
    }

    // Write output file
    int fd_out = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_out < 0) {
        perror("open output");
        free(output_buf);
        free(adjusts);
        free(sec_removed);
        return -1;
    }

    ssize_t written = write(fd_out, output_buf, new_file_size);
    if (written < 0 || (size_t)written != new_file_size) {
        perror("write output");
        close(fd_out);
        free(output_buf);
        free(adjusts);
        free(sec_removed);
        return -1;
    }

    close(fd_out);
    free(output_buf);
    free(adjusts);
    free(sec_removed);

    printf("Output written to: %s (size: %zu bytes, reduced by %zu bytes)\n", output_file,
           new_file_size, orig_file_size - new_file_size);
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

        uint32_t r_offset = rel->r_offset;
        uint32_t *patch_loc = (uint32_t *)((char *)ehdr + text_sec->sh_offset + r_offset);
        uint32_t sym_addr =
            (uint32_t)(unsigned long long)ehdr + text_sec->sh_offset + sym->st_value;

        if (rel_type == R_ARM_THM_CALL || rel_type == R_ARM_THM_JUMP24) {
            relocate_thumb(ehdr, sym_addr, (unsigned long)patch_loc);
            add_relocated_entry(rel_sec_index, i);
        } else if (rel_type == R_ARM_CALL || rel_type == R_ARM_JUMP24) {
            relocate_arm_call(ehdr, sym_addr, (unsigned long)patch_loc);
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

    // First open the file for processing and information collection
    int fd = open(filename, O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    struct stat st;
    fstat(fd, &st);
    size_t file_size = st.st_size;

    char *input_buf = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (input_buf == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    char temp_file[256];

    snprintf(temp_file, sizeof(temp_file), "%s.tmp.XXXXXX", filename);
    int fd_temp = mkstemp(temp_file);
    if (fd_temp < 0) {
        perror("mkstemp");
        return 1;
    }
    int bytes = 0;
    while (bytes < file_size) {
        int ret = write(fd_temp, input_buf + bytes, file_size - bytes);
        if (ret < 0) {
            perror("write failed\n");
            break;
        }
        bytes += ret;
    }
    munmap(input_buf, file_size);
    close(fd);
    filename = temp_file;

    char *map_base = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_temp, 0);
    if (map_base == MAP_FAILED) {
        perror("mmap");
        close(fd_temp);
        return 1;
    }

    // Check ELF validity
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)map_base;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 || ehdr->e_ident[EI_CLASS] != ELFCLASS32) {
        printf("Not a valid 32-bit ELF file.\n");
        munmap(map_base, file_size);
        close(fd_temp);
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

    int ret = write_output_elf(ehdr, file_size, output_file);

    munmap(map_base, file_size);
    close(fd_temp);

    free(relocated_entries);
    relocated_entries = NULL;
    relocated_count = 0;
    relocated_capacity = 0;

    return ret < 0 ? 1 : 0;
}
