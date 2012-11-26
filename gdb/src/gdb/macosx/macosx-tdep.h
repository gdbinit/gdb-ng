#ifndef __GDB_MACOSX_TDEP_H__
#define __GDB_MACOSX_TDEP_H__

#if defined (TARGET_POWERPC)
#include "ppc-macosx-tdep.h"
#elif defined (TARGET_I386)
#include "i386-macosx-tdep.h"
#elif defined (TARGET_ARM)
#include "arm-macosx-tdep.h"
#else 
#error "Unrecognized target architecture"
#endif

#include "symtab.h"

#include <CoreFoundation/CoreFoundation.h>

struct internal_nlist;
struct external_nlist;
struct objfile;
extern enum gdb_osabi osabi_seen_in_attached_dyld;

extern int disable_aslr_flag;

extern CORE_ADDR kernel_slide;

void macosx_internalize_symbol (struct internal_nlist * in, int *sect_p,
                                struct external_nlist * ext, bfd *abfd);

const char *dyld_symbol_stub_function_name (CORE_ADDR pc);
CORE_ADDR dyld_symbol_stub_function_address (CORE_ADDR pc, const char **name);

CORE_ADDR macosx_skip_trampoline_code (CORE_ADDR pc);
int macosx_in_solib_return_trampoline (CORE_ADDR pc, char *name);
int macosx_in_solib_call_trampoline (CORE_ADDR pc, char *name);
int macosx_record_symbols_from_sect_p (bfd *abfd, unsigned char macho_type, 
				       unsigned char macho_sect);

char *macosx_locate_dsym (struct objfile *objfile);
char *macosx_locate_kext_executable_by_symfile(bfd *abfd);
struct objfile *macosx_find_objfile_matching_dsym_in_bundle (char *dsym_bundle_path, 
							     char **out_full_path);

int macosx_get_uuid_for_path(const char *filename, unsigned char uuid[], unsigned long len);

char *macosx_kext_info (const char *filename,
                  const char **bundle_executable_name_from_plist,
                  const char **bundle_identifier_name_from_plist);

enum gdb_osabi generic_mach_o_osabi_sniffer (bfd *abfd, enum bfd_architecture arch, 
			      unsigned long mach_32,
			      unsigned long mach_64,
			      int (*query_64_bit_fn) ());

int fast_show_stack_trace_prologue (unsigned int count_limit, 
				unsigned int print_start,
				unsigned int print_end,
				unsigned int wordsize,
				CORE_ADDR *sigtramp_start_ptr,
				CORE_ADDR *sigtramp_end_ptr,
				unsigned int *count,
				struct frame_info **fi,
				void (print_fun) (struct ui_out * uiout, int *frame_num,
						  CORE_ADDR pc, CORE_ADDR fp));

int macosx_enable_exception_callback (enum exception_event_kind kind, int enable);

struct symtabs_and_lines *macosx_find_exception_catchpoints (enum exception_event_kind kind, struct objfile *restrict_objfile);

struct exception_event_record *macosx_get_current_exception_event ();

struct section_addr_info *get_section_addresses_for_macho_in_memory (CORE_ADDR mh_addr);

struct section_addr_info *get_section_addrs_of_macho_on_disk (const char *filename);

struct section_addr_info *get_section_addresses_for_bfd (bfd *abfd);

struct section_addr_info *macosx_get_kext_sect_addrs_from_kernel (const char *kext_filename, uint8_t **kext_uuids, const char *kext_bundle_ident);

char *macosx_pid_or_tid_to_str (ptid_t ptid);

int exhaustive_search_for_kernel_in_mem (struct objfile *ofile, CORE_ADDR *addr, uuid_t *uuid_output);

char *macosx_locate_executable_by_dbg_shell_command (CFStringRef uuid);

CFUUIDRef get_uuidref_for_uuid_t (uint8_t *uuid);

CORE_ADDR get_load_addr_of_macho_on_disk (const char *filename, enum gdb_osabi osabi);

int get_information_about_macho (const char *filename, CORE_ADDR mh_addr, bfd *abfd,
                             int require_kernel, int force_live_memory_reads,
                             uuid_t *uuid, enum gdb_osabi *osabi,
                             int *wordsize, CORE_ADDR *intended_load_address, CORE_ADDR *slide,
                             struct section_addr_info **addrs);

int slide_kernel_objfile (struct objfile *o, CORE_ADDR in_memory_addr, uuid_t in_memory_uuid, enum gdb_osabi osabi);

int try_to_find_and_load_kernel_via_uuid (CORE_ADDR in_memory_addr, uuid_t in_memory_uuid, enum gdb_osabi osabi);


struct gdb_copy_dyld_cache_local_symbols_entry
{
        uint32_t        dylibOffset;      // file (pre-loaded) address of this dylib minus 0x30000000
        uint32_t        nlistStartIndex;  // nlist record number in the array at dyld_shared_cache_local_nlists
        uint32_t        nlistCount;       // number of nlist records for this dylib
};

extern uint8_t *dyld_shared_cache_local_nlists;
extern int dyld_shared_cache_local_nlists_count;
extern char *dyld_shared_cache_strings;
extern int dyld_shared_cache_strings_size;
extern struct gdb_copy_dyld_cache_local_symbols_entry *dyld_shared_cache_entries;
extern int dyld_shared_cache_entries_count;

void free_dyld_shared_cache_local_syms ();
void get_dyld_shared_cache_local_syms ();
struct gdb_copy_dyld_cache_local_symbols_entry *get_dyld_shared_cache_entry (CORE_ADDR intended_load_addr);


#endif /* __GDB_MACOSX_TDEP_H__ */
