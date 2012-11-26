/* Mac OS X support for GDB, the GNU debugger.
   Copyright 1997, 1998, 1999, 2000, 2001, 2002
   Free Software Foundation, Inc.

   Contributed by Apple Computer, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* This file is part of GDB.

GDB is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 1, or (at your option)
any later version.

GDB is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with GDB; see the file COPYING.  If not, write to
the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.  */

#include "defs.h"
#include "inferior.h"
#include "target.h"
#include "symfile.h"
#include "symtab.h"
#include "objfiles.h"
#include "gdbcmd.h"
#include "language.h"
#include "block.h"

#include "libaout.h"            /* FIXME Secret internal BFD stuff for a.out */
#include "aout/aout64.h"
#include "complaints.h"

#include "mach-o.h"
#include "objc-lang.h"

#include "macosx-tdep.h"
#include "regcache.h"
#include "source.h"
#include "completer.h"
#include "exceptions.h"
#include "gdbcmd.h"

#include "gdbcore.h"
#include "exec.h"

#include <dirent.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <mach/machine.h>
#include <mach/kmod.h>

#include <CoreFoundation/CoreFoundation.h>
#include <CoreFoundation/CFPropertyList.h>

#include "readline/tilde.h" /* For tilde_expand */
#include "arch-utils.h"

#include "macosx-nat-utils.h"

#include "x86-shared-tdep.h"
#include "osabi.h"

#include <mach-o/loader.h>
#include "macosx-nat-dyld.h" // for target_read_mach_header()

/* For the gdbarch_tdep structure so we can get the wordsize. */
#if defined(TARGET_POWERPC)
#include "ppc-tdep.h"
#elif defined (TARGET_I386)
#include "amd64-tdep.h"
#include "i386-tdep.h"
#elif defined (TARGET_ARM)
#include "arm-tdep.h"
#else
#error "Unrecognized target architecture."
#endif
#include "gdbarch.h"

int disable_aslr_flag = 1;

CORE_ADDR kernel_slide = INVALID_ADDRESS;

static char *find_info_plist_filename_from_bundle_name (const char *bundle,
                                                     const char *bundle_suffix);

#if USE_DEBUG_SYMBOLS_FRAMEWORK
extern CFArrayRef DBGCopyMatchingUUIDsForURL (CFURLRef path,
                                              int /* cpu_type_t */ cpuType,
                                           int /* cpu_subtype_t */ cpuSubtype);
extern CFURLRef DBGCopyDSYMURLForUUID (CFUUIDRef uuid);
extern CFDictionaryRef DBGCopyDSYMPropertyLists (CFURLRef dsym_url);
#endif

static void get_uuid_t_for_uuidref (CFUUIDRef uuid_in, uuid_t *uuid_out);

static const char dsym_extension[] = ".dSYM";
static const char dsym_bundle_subdir[] = "Contents/Resources/DWARF/";
static const int  dsym_extension_len = (sizeof (dsym_extension) - 1);
static const int  dsym_bundle_subdir_len = (sizeof (dsym_bundle_subdir) - 1);
static int dsym_locate_enabled = 1;
static int kaslr_memory_search_enabled = 1;
#define APPLE_DSYM_EXT_AND_SUBDIRECTORY ".dSYM/Contents/Resources/DWARF/"

int
actually_do_stack_frame_prologue (unsigned int count_limit, 
				unsigned int print_start,
				unsigned int print_end,
				unsigned int wordsize,
				unsigned int *count,
				struct frame_info **out_fi,
				void (print_fun) (struct ui_out * uiout, int *frame_num,
						  CORE_ADDR pc, CORE_ADDR fp));

/* When we're doing native debugging, and we attach to a process,
   we start out by finding the in-memory dyld -- the osabi of that
   dyld is stashed away here for use when picking the right osabi of
   a fat file.  In the case of cross-debugging, none of this happens
   and this global remains untouched.  */

enum gdb_osabi osabi_seen_in_attached_dyld = GDB_OSABI_UNKNOWN;

#if 0
struct deprecated_complaint unknown_macho_symtype_complaint =
  { "unknown Mach-O symbol type %s", 0, 0 };

struct deprecated_complaint unknown_macho_section_complaint =
  { "unknown Mach-O section value %s (assuming DATA)", 0, 0 };

struct deprecated_complaint unsupported_indirect_symtype_complaint =
  { "unsupported Mach-O symbol type %s (indirect)", 0, 0 };
#endif

#define BFD_GETB16(addr) ((addr[0] << 8) | addr[1])
#define BFD_GETB32(addr) ((((((uint32_t) addr[0] << 8) | addr[1]) << 8) | addr[2]) << 8 | addr[3])
#define BFD_GETB64(addr) ((((((((((uint64_t) addr[0] << 8) | addr[1]) << 8) | addr[2]) << 8 | addr[3]) << 8 | addr[4]) << 8 | addr[5]) << 8 | addr[6]) << 8 | addr[7])
#define BFD_GETL16(addr) ((addr[1] << 8) | addr[0])
#define BFD_GETL32(addr) ((((((uint32_t) addr[3] << 8) | addr[2]) << 8) | addr[1]) << 8 | addr[0])
#define BFD_GETL64(addr) ((((((((((uint64_t) addr[7] << 8) | addr[6]) << 8) | addr[5]) << 8 | addr[4]) << 8 | addr[3]) << 8 | addr[2]) << 8 | addr[1]) << 8 | addr[0])

unsigned char macosx_symbol_types[256];

static unsigned char
macosx_symbol_type_base (macho_type)
     unsigned char macho_type;
{
  unsigned char mtype = macho_type;
  unsigned char ntype = 0;

  if (macho_type & BFD_MACH_O_N_STAB)
    {
      return macho_type;
    }

  if (mtype & BFD_MACH_O_N_PEXT)
    {
      mtype &= ~BFD_MACH_O_N_PEXT;
      ntype |= N_EXT;
    }

  if (mtype & BFD_MACH_O_N_EXT)
    {
      mtype &= ~BFD_MACH_O_N_EXT;
      ntype |= N_EXT;
    }

  switch (mtype & BFD_MACH_O_N_TYPE)
    {
    case BFD_MACH_O_N_SECT:
      /* should add section here */
      break;

    case BFD_MACH_O_N_PBUD:
      ntype |= N_UNDF;
      break;

    case BFD_MACH_O_N_ABS:
      ntype |= N_ABS;
      break;

    case BFD_MACH_O_N_UNDF:
      ntype |= N_UNDF;
      break;

    case BFD_MACH_O_N_INDR:
      /* complain (&unsupported_indirect_symtype_complaint, hex_string (macho_type)); */
      return macho_type;

    default:
      /* complain (&unknown_macho_symtype_complaint, hex_string (macho_type)); */
      return macho_type;
    }
  mtype &= ~BFD_MACH_O_N_TYPE;

  CHECK_FATAL (mtype == 0);

  return ntype;
}

static void
macosx_symbol_types_init ()
{
  unsigned int i;
  for (i = 0; i < 256; i++)
    {
      macosx_symbol_types[i] = macosx_symbol_type_base (i);
    }
}

static unsigned char
macosx_symbol_type (macho_type, macho_sect, abfd)
     unsigned char macho_type;
     unsigned char macho_sect;
     bfd *abfd;
{
  unsigned char ntype = macosx_symbol_types[macho_type];

  /* If the symbol refers to a section, modify ntype based on the value of macho_sect. */

  if ((macho_type & BFD_MACH_O_N_TYPE) == BFD_MACH_O_N_SECT)
    {
      if (macho_sect == 1)
        {
          /* Section 1 is always the text segment. */
          ntype |= N_TEXT;
        }

      else if ((macho_sect > 0)
               && (macho_sect <= abfd->tdata.mach_o_data->nsects))
        {
          const bfd_mach_o_section *sect =
            abfd->tdata.mach_o_data->sections[macho_sect - 1];

          if (sect == NULL)
            {
              /* complain (&unknown_macho_section_complaint, hex_string (macho_sect)); */
            }
          else if ((sect->segname != NULL)
                   && (strcmp (sect->segname, "__DATA") == 0))
            {
              if ((sect->sectname != NULL)
                  && (strcmp (sect->sectname, "__bss") == 0))
                ntype |= N_BSS;
              else
                ntype |= N_DATA;
            }
          else if ((sect->segname != NULL)
                   && (strcmp (sect->segname, "__TEXT") == 0))
            {
              ntype |= N_TEXT;
            }
          else
            {
              /* complain (&unknown_macho_section_complaint, hex_string (macho_sect)); */
              ntype |= N_DATA;
            }
        }

      else
        {
          /* complain (&unknown_macho_section_complaint, hex_string (macho_sect)); */
          ntype |= N_DATA;
        }
    }

  /* All modifications are done; return the computed type code. */

  return ntype;
}

void
macosx_internalize_symbol (in, sect_p, ext, abfd)
     struct internal_nlist *in;
     int *sect_p;
     struct external_nlist *ext;
     bfd *abfd;
{
  int symwide = (bfd_mach_o_version (abfd) > 1);

  if (bfd_header_big_endian (abfd))
    {
      in->n_strx = BFD_GETB32 (ext->e_strx);
      in->n_desc = BFD_GETB16 (ext->e_desc);
      if (symwide)
        in->n_value = BFD_GETB64 (ext->e_value);
      else
        in->n_value = BFD_GETB32 (ext->e_value);
    }
  else if (bfd_header_little_endian (abfd))
    {
      in->n_strx = BFD_GETL32 (ext->e_strx);
      in->n_desc = BFD_GETL16 (ext->e_desc);
      if (symwide)
        in->n_value = BFD_GETL64 (ext->e_value);
      else
        in->n_value = BFD_GETL32 (ext->e_value);
    }
  else
    {
      error ("unable to internalize symbol (unknown endianness)");
    }

  if ((ext->e_type[0] & BFD_MACH_O_N_TYPE) == BFD_MACH_O_N_SECT)
    *sect_p = 1;
  else
    *sect_p = 0;

  in->n_type = macosx_symbol_type (ext->e_type[0], ext->e_other[0], abfd);
  in->n_other = ext->e_other[0];
}

CORE_ADDR
dyld_symbol_stub_function_address (CORE_ADDR pc, const char **name)
{
  struct symbol *sym = NULL;
  struct minimal_symbol *msym = NULL;
  const char *lname = NULL;

  lname = dyld_symbol_stub_function_name (pc);
  if (name)
    *name = lname;

  if (lname == NULL)
    return 0;

  /* found a name, now find a symbol and address */

  sym = lookup_symbol_global (lname, lname, VAR_DOMAIN, 0);
  if ((sym == NULL) && (lname[0] == '_'))
    sym = lookup_symbol_global (lname + 1, lname + 1, VAR_DOMAIN, 0);
  if (sym != NULL && SYMBOL_BLOCK_VALUE (sym) != NULL)
    /* APPLE LOCAL begin address ranges  */
    return BLOCK_LOWEST_PC (SYMBOL_BLOCK_VALUE (sym));
    /* APPLE LOCAL end address ranges  */

  msym = lookup_minimal_symbol (lname, NULL, NULL);
  if ((msym == 0) && (lname[0] == '_'))
    msym = lookup_minimal_symbol (lname + 1, NULL, NULL);
  if (msym != NULL)
    return SYMBOL_VALUE_ADDRESS (msym);

  return 0;
}

const char *
dyld_symbol_stub_function_name (CORE_ADDR pc)
{
  struct minimal_symbol *msymbol = NULL;
  const char *DYLD_PREFIX = "dyld_stub_";

  msymbol = lookup_minimal_symbol_by_pc (pc);

  if (msymbol == NULL)
    return NULL;

  if (SYMBOL_VALUE_ADDRESS (msymbol) != pc)
    return NULL;

  if (strncmp
      (SYMBOL_LINKAGE_NAME (msymbol), DYLD_PREFIX, strlen (DYLD_PREFIX)) != 0)
    return NULL;

  return SYMBOL_LINKAGE_NAME (msymbol) + strlen (DYLD_PREFIX);
}

CORE_ADDR
macosx_skip_trampoline_code (CORE_ADDR pc)
{
  CORE_ADDR newpc;

  newpc = dyld_symbol_stub_function_address (pc, NULL);
  if (newpc != 0)
    return newpc;

#if defined (TARGET_I386)
  newpc = x86_cxx_virtual_override_thunk_trampline (pc);
  if (newpc != 0)
    return newpc;
#endif

  newpc = decode_fix_and_continue_trampoline (pc);
  if (newpc != 0)
    return newpc;

  return 0;
}

/* This function determings whether a symbol is in a SYMBOL_STUB section.
   ld64 puts symbols there for all the stubs, but if we read those in, they
   will confuse us when we lookup the symbol for the pc to see if we are
   in a stub.  NOTE, this function assumes the symbols passed in are of type
   N_SECT.  */

int
macosx_record_symbols_from_sect_p (bfd *abfd, unsigned char macho_type, 
				   unsigned char macho_sect)
{
  const bfd_mach_o_section *sect;
  /* We sometimes get malformed symbols which are of type N_SECT, but
     with a section number of NO_SECT.  */
  if (macho_sect <= 0 || macho_sect > abfd->tdata.mach_o_data->nsects)
    {
      warning ("Bad symbol - type is N_SECT but section is %d in file '%s'", macho_sect, abfd->filename);
      return 0;
    }

  sect = abfd->tdata.mach_o_data->sections[macho_sect - 1];
  if ((sect->flags & BFD_MACH_O_SECTION_TYPE_MASK) ==
      BFD_MACH_O_S_SYMBOL_STUBS)
    return 0;
  else
    return 1;
}

int
macosx_in_solib_return_trampoline (CORE_ADDR pc, char *name)
{
  return 0;
}

int
macosx_in_solib_call_trampoline (CORE_ADDR pc, char *name)
{
  if (macosx_skip_trampoline_code (pc) != 0)
    {
      return 1;
    }
  return 0;
}

static void
info_trampoline_command (char *exp, int from_tty)
{
  struct expression *expr;
  struct value *val;
  CORE_ADDR address;
  CORE_ADDR trampoline;
  CORE_ADDR objc;

  expr = parse_expression (exp);
  val = evaluate_expression (expr);
  if (TYPE_CODE (value_type (val)) == TYPE_CODE_REF)
    val = value_ind (val);
  if ((TYPE_CODE (value_type (val)) == TYPE_CODE_FUNC)
      && (VALUE_LVAL (val) == lval_memory))
    address = VALUE_ADDRESS (val);
  else
    address = value_as_address (val);

  trampoline = macosx_skip_trampoline_code (address);

  find_objc_msgcall (trampoline, &objc);

  fprintf_filtered
    (gdb_stderr, "Function at 0x%s becomes 0x%s becomes 0x%s\n",
     paddr_nz (address), paddr_nz (trampoline), paddr_nz (objc));
}

struct sal_chain
{
  struct sal_chain *next;
  struct symtab_and_line sal;
};


/* On some platforms, you need to turn on the exception callback
   to hit the catchpoints for exceptions.  Not on Mac OS X. */

int
macosx_enable_exception_callback (enum exception_event_kind kind, int enable)
{
  return 1;
}

/* The MacOS X implemenatation of the find_exception_catchpoints
   target vector entry.  Relies on the __cxa_throw and
   __cxa_begin_catch functions from libsupc++.  */

struct symtabs_and_lines *
macosx_find_exception_catchpoints (enum exception_event_kind kind,
                                   struct objfile *restrict_objfile)
{
  struct symtabs_and_lines *return_sals;
  char *symbol_name;
  struct objfile *objfile;
  struct minimal_symbol *msymbol;
  unsigned int hash;
  struct sal_chain *sal_chain = 0;

  switch (kind)
    {
    case EX_EVENT_THROW:
      symbol_name = "__cxa_throw";
      break;
    case EX_EVENT_CATCH:
      symbol_name = "__cxa_begin_catch";
      break;
    default:
      error ("We currently only handle \"throw\" and \"catch\"");
    }

  hash = msymbol_hash (symbol_name) % MINIMAL_SYMBOL_HASH_SIZE;

  ALL_OBJFILES (objfile)
  {
    for (msymbol = objfile->msymbol_hash[hash];
         msymbol != NULL; msymbol = msymbol->hash_next)
      if (MSYMBOL_TYPE (msymbol) == mst_text
          && (strcmp_iw (SYMBOL_LINKAGE_NAME (msymbol), symbol_name) == 0))
        {
          /* We found one, add it here... */
          CORE_ADDR catchpoint_address;
          CORE_ADDR past_prologue;

          struct sal_chain *next
            = (struct sal_chain *) alloca (sizeof (struct sal_chain));

          next->next = sal_chain;
          init_sal (&next->sal);
          next->sal.symtab = NULL;

          catchpoint_address = SYMBOL_VALUE_ADDRESS (msymbol);
          past_prologue = SKIP_PROLOGUE (catchpoint_address);

          next->sal.pc = past_prologue;
          next->sal.line = 0;
          next->sal.end = past_prologue;

          sal_chain = next;

        }
  }

  if (sal_chain)
    {
      int index = 0;
      struct sal_chain *temp;

      for (temp = sal_chain; temp != NULL; temp = temp->next)
        index++;

      return_sals = (struct symtabs_and_lines *)
        xmalloc (sizeof (struct symtabs_and_lines));
      return_sals->nelts = index;
      return_sals->sals =
        (struct symtab_and_line *) xmalloc (index *
                                            sizeof (struct symtab_and_line));

      for (index = 0; sal_chain; sal_chain = sal_chain->next, index++)
        return_sals->sals[index] = sal_chain->sal;
      return return_sals;
    }
  else
    return NULL;

}

/* Returns data about the current exception event */

struct exception_event_record *
macosx_get_current_exception_event ()
{
  static struct exception_event_record *exception_event = NULL;
  struct frame_info *curr_frame;
  struct frame_info *fi;
  CORE_ADDR pc;
  int stop_func_found;
  char *stop_name;
  char *typeinfo_str;

  if (exception_event == NULL)
    {
      exception_event = (struct exception_event_record *)
        xmalloc (sizeof (struct exception_event_record));
      exception_event->exception_type = NULL;
    }

  curr_frame = get_current_frame ();
  if (!curr_frame)
    return (struct exception_event_record *) NULL;

  pc = get_frame_pc (curr_frame);
  stop_func_found = find_pc_partial_function (pc, &stop_name, NULL, NULL);
  if (!stop_func_found)
    return (struct exception_event_record *) NULL;

  if (strcmp (stop_name, "__cxa_throw") == 0)
    {

      fi = get_prev_frame (curr_frame);
      if (!fi)
        return (struct exception_event_record *) NULL;

      exception_event->throw_sal = find_pc_line (get_frame_pc (fi), 1);

      /* FIXME: We don't know the catch location when we
         have just intercepted the throw.  Can we walk the
         stack and redo the runtimes exception matching
         to figure this out? */
      exception_event->catch_sal.pc = 0x0;
      exception_event->catch_sal.line = 0;

      exception_event->kind = EX_EVENT_THROW;

    }
  else if (strcmp (stop_name, "__cxa_begin_catch") == 0)
    {
      fi = get_prev_frame (curr_frame);
      if (!fi)
        return (struct exception_event_record *) NULL;

      exception_event->catch_sal = find_pc_line (get_frame_pc (fi), 1);

      /* By the time we get here, we have totally forgotten
         where we were thrown from... */
      exception_event->throw_sal.pc = 0x0;
      exception_event->throw_sal.line = 0;

      exception_event->kind = EX_EVENT_CATCH;


    }

#ifdef THROW_CATCH_FIND_TYPEINFO
  typeinfo_str =
    THROW_CATCH_FIND_TYPEINFO (curr_frame, exception_event->kind);
#else
  typeinfo_str = NULL;
#endif

  if (exception_event->exception_type != NULL)
    xfree (exception_event->exception_type);

  if (typeinfo_str == NULL)
    {
      exception_event->exception_type = NULL;
    }
  else
    {
      exception_event->exception_type = xstrdup (typeinfo_str);
    }

  return exception_event;
}

void
update_command (char *args, int from_tty)
{
  registers_changed ();
  reinit_frame_cache ();
}

void
stack_flush_command (char *args, int from_tty)
{
  reinit_frame_cache ();
  if (from_tty)
    printf_filtered ("Stack cache flushed.\n");
}

/* Opens the file pointed to in ARGS with the default editor
   given by LaunchServices.  If ARGS is NULL, opens the current
   source file & line.  You can also supply file:line and it will
   open the that file & try to put the selection on that line.  */

static void
open_command (char *args, int from_tty)
{
  const char *filename = NULL;  /* Possibly directory-less filename */
  const char *fullname = NULL;  /* Fully qualified on-disk filename */
  struct stat sb;
  int line_no = 0;

  warning ("open command no longer supported - may be back in a future build.");
  return;

  if (args == NULL || args[0] == '\0')
    {
      filename = NULL;
      line_no = 0;
    }

  else
    {
      char *colon_pos = strrchr (args, ':');
      if (colon_pos == NULL)
	line_no = 0;
      else
	{
	  line_no = atoi (colon_pos + 1);
	  *colon_pos = '\0';
	}
      filename = args;
    }

  if (filename == NULL)
    {
      struct symtab_and_line cursal = get_current_source_symtab_and_line ();
      if (cursal.symtab)
        fullname = symtab_to_fullname (cursal.symtab);
      else
        error ("No currently selected source file available; "
               "please specify one.");
      /* The cursal is actually set to the list-size bracket around
         the current line, so we have to add that back in to get the
	 real source line.  */

      line_no = cursal.line + get_lines_to_list () / 2;
    }

  if (fullname == NULL)
    {
       /* lookup_symtab will give us the first match; should we use
	  the Apple local variant, lookup_symtab_all?  And what
	  would we do with the results; open all of them?  */
       struct symtab *s = lookup_symtab (filename);
       if (s)
         fullname = symtab_to_fullname (s);
       else
         error ("Filename '%s' not found in this program's debug information.",
                filename);
    }

  /* Prefer the fully qualified FULLNAME over whatever FILENAME might have.  */

  if (stat (fullname, &sb) == 0)
    filename = fullname;
  else
    if (stat (filename, &sb) != 0)
      error ("File '%s' not found.", filename);
}


/* Helper function for gdb_DBGCopyMatchingUUIDsForURL.
   Given a bfd of a MachO file, look for an LC_UUID load command
   and return that uuid in an allocated CFUUIDRef.
   If the file being examined is fat, we assume that the bfd we're getting
   passed in has already been iterated over to get one of the thin forks of
   the file.
   It is the caller's responsibility to release the memory.
   NULL is returned if we do not find a LC_UUID for any reason.  */

static CFUUIDRef
get_uuidref_for_bfd (struct bfd *abfd)
{
 uint8_t uuid[16];
 if (abfd == NULL)
   return NULL;

 if (bfd_mach_o_get_uuid (abfd, uuid, sizeof (uuid)))
   return CFUUIDCreateWithBytes (kCFAllocatorDefault,
             uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5],
             uuid[6], uuid[7], uuid[8], uuid[9], uuid[10], uuid[11],
             uuid[12], uuid[13], uuid[14], uuid[15]);

 return NULL;
}

/* Helper function for gdb_DBGCopyMatchingUUIDsForURL.
   Given a uuid_t (16-bytes of uint8_t's) return that uuid in an 
   allocated CFUUIDRef.
   It is the caller's responsibility to release the memory via CFRelease. */

CFUUIDRef
get_uuidref_for_uuid_t (uint8_t *uuid)
{
 if (uuid == NULL)
   return NULL;

 return CFUUIDCreateWithBytes (kCFAllocatorDefault,
           uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5],
           uuid[6], uuid[7], uuid[8], uuid[9], uuid[10], uuid[11],
           uuid[12], uuid[13], uuid[14], uuid[15]);
}

/* Given a CFUUIDRef return that uuid in a uuid_t. 
   UUID_OUT is a pointer to allocated memory uuid_t large.  */

static void
get_uuid_t_for_uuidref (CFUUIDRef uuid_in, uuid_t *uuid_out)
{
  assert (sizeof (uuid_t) == sizeof (CFUUIDBytes));

  CFUUIDBytes ret;
  ret = CFUUIDGetUUIDBytes (uuid_in);

  memcpy ((uint8_t *) uuid_out, (uint8_t *) &ret, sizeof (uuid_t));
}


/* This is an implementation of the DebugSymbols framework's
   DBGCopyMatchingUUIDsForURL function.  Given the path to a
   dSYM file (not the bundle directory but the actual dSYM dwarf
   file), it will return a CF array of UUIDs that this file has.  
   Normally depending on DebugSymbols.framework isn't a problem but
   we don't have this framework on all platforms and we want the
   "add-dsym" command to continue to work without it. */

static CFMutableArrayRef
gdb_DBGCopyMatchingUUIDsForURL (const char *path)
{
  if (path == NULL || path[0] == '\0')
    return NULL;

  CFAllocatorRef alloc = kCFAllocatorDefault;
  CFMutableArrayRef uuid_array = NULL;
  struct gdb_exception e;
  bfd *abfd = NULL;

  TRY_CATCH (e, RETURN_MASK_ERROR)
  {
    abfd = symfile_bfd_open (path, 0, GDB_OSABI_UNKNOWN);
  }
  
  if (abfd == NULL || e.reason == RETURN_ERROR)
    return NULL;
  if (bfd_check_format (abfd, bfd_archive)
      && strcmp (bfd_get_target (abfd), "mach-o-fat") == 0)
    {
      bfd *nbfd = NULL;
      for (;;)
        {
          nbfd = bfd_openr_next_archived_file (abfd, nbfd);
          if (nbfd == NULL)
            break;
          if (!bfd_check_format (nbfd, bfd_object) 
              && !bfd_check_format (nbfd, bfd_archive))
            continue;
          CFUUIDRef nbfd_uuid = get_uuidref_for_bfd (nbfd);
          if (nbfd_uuid != NULL)
            {
              if (uuid_array == NULL)
                uuid_array = CFArrayCreateMutable(alloc, 0, &kCFTypeArrayCallBacks);
              if (uuid_array)
                CFArrayAppendValue (uuid_array, nbfd_uuid);
              CFRelease (nbfd_uuid);
            }
        }
      bfd_free_cached_info (abfd);
    }
  else
   {
      CFUUIDRef abfd_uuid = get_uuidref_for_bfd (abfd);
      if (abfd_uuid != NULL)
        {
          if (uuid_array == NULL)
            uuid_array = CFArrayCreateMutable(alloc, 0, &kCFTypeArrayCallBacks);
          if (uuid_array)
            CFArrayAppendValue (uuid_array, abfd_uuid);
          CFRelease (abfd_uuid);
        }
    }

  bfd_close (abfd);
  return uuid_array;
}


CFMutableDictionaryRef
create_dsym_uuids_for_path (char *dsym_bundle_path)
{
  char path[PATH_MAX];
  struct dirent* dp = NULL;
  DIR* dirp = NULL;
  char* dsym_path = NULL;
  CFMutableDictionaryRef paths_and_uuids;
  
  /* Copy the base dSYM bundle directory path into our new path.  */
  strncpy (path, dsym_bundle_path, sizeof (path));
  
  if (path[sizeof (path) - 1])
    return NULL;  /* Path is too large.  */
  
  int path_len = strlen (path);
  
  if (path_len > 0)
    {
      /* Add directory delimiter to end of bundle path if
	 needed to normalize the path.  */
      if (path[path_len-1] != '/')
	{
	  path[path_len] = '/';
	  if (path_len + 1 < sizeof (path))
	    path[++path_len] = '\0';
	  else
	    return NULL; /* Path is too large.  */
	}
    }
  
  /* Append the bundle subdirectory path.  */
  if (dsym_bundle_subdir_len + 1 > sizeof (path) - path_len)
    return NULL; /* Path is too large.  */
  
  strncat (path, dsym_bundle_subdir, sizeof (path) - path_len - 1);
  
  if (path[sizeof (path) - 1])
    return NULL;  /* Path is too large.  */
  
  dirp = opendir (path);
  if (dirp == NULL)
    return NULL;
  
  path_len = strlen (path);
  
  /* Leave room for a NULL at the end in case strncpy 
     doesn't NULL terminate.  */
  paths_and_uuids = CFDictionaryCreateMutable (kCFAllocatorDefault, 0, 
					       &kCFTypeDictionaryKeyCallBacks, 
					       &kCFTypeDictionaryValueCallBacks);
  
  while (dsym_path == NULL && (dp = readdir (dirp)) != NULL)
    {
      /* Don't search directories.  Note, some servers return DT_UNKNOWN
         for everything, so you can't assume this test will keep you from
	 trying to read directories...  */
      if (dp->d_type == DT_DIR)
	continue;
      
      /* Full path length to each file in the dSYM's
	 /Contents/Resources/DWARF/ directory.  */
      int full_path_len = path_len + dp->d_namlen + 1;
      if (sizeof (path) > full_path_len)
	{
	  CFURLRef path_url = NULL;
	  CFArrayRef uuid_array = NULL;
	  CFStringRef path_cfstr = NULL;
	  /* Re-use the path each time and only copy the 
	     directory entry name just past the 
	     ".../Contents/Resources/DWARF/" part of PATH.  */
	  strcpy(&path[path_len], dp->d_name);
	  path_cfstr = CFStringCreateWithCString (NULL, path,  
						  kCFStringEncodingUTF8);
	  path_url = CFURLCreateWithFileSystemPath (NULL, path_cfstr,
                                                    kCFURLPOSIXPathStyle, 0);
	  
	  CFRelease (path_cfstr), path_cfstr = NULL;
	  if (path_url == NULL)
	    continue;
	  
	  uuid_array = gdb_DBGCopyMatchingUUIDsForURL (path);
	  if (uuid_array != NULL)
	    CFDictionarySetValue (paths_and_uuids, path_url, uuid_array);
	  
	  /* We are done with PATH_URL.  */
	  CFRelease (path_url);
	  path_url = NULL;
	  
	  /* Skip to next while loop iteration if we didn't get any matches.  */
	  /* Release the UUID array.  */
	  if (uuid_array != NULL)
	    CFRelease (uuid_array);
	  uuid_array = NULL;
	}
    }
  closedir (dirp);
  if (CFDictionaryGetCount (paths_and_uuids) == 0)
    {
      CFRelease (paths_and_uuids);
      return NULL;
    }
  else
    return paths_and_uuids;
}

struct search_baton
{
  CFUUIDRef test_uuid;
  int found_it;
  CFURLRef path_url;
};

void 
paths_and_uuids_map_func (const void *in_url, 
			  const void *in_array, 
			  void *in_results)
{
  const CFURLRef path_url = (CFURLRef) in_url;
  const CFArrayRef uuid_array = (CFArrayRef) in_array;
  struct search_baton *results = (struct search_baton *) in_results;

  const CFIndex count = CFArrayGetCount (uuid_array);
  CFIndex i;

  if (results->found_it)
    return;
  for (i = 0; i < count; i++)
    {
      CFUUIDRef tmp_uuid = CFArrayGetValueAtIndex (uuid_array, i);
      if (CFEqual (tmp_uuid, results->test_uuid))
	{
	  results->path_url = path_url;
	  CFRetain (path_url);
	  results->found_it = 1;
	  break;
	}
    }
}

/* Search a dSYM bundle for a specific UUID. UUID_REF is the UUID object
   to look for, and DSYM_BUNDLE_PATH is a path to the top level dSYM bundle
   directory. We need to look through the bundle and find the correct dSYM 
   Mach-O file. This allows dSYM bundle directory names and the dsym Mach-O files
   within them to have names that are different from the name of the
   executable which can be handy when debugging build styles (debug and 
   profile). The returned string has been xmalloc()'ed and it is the 
   responsibility of the caller to xfree it. */
static char *
locate_dsym_mach_in_bundle (CFUUIDRef uuid_ref, char *dsym_bundle_path)
{
  CFMutableDictionaryRef paths_and_uuids;
  struct search_baton results;

  paths_and_uuids = create_dsym_uuids_for_path (dsym_bundle_path);

  if (paths_and_uuids == NULL)
    return NULL;

  results.found_it = 0;
  results.test_uuid = uuid_ref;

  CFDictionaryApplyFunction (paths_and_uuids, paths_and_uuids_map_func,
			     &results);

  CFRelease (paths_and_uuids);

  if (results.found_it)
    {
      char path[PATH_MAX];
      path[PATH_MAX-1] = '\0';
      if (CFURLGetFileSystemRepresentation (results.path_url, 1, 
						(UInt8 *)path, sizeof (path)))
	return xstrdup (path);
      else
	return NULL;
    }
  else
    return NULL;

}

#if USE_DEBUG_SYMBOLS_FRAMEWORK

struct plist_filenames_search_baton {
  CFPropertyListRef plist;
  int found_it;
  CFStringRef searching_for;
};

static void 
plist_filenames_and_uuids_map_func (const void *in_key, const void *in_value, 
                                    void *context)
{
  struct plist_filenames_search_baton *baton = (struct plist_filenames_search_baton *) context;
  CFStringRef searching_for = baton->searching_for;
  CFStringRef key = (CFStringRef) in_key;
  CFPropertyListRef value = (CFPropertyListRef) in_value;

  if (CFStringCompare (key, searching_for, 0))
    {
      baton->found_it = 1;
      baton->plist = value;
    }
  return;
}

static void
find_source_path_mappings (CFUUIDRef uuid, CFURLRef dsym)
{
  CFDictionaryRef plists = DBGCopyDSYMPropertyLists (dsym);
  CFStringRef uuid_str = CFUUIDCreateString (kCFAllocatorDefault, uuid);
  if (plists && uuid_str)
    {
      struct plist_filenames_search_baton results;
      results.found_it = 0;
      results.searching_for = uuid_str;
      CFDictionaryApplyFunction (plists, plist_filenames_and_uuids_map_func, 
                                 &results);
      if (results.found_it)
        {
          const char *build_src_path = macosx_get_plist_posix_value 
                                          (results.plist, "DBGBuildSourcePath");
          const char *src_path = macosx_get_plist_posix_value 
                                               (results.plist, "DBGSourcePath");
          if (src_path)
            {
              const char *src_path_tilde_expanded = tilde_expand (src_path);
              xfree ((char *) src_path);
              src_path = src_path_tilde_expanded;
            }
          if (build_src_path && src_path)
            {
              add_one_pathname_substitution (build_src_path, src_path);
            }
        }
    }
  if (uuid_str)
    CFRelease (uuid_str);
  if (plists)
    CFRelease (plists);
}

/* Given an OBJFILE, we've found a matching dSYM bundle at pathname DSYM
   (the string in DSYM ends in ".dSYM").  This function creates CF 
   representations of the UUID in the objfile and the dSYM pathname and
   looks for a plist with pathname substitutions in it.  
   If the pathname given in DSYM contains additional path components (inside
   the dSYM bundle), those will be ignored.  */

void
find_source_path_mappings_posix (struct objfile *objfile, const char *dsym)
{
  unsigned char uuid[16];
  CFURLRef dsym_ref;
  CFStringRef dsym_str_ref;

  /* Extract the UUID from the objfile.  */
  if (!bfd_mach_o_get_uuid (objfile->obfd, uuid, sizeof (uuid)))
    return;

  /* Create a CFUUID object for use with DebugSymbols framework.  */
  CFUUIDRef uuid_ref = CFUUIDCreateWithBytes (kCFAllocatorDefault, uuid[0],
                                              uuid[1], uuid[2], uuid[3],
                                              uuid[4], uuid[5], uuid[6],
                                              uuid[7], uuid[8], uuid[9],
                                              uuid[10], uuid[11], uuid[12],
                                              uuid[13], uuid[14], uuid[15]);
  if (uuid_ref == NULL)
    return;

  /* If the DSYM pathname passed in has stuff after the ".dSYM" component,
     get rid of it.  Find the last ".dSYM" in the string, copy the string to
     a local buffer.  */

  const char *j, *i = strstr (dsym, ".dSYM");
  if (i == NULL)
    {
      CFRelease (uuid_ref);
      return;
    }
  while ((j = strstr (i + 1, ".dSYM")) != NULL)
    i = j;

  if (i[5] != '\0')
    {
      i += 5;  /* i now points past the ".dSYM" characters */
      int len = i - dsym + 1;
      char *n = alloca (len);
      strlcpy (n, dsym, len);
      dsym = n;
    }

  dsym_str_ref = CFStringCreateWithCString (NULL, dsym,
                                            kCFStringEncodingUTF8);
  if (dsym_str_ref == NULL)
    {
      CFRelease (uuid_ref);
      return;
    }

  dsym_ref = CFURLCreateWithFileSystemPath (NULL, dsym_str_ref,
                                            kCFURLPOSIXPathStyle, 0);
  CFRelease (dsym_str_ref);

  if (dsym_ref == NULL)
    {
      CFRelease (uuid_ref);
      return;
    }

  find_source_path_mappings (uuid_ref, dsym_ref);

  CFRelease (uuid_ref);
  CFRelease (dsym_ref);
}

/* Locate a full path to the dSYM Mach-O file within the dSYM bundle using
   OJBFILE's uuid and the DebugSymbols.framework. The DebugSymbols.framework 
   will used using the current set of global DebugSymbols.framework defaults 
   from com.apple.DebugSymbols.plist.  If a UUID is available and a path to
   a dSYM is returned from the framework, the dSYM bundle contents will be
   searched to find a matching UUID only if the URL returned by the framework
   doesn't fully specify the dSYM Mach-O file. The returned string has been 
   xmalloc()'ed and it is the responsibility of the caller to xfree it. */
static char *
locate_dsym_using_framework (struct objfile *objfile)
{
  CFURLRef dsym_bundle_url = NULL;
  char* dsym_path = NULL;
  CFUUIDRef uuid_ref = get_uuidref_for_bfd (objfile->obfd);
  if (uuid_ref == NULL)
    return NULL;

  /* Use DebugSymbols framework to search for the dSYM.  */
  dsym_bundle_url = DBGCopyDSYMURLForUUID (uuid_ref);
  if (dsym_bundle_url)
    {
      /* Get the path for the URL in 8 bit format.  */
      char path[PATH_MAX];
      path[PATH_MAX-1] = '\0';
      if (CFURLGetFileSystemRepresentation (dsym_bundle_url, 1,
            (UInt8 *)path, sizeof (path)))
        {
          char *dsym_ext = strcasestr (path, dsym_extension);
          /* Check the dsym path to see if it is a full path to a dSYM
             Mach-O file in the dSYM bundle. We do this by checking:
             1 - If there is no dSYM extension in the path
             2 - If the path ends with ".dSYM"
             3 - If the path ends with ".dSYM/"
           */
          int search_bundle_dir = ((dsym_ext == NULL) ||
              (dsym_ext[dsym_extension_len] == '\0') ||
              (dsym_ext[dsym_extension_len] == '/' &&
               dsym_ext[dsym_extension_len+1] == '\0'));

          if (search_bundle_dir)
            {
              dsym_path = locate_dsym_mach_in_bundle (uuid_ref, path);
            }
          else
            {
              /* Don't mess with the path if it was fully specified. PATH
                 should be a full path to the dSYM Mach-O file within the
                 dSYM bundle directory.  */
              dsym_path = xstrdup (path);
            }
        }
      find_source_path_mappings (uuid_ref, dsym_bundle_url);
      CFRelease (dsym_bundle_url);
      dsym_bundle_url = NULL;
    }
  CFRelease (uuid_ref);
  uuid_ref = NULL;
  return dsym_path;
}
#endif

/* Locate a full path to the dSYM Mach-O file within the dSYM bundle given
   OJBFILE. This function will first search in the same directory as the
   executable for OBJFILE, then it will traverse the directory structure
   upwards looking for any dSYM bundles at the bundle level. If no dSYM
   file is found in the parent directories of the executable, then the
   DebugSymbols.framework will used using the current set of global 
   DebugSymbols.framework defaults from com.apple.DebugSymbols.plist.  */

char *
macosx_locate_dsym (struct objfile *objfile)
{
  char *basename_str;
  char *dot_ptr;
  char *slash_ptr;
  char *dsymfile;
  const char *executable_name;

  /* Don't load a dSYM file unless we our load level is set to ALL.  If a
     load level gets raised, then the old objfile will get destroyed and
     it will get rebuilt, and this function will get called again and get
     its chance to locate the dSYM file.  */
  if (objfile->symflags != OBJF_SYM_ALL)
    return NULL;

  /* When we're debugging a kext with dSYM, OBJFILE is the kext syms
     output by kextload (com.apple.IOKitHello.syms), 
     objfile->not_loaded_kext_filename is the name of the kext bundle
     (IOKitHello.kext) and we're going to be looking for IOKitHello.kext.dSYM
     in this function.  */
  if (objfile->not_loaded_kext_filename != NULL)
    executable_name = objfile->not_loaded_kext_filename;
  else
    executable_name = objfile->name;

  /* Make sure the object file name itself doesn't contain ".dSYM" in it or we
     will end up with an infinite loop where after we add a dSYM symbol file,
     it will then enter this function asking if there is a debug file for the
     dSYM file itself.  */
  if (strcasestr (executable_name, ".dSYM") == NULL)
    {
      /* Check for the existence of a .dSYM file for a given executable.  */
      basename_str = basename ((char *) executable_name);
      dsymfile = alloca (strlen (executable_name)
			       + strlen (APPLE_DSYM_EXT_AND_SUBDIRECTORY)
			       + strlen (basename_str)
			       + 1);
      
      /* First try for the dSYM in the same directory as the original file.  */
      strcpy (dsymfile, executable_name);
      strcat (dsymfile, APPLE_DSYM_EXT_AND_SUBDIRECTORY);
      strcat (dsymfile, basename_str);
	  
      if (file_exists_p (dsymfile))
        {
#if USE_DEBUG_SYMBOLS_FRAMEWORK
          find_source_path_mappings_posix (objfile, dsymfile);
#endif
          return xstrdup (dsymfile);
        }
      
      /* Now search for any parent directory that has a '.' in it so we can find
	 Mac OS X applications, bundles, plugins, and any other kinds of files.  
	 Mac OS X application bundles wil have their program in
	 "/some/path/MyApp.app/Contents/MacOS/MyApp" (or replace ".app" with
	 ".bundle" or ".plugin" for other types of bundles).  So we look for any
	 prior '.' character and try appending the apple dSYM extension and 
	 subdirectory and see if we find an existing dSYM file (in the above 
         MyApp example the dSYM would be at either:
	 "/some/path/MyApp.app.dSYM/Contents/Resources/DWARF/MyApp" or
	 "/some/path/MyApp.dSYM/Contents/Resources/DWARF/MyApp".  */
      strcpy (dsymfile, dirname ((char *) executable_name));
      /* Append a directory delimiter so we don't miss shallow bundles that
         have the dSYM appended on like "/some/path/MacApp.app.dSYM" when
	 we start with "/some/path/MyApp.app/MyApp".  */
      strcat (dsymfile, "/");
      while ((dot_ptr = strrchr (dsymfile, '.')))
	{
	  /* Find the directory delimiter that follows the '.' character since
	     we now look for a .dSYM that follows any bundle extension.  */
	  slash_ptr = strchr (dot_ptr, '/');
	  if (slash_ptr)
	    {
	      /* NULL terminate the string at the '/' character and append
	         the path down to the dSYM file.  */
	      *slash_ptr = '\0';
	      strcat (slash_ptr, APPLE_DSYM_EXT_AND_SUBDIRECTORY);
	      strcat (slash_ptr, basename_str);
	      if (file_exists_p (dsymfile))
                {
#if USE_DEBUG_SYMBOLS_FRAMEWORK
                  find_source_path_mappings_posix (objfile, dsymfile);
#endif
		  return xstrdup (dsymfile);
                }
	    }
	    
	  /* NULL terminate the string at the '.' character and append
	     the path down to the dSYM file.  */
	  *dot_ptr = '\0';
	  strcat (dot_ptr, APPLE_DSYM_EXT_AND_SUBDIRECTORY);
	  strcat (dot_ptr, basename_str);
	  if (file_exists_p (dsymfile))
            {
#if USE_DEBUG_SYMBOLS_FRAMEWORK
              find_source_path_mappings_posix (objfile, dsymfile);
#endif
              return xstrdup (dsymfile);
            }

	  /* NULL terminate the string at the '.' locatated by the strrchr() 
             function again.  */
	  *dot_ptr = '\0';

	  /* We found a previous extension '.' character and did not find a 
             dSYM file so now find previous directory delimiter so we don't 
             try multiple times on a file name that may have a version number 
             in it such as "/some/path/MyApp.6.0.4.app".  */
	  slash_ptr = strrchr (dsymfile, '/');
	  if (!slash_ptr)
	    break;
	  /* NULL terminate the string at the previous directory character 
             and search again.  */
	  *slash_ptr = '\0';
	}
#if USE_DEBUG_SYMBOLS_FRAMEWORK
      /* Check to see if configure detected the DebugSymbols framework, and
	 try to use it to locate the dSYM files if it was detected.  */
      if (dsym_locate_enabled)
	return locate_dsym_using_framework (objfile);
#endif
    }
  return NULL;
}

/* Returns 1 if the directory is found.  0 if error or not found.
   Files return 0. */
int
dir_exists_p (const char *dir)
{
  struct stat sb;
  return (stat (dir, &sb) == 0) && S_ISDIR (sb.st_mode);
}

/* Searches a string for a substring.  If the substring is found, the
   string is truncated at the end of the substring, and the string
   is returned.  If the substring is not found, NULL is retuned. */
char *
strtrunc (char *str, const char *substr)
{
  char *match;
  u_long len;

  match = strcasestr (str, substr);
  if (!match)
    return NULL;

  // Try to find the LAST occurrence of substr
  char *best_match = match;
  while (match && *match != '\0' && *(match + 1) != '\0')
    {
      match = strcasestr (match + 1, substr);
      if (match)
        best_match = match;
    }

  len = (best_match - str) + strlen (substr);
  str[len] = '\0';
  return str;
}

/* Retrieve the com.apple.DebugSymbols DBGShellCommands contents.
   I believe this could be an array of commands but gdb is only going to handle the case of a single
   command.  gdb is looking for a plist output from this command which looks something like

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>7FA0D1C5-55E6-3664-AE94-9FE32B426750</key>
	<dict>
.... various other keys like DBGArchitecture and DBGDSYMPath ...
		<key>DBGSymbolRichExecutable</key>
		<string>/tmp/my_unstripped_executable_binary_file</string>
	</dict>
</dict>
</plist>

  gdb uses this when it has a UUID of something in memory and it needs to find a copy of that
  binary on the local filesystem.  The normal DebugSymbols API can only track down dSYMs, not
  locate binaries.  

  If a valid shell command was found, an xmalloc()'ed copy of that shell command is returned.
  The caller is responsible for freeing it.  On failure, NULL is returned.  */

static char *
get_dbg_shell_command ()
{
  CFTypeRef shell_cmd = CFPreferencesCopyAppValue (CFSTR ("DBGShellCommands"), CFSTR ("com.apple.DebugSymbols"));
  if (shell_cmd == NULL || CFGetTypeID (shell_cmd) != CFStringGetTypeID())
    { 
      if (shell_cmd)
        CFRelease (shell_cmd);
      return NULL;
    }

  char shell_cmd_cstr[PATH_MAX];
  if (!CFStringGetCString ((CFStringRef) shell_cmd, shell_cmd_cstr, sizeof (shell_cmd_cstr), kCFStringEncodingUTF8))
    return NULL;
  CFRelease (shell_cmd);

  if (file_exists_p (shell_cmd_cstr))
    return xstrdup (shell_cmd_cstr);
  return NULL;
}


// Given a path to a kext binary, run it through tilde expansion,
// realpath expansion, and return an xmalloc'ed string of the resolved name.
// Caller must free the returned memory.

char *
expand_kext_cstr (const char *kext_path)
{
  char pathbuf[PATH_MAX];

  if (file_exists_p (kext_path))
    return xstrdup (kext_path);

  const char *tilde_expanded_path = tilde_expand (kext_path);
  if (file_exists_p (tilde_expanded_path))
    return xstrdup (tilde_expanded_path);
  strlcpy (pathbuf, tilde_expanded_path, sizeof (pathbuf));

  char real_path[PATH_MAX];
  real_path[0] = '\0';
  if (realpath (kext_path, real_path))
    {
      if (file_exists_p (real_path))
        return xstrdup (real_path);
    }

  return xstrdup (kext_path);
}


/* If we've failed to find the binary in the location specified
   by the dSYM's Info.plist, AND the DebugSymbols framework has a 
   shell command set in its defaults (com.apple.DebugSymbols DBGShellCommands),
   see if we can call the shell command directly to get a
   path to the executable that might work.
  
   DebugSymbols only traffics in finding dSYMs via UUIDs - reflecting what
   we can get from Spotlight.  But the DBGShellCommands may be capable of
   returning additional informatin, such as the location to an unstripped
   executable binary.  We try to use that ability in this function to find
   an executable given a UUID.

   NULL is returned if no binary is found.

   The returned char* is xmalloced by this function; it is the responsibility
   of the caller to free it.  */

char *
macosx_locate_executable_by_dbg_shell_command (CFStringRef uuid)
{
  if (uuid == NULL)
    return NULL;

  char *shell_cmd_cstr = get_dbg_shell_command ();

  if (shell_cmd_cstr == NULL)
    return NULL;

  char uuid_cstr[80];
  if (!CFStringGetCString (uuid, uuid_cstr, sizeof (uuid_cstr), kCFStringEncodingUTF8))
    return NULL;

  char command[PATH_MAX];
  strlcpy (command, shell_cmd_cstr, sizeof (command));
  strlcat (command, " ", sizeof (command));
  strlcat (command, uuid_cstr, sizeof (command));

  int data_buffer_size = 80 * PATH_MAX;
  char *data_buffer = (char *) xmalloc (data_buffer_size);
  data_buffer[0] = '\0';

  FILE *input = popen (command, "r");
  if (input == NULL)
    return NULL;

  char one_line[PATH_MAX];
  while (fgets (one_line, sizeof (one_line), input) != NULL)
    strlcat (data_buffer, one_line, data_buffer_size);
  pclose (input);

  data_buffer[data_buffer_size - 1] = '\0';

  CFDataRef plist_data = CFDataCreate (kCFAllocatorDefault, (const UInt8 *) data_buffer, strlen (data_buffer) + 1);

  if (plist_data == NULL)
    return NULL;

  CFPropertyListRef plist = CFPropertyListCreateWithData (kCFAllocatorDefault, plist_data, kCFPropertyListImmutable, NULL, NULL);

  if (plist == NULL || CFGetTypeID (plist) != CFDictionaryGetTypeID())
    {
      CFRelease (plist_data);
      xfree (data_buffer);
      xfree (shell_cmd_cstr);
      return NULL;
    }

  // Get the dictionary value under the UUID key
  CFDictionaryRef per_arch_kv = CFDictionaryGetValue (plist, uuid);
  if (per_arch_kv == NULL || CFGetTypeID (per_arch_kv) != CFDictionaryGetTypeID())
    {
      CFRelease (plist_data);
      xfree (data_buffer);
      xfree (shell_cmd_cstr);
      return NULL;
    }

  CFStringRef sym_rich_exe = CFDictionaryGetValue (per_arch_kv, CFSTR ("DBGSymbolRichExecutable"));
  if (sym_rich_exe == NULL || CFGetTypeID (sym_rich_exe) != CFStringGetTypeID())
    {
      CFRelease (plist_data);
      xfree (data_buffer);
      xfree (shell_cmd_cstr);
      return NULL;
    }

  char tempbuf[PATH_MAX];
  char *return_path = NULL;
  if (CFStringGetCString ((CFStringRef) sym_rich_exe, tempbuf, sizeof (tempbuf), kCFStringEncodingUTF8))
    return_path = xstrdup (tempbuf);

  CFRelease (plist_data);
  xfree (data_buffer);
  xfree (shell_cmd_cstr);

  char *possibly_expanded_path = expand_kext_cstr (return_path);
  if (possibly_expanded_path != return_path)
    {
      xfree (return_path);
      return_path = possibly_expanded_path;
    }

  return return_path;
}

const CFStringRef kSymbolRichExecutable = CFSTR("DBGSymbolRichExecutable");

/* Given a UUID plist from a dSYM and a UUID, returns the full path to the
   symbol-rich executable described in that plist, or NULL on error. Caller is
   responsible for freeing the returned xmalloc'd filename. */

char *
locate_kext_executable_by_dsym_plist (CFDictionaryRef dsym_info, CFUUIDRef uuid_ref)
{
  CFDictionaryRef uuid_info = NULL;
  CFStringRef kext_path = NULL;
  CFStringRef uuid_string = NULL;
  CFStringRef alt_exe_path = NULL;
  char *path = NULL;

  uuid_string = CFUUIDCreateString(kCFAllocatorDefault, uuid_ref);
  if (!uuid_string)
    {
      warning ("could not convert CFUUIDRef into string");
      goto finish;
    }

  uuid_info = CFDictionaryGetValue(dsym_info, uuid_string);
  if (!uuid_info)
    {
      warning ("could not find UUID key in dSYM Info.plist");
      goto finish;
    }

  kext_path = CFDictionaryGetValue (uuid_info, kSymbolRichExecutable);

  // Try calling dsymForUUID to possibly get a more up-to-date location
  // for the symbol rich executable if looking in the dSYM's Info.plist failed
  if (!kext_path || CFGetTypeID (kext_path) != CFStringGetTypeID())
    {
      char *alt_exe_path = macosx_locate_executable_by_dbg_shell_command (uuid_string);
      if (alt_exe_path)
        {
          CFRelease (uuid_string);
          char *final_path = expand_kext_cstr (alt_exe_path);
          xfree (alt_exe_path);
          return final_path;
        }
    }

  if (!kext_path || CFGetTypeID (kext_path) != CFStringGetTypeID())
    {
      warning ("could not find DBGSymbolRichExecutable key in dSYM Info.plist");
      goto finish;
    }

  char temp_pathbuf[PATH_MAX];
  if (!CFStringGetFileSystemRepresentation (kext_path, temp_pathbuf, sizeof (temp_pathbuf)))
    goto finish;

  path = expand_kext_cstr (temp_pathbuf);

  if (!file_exists_p (path))
    {
      char *alt_exe_path = macosx_locate_executable_by_dbg_shell_command (uuid_string);
      if (alt_exe_path)
        {
          char *expanded_path = expand_kext_cstr (alt_exe_path);
          xfree (alt_exe_path);
          if (file_exists_p (expanded_path))
            {
              if (path)
                xfree (path);
              CFRelease (uuid_string);
              return expanded_path;
            }
          xfree (expanded_path);
        }
    }

  if (!file_exists_p (path))
    {
      warning ("No kext binary found at '%s' from dSYM's Info.plist", path);
    }

finish:
  if (uuid_string) 
    CFRelease (uuid_string);

  return path;
}

/* Given the path to a dSYM, locates a corresponding kext bundle in the same
   directory and returns the full path to the contained kext executable, or
   NULL on error. Caller is responsible for freeing the retuned xmalloc'd
   filename. */

char *
locate_kext_executable_by_dsym_url (CFURLRef dsym_url)
{
  char * result = NULL;
  char path[PATH_MAX];
  const char * identifier_name = NULL;
  const char * exec_name = NULL;
  char * bundle_path = NULL;
  char * tmp;

  if (!CFURLGetFileSystemRepresentation (dsym_url, 1, (UInt8 *) path, sizeof(path)))
    {
      goto finish;
    }

  tmp = strtrunc (path, ".kext");
  if (!tmp)
    {
      goto finish;
    }

  if (!dir_exists_p (path))
    {
      if (*path != '\0')
        warning ("No kext at path '%s'", path);
      goto finish;
    }

  bundle_path = macosx_kext_info (path, &exec_name, &identifier_name);
  if (!bundle_path)
    {
      goto finish;
    }

  strlcat (path, "/Contents/MacOS/", sizeof(path));
  strlcat (path, exec_name, sizeof(path));
  if (!file_exists_p (path))
    {
      strtrunc (path, ".kext");
      strlcat (path, "/", sizeof(path));
      strlcat (path, exec_name, sizeof(path));

      if (!file_exists_p (path))
        {
          goto finish;
        }
    }

  result = xstrdup (path);
finish:
  if (bundle_path) 
    xfree (bundle_path);
  if (exec_name) 
    xfree ((char *) exec_name);
  if (identifier_name) 
    xfree ((char *) identifier_name);

  return result;
}

// We're given the path to a .dSYM bundle for a kext in DSYM_PATH, e.g.
// /tmp/whatever.kext.dSYM
// We look for a kext binary next to that dSYM.  Note that we're not looking
// for a kext BUNDLE next to the dSYM - there are other bits of code that 
// do that.  This is looking for a bare binary.  I'm pretty sure we'll only
// get to this code path when we're doing "add-kext" with a .sym file (so we
// get the UUID out of the .sym, use DebugSymbols framework to find the dSYM
// and try to locate the kext binary next to the dSYM).

// KEXT_UUID is used to verify that we've found the correct binary.

// If we find a matching binary next to the dSYM, an xmalloc'ed string of 
// the file path is returned.  If not, NULL is returned.

static char *
look_for_kext_binary_next_to_dsym (const char *dsym_path, CFUUIDRef kext_uuid)
{
  if (dsym_path == NULL || kext_uuid == NULL || dsym_path[0] == '\0')
    return NULL;

  // does the dsym_path end in ".kext.dSYM" ?
  if (strlen (dsym_path) < 11)
    return NULL;

  char kextpath[PATH_MAX];
  strlcpy (kextpath, dsym_path, sizeof (kextpath));
  if (strcmp (kextpath + strlen (kextpath) - 10, ".kext.dSYM") != 0)
    return NULL;

  // chop off the ".kext.dSYM" part from the pathname
  kextpath[strlen (kextpath) - 10] = '\0';
  if (kextpath[0] == '\0' || !file_exists_p (kextpath))
    return NULL;

  uint8_t uuid[16];
  get_uuid_t_for_uuidref (kext_uuid, &uuid);
  uint8_t **file_uuids = get_binary_file_uuids (kextpath);
  uint8_t **i;

  if (file_uuids == NULL)
    return NULL;

  for (i = file_uuids ; *i != NULL; i++)
    {
      if (memcmp (*i, uuid, sizeof (uuid_t)) == 0)
        {
          free_uuids_array (file_uuids);
          return xstrdup (kextpath);
        }
    }

  free_uuids_array (file_uuids);
  return NULL;
}


/* Given a UUIDRef for a kext, returns the path to the kext's corresponding 
   symbol-rich executable, or NULL on error. 
   KEXT_NAME is the bundle ID, reverse-dns style name, for the kext, used for
   error reporting.
   Caller is responsible for freeing the returned xmalloc'd filename. */

static char *
macosx_locate_kext_executable_by_symfile_helper (CFUUIDRef kext_uuid, 
                                                 const char *kext_name)
{
#if USE_DEBUG_SYMBOLS_FRAMEWORK
  char *result = NULL;
  CFUUIDBytes kext_uuid_bytes;
  CFDictionaryRef dsym_info = NULL;
  CFURLRef dsym_url = NULL;
  char *kext_executable_name = NULL;
  bfd *kext_executable_bfd = NULL;
  CFUUIDRef kext_executable_uuid = NULL;
  CFUUIDBytes kext_executable_uuid_bytes;

  uuid_t uuid;
  get_uuid_t_for_uuidref (kext_uuid, &uuid); // Convert CFUUIDRef to uuid_t

  /* Find the dSYM using the DebugSymbols framework */

  dsym_url = DBGCopyDSYMURLForUUID (kext_uuid);
  if (!dsym_url)
    {
      const char *basep = strrchr (kext_name, '/');
      const char *name = kext_name;
      if (basep && *basep != '\0' && *(basep + 1) != '\0')
        name = ++basep;
      warning ("Can't find dSYM for %s (%s)", name, puuid (uuid));
      goto finish;
    }

  char dsym_path[PATH_MAX];
  if (dsym_url == NULL 
      || CFGetTypeID (dsym_url) != CFURLGetTypeID()
      || !CFURLGetFileSystemRepresentation (dsym_url, 1, (UInt8 *) dsym_path, sizeof (dsym_path)))
    {
      dsym_path[0] = '\0';
    }

  // Before we go searching for the kext binary too far, see if it's sitting next
  // to the dSYM as a bare file (not a bundle).
  char *kext_next_to_dsym = look_for_kext_binary_next_to_dsym (dsym_path, kext_uuid);
  if (file_exists_p (kext_next_to_dsym))
    {
      if (dsym_url) 
        CFRelease (dsym_url);
      return kext_next_to_dsym;
    }

  /* We have two ways to find the kext bundle:
   *   1) A plist in the dSYM will give us a path
   *   2) If that plist doesn't exist, look for a kext nearby
   */

  // This returns the Info.plist in the .dSYM bundle parsed into a CFDictionary
  dsym_info = DBGCopyDSYMPropertyLists (dsym_url);
  if (dsym_info)
    {
      kext_executable_name = locate_kext_executable_by_dsym_plist (dsym_info, kext_uuid);
    }
  else
    {
      kext_executable_name = locate_kext_executable_by_dsym_url (dsym_url);
    }
  if (!kext_executable_name) 
    {
      char path[PATH_MAX];
      // print a specific warning message if we have a dSYM pathname
      if (CFURLGetFileSystemRepresentation (dsym_url, 1, (UInt8 *) path, sizeof (path)))
        {
          path[sizeof (path) - 1] = '\0';
          warning ("Unable to locate symbol-rich-executable for dSYM at %s (%s)",
                    path, puuid (uuid));
        }
      goto finish;
    }

  if (!file_exists_p (kext_executable_name))
    {
      warning ("The needed symbol-rich-executable at '%s' does not exist.",
               kext_executable_name);
      goto finish;
    }

  /* Ensure the symfile's UUID matches the symbol-rich executable's */

  kext_executable_bfd = symfile_bfd_open (kext_executable_name, 0, GDB_OSABI_UNKNOWN);
  if (!kext_executable_bfd) 
    {
      warning ("Unable to open symbol-rich-executable for reading at '%s'.", 
               kext_executable_name);
      goto finish;
    }

  kext_executable_uuid = get_uuidref_for_bfd (kext_executable_bfd);
  if (!kext_executable_uuid) 
    goto finish;

  kext_uuid_bytes = CFUUIDGetUUIDBytes (kext_uuid);
  kext_executable_uuid_bytes = CFUUIDGetUUIDBytes (kext_executable_uuid);
  if (memcmp (&kext_uuid_bytes, &kext_executable_uuid_bytes,
              sizeof (CFUUIDBytes)))
    {
      goto finish;
    }

  result = kext_executable_name;
  kext_executable_name = NULL;
finish:
  if (dsym_url) 
    CFRelease (dsym_url);
  if (dsym_info) 
    CFRelease (dsym_info);

  if (kext_executable_name) 
    xfree (kext_executable_name);
  if (kext_executable_bfd) 
    bfd_close (kext_executable_bfd);
  if (kext_executable_uuid) 
    CFRelease (kext_executable_uuid);

  return result;
#else
  warning("DebugSymbols framework unavailable.  Can't locate kext bundle and dSYM.");
  return NULL;
#endif
}

/* Given a kextutil- or kextcache-generated .sym file, returns the path to the
   kext's corresponding symbol-rich executable, or NULL on error. Caller is
   responsible for freeing the returned xmalloc'd filename. */

char *
macosx_locate_kext_executable_by_symfile (bfd *abfd)
{
  if (abfd == NULL)
    return NULL;
  CFUUIDRef symfile_uuid = get_uuidref_for_bfd (abfd);
  if (symfile_uuid == NULL) 
    return NULL;

  char *ret;
  ret = macosx_locate_kext_executable_by_symfile_helper (symfile_uuid, 
                                                         abfd->filename);
  CFRelease (symfile_uuid);
  return ret;
}

struct objfile *
macosx_find_objfile_matching_dsym_in_bundle (char *dsym_bundle_path, char **out_full_path)
{
  CFMutableDictionaryRef paths_and_uuids;
  struct search_baton results;
  struct objfile *objfile;
  struct objfile *out_objfile = NULL;

  paths_and_uuids = create_dsym_uuids_for_path (dsym_bundle_path);
  if (paths_and_uuids == NULL)
    return NULL;

  results.found_it = 0;
  *out_full_path = NULL;

  ALL_OBJFILES (objfile)
  {
    /* Extract the UUID from the objfile.  */
    CFUUIDRef uuid_ref = get_uuidref_for_bfd (objfile->obfd);
    if (uuid_ref == NULL)
      continue;
    results.test_uuid = uuid_ref;
    CFDictionaryApplyFunction (paths_and_uuids, paths_and_uuids_map_func,
        &results);
    CFRelease (uuid_ref);

    if (results.found_it)
    {
      *out_full_path = xmalloc (PATH_MAX);
      *(*out_full_path) = '\0';
      if (CFURLGetFileSystemRepresentation (results.path_url, 1,
            (UInt8 *) (*out_full_path), PATH_MAX - 1))
        {
          out_objfile = objfile;
        }
      else
        {
          warning ("Could not get file system representation for URL:");
          CFShow (results.path_url);
          *out_full_path = NULL;
          out_objfile = NULL;
        }
      CFRelease (results.path_url);
      goto cleanup_and_return;

    }
  }
cleanup_and_return:
  CFRelease (paths_and_uuids);
  return out_objfile;
}

/* Given a path to a kext bundle look in the Info.plist and retrieve
   the CFBundleExecutable (the name of the kext bundle executable) and
   the CFBundleIdentifier (the thing that kextload -s/-a outputs).  
   Returns the canonicalized path to the kext bundle top-level directory.

   For instance, given a FILENAME of
       /tmp/DummySysctl/build/Debug/DummySysctl.kext/Contents/MacOS/DummySysctl

   BUNDLE_EXECUTABLE_NAME_FROM_PLIST will be set to DummySysctl
   BUNDLE_IDENTIFIER_NAME_FROM_PLIST will be set to com.osxbook.kext.DummySysctl
   and the value /tmp/DummySysctl/build/Debug/DummySysctl.kext will be returned.

   All three strings have been xmalloc()'ed, it is the caller's responsibility
   to xfree them.  */

char *
macosx_kext_info (const char *filename, 
                  const char **bundle_executable_name_from_plist,
                  const char **bundle_identifier_name_from_plist)
{
  char *info_plist_name;
  char *t;
  *bundle_executable_name_from_plist = NULL;
  *bundle_identifier_name_from_plist = NULL;
  const void *plist = NULL;

  info_plist_name = find_info_plist_filename_from_bundle_name 
                                                      (filename, ".kext");
  if (info_plist_name == NULL)
    return NULL;

  plist = macosx_parse_plist (info_plist_name);

  *bundle_executable_name_from_plist = macosx_get_plist_posix_value (plist, 
						      "CFBundleExecutable");
  *bundle_identifier_name_from_plist = macosx_get_plist_string_value (plist, 
						      "CFBundleIdentifier");
  macosx_free_plist (&plist);
  
  /* Was there a /Contents directory in the bundle?  */
  t = strstr (info_plist_name, "/Contents");
  if (t != NULL)
    t[0] = '\0';
  
  /* Or is it a flat bundle with the Info.plist at the top level?  */
  t = strstr (info_plist_name, "/Info.plist");
  if (t != NULL)
    t[0] = '\0';

  if (*bundle_executable_name_from_plist == NULL
      || *bundle_identifier_name_from_plist == NULL)
    return NULL;
  else
    return info_plist_name;
}

/* Given a BUNDLE from the user such as
    /a/b/c/Foo.app
    /a/b/c/Foo.app/
    /a/b/c/Foo.app/Contents/MacOS/Foo
   (for BUNDLE_SUFFIX of ".app") return the string
    /a/b/c/Foo.app/Contents/Info.plist
   The return string has been xmalloc()'ed; it is the caller's
   responsibility to free it.  */

static char *
find_info_plist_filename_from_bundle_name (const char *bundle, 
                                           const char *bundle_suffix)
{
  char *t;
  char *bundle_copy;
  char tmp_path[PATH_MAX];
  char realpath_buf[PATH_MAX];
  char *retval = NULL;
   
  /* Make a local copy of BUNDLE so it may be modified below.  */
  bundle_copy = tilde_expand (bundle);
  tmp_path[0] = '\0';

  /* Is BUNDLE in the form "/a/b/c/Foo.kext/Contents/MacOS/Foo"?  */
  t = strstr (bundle_copy, bundle_suffix);

  // Find the last possible ".kext" or ".app" in the path
  char *best_t = t;
  while (t)
    {
      t = strstr (t + 1, bundle_suffix);
      if (t)
        best_t = t;
    }
  t = best_t;

  if (t != NULL && t > bundle_copy)
    {
      t += strlen (bundle_suffix);
      /* Do we have a / character after the bundle suffix?  */
      if (t[0] == '/')
        {
          strncpy (tmp_path, bundle_copy, t - bundle_copy);
          tmp_path[t - bundle_copy] = '\0';
        }
    }

   /* Is BUNDLE in the form "/a/b/c/Foo.kext"?  */
   t = strstr (bundle_copy, bundle_suffix);

  // Find the last possible ".kext" or ".app" in the path
   best_t = t;
   while (t)
     {
       t = strstr (t + 1, bundle_suffix);
       if (t)
         best_t = t;
     }
   t = best_t;

   if (t != NULL && t > bundle_copy && t[strlen (bundle_suffix)] == '\0')
     {
          strcpy (tmp_path, bundle_copy);
     }

   if (tmp_path[0] == '\0')
     {
       if (bundle && *bundle != '\0')
         warning ("No Info.plist found under %s", bundle);
       return NULL;
     }

   /* Now let's find the Info.plist in the bundle.  */

   strcpy (realpath_buf, tmp_path);
   strcat (realpath_buf, "/Contents/Info.plist");
   if (file_exists_p (realpath_buf))
     {
       retval = realpath_buf;
     }
   else
     {
       strcpy (realpath_buf, tmp_path);
       strcat (realpath_buf, "/Info.plist");
       if (file_exists_p (realpath_buf))
         {
           retval = realpath_buf;
         }
     }

   if (retval == NULL)
     {
       if (*tmp_path != '\0')
         warning ("No Info.plist found under %s", tmp_path);
       return retval;
     }

   tmp_path[0] = '\0';  /* Not necessary; just to make it clear. */

    if (realpath (realpath_buf, tmp_path) == NULL)
        retval = xstrdup (realpath_buf);
    else
        retval = xstrdup (tmp_path);

   xfree (bundle_copy);
  return retval;
}

/* FIXME: We shouldn't be grabbing internal functions from bfd!  It's
 used in both the osabi sniffers.  */
extern const bfd_arch_info_type *bfd_default_compatible
  (const bfd_arch_info_type *a, const bfd_arch_info_type *b);

/* If we're attaching to a process, we start by finding the dyld that
   is loaded and go from there.  So when we're selecting the OSABI,
   prefer the osabi of the actually-loaded dyld when we can.  

   That's what this function implements, but it does it in a somewhat
   roundabout way.  What this really does is this:

   1) If we haven't seen a dyld loaded into a running program yet,
   it returns GDB_OSABI_UNKNOWN.
   2) If you give it a bfd_object file it returns GDB_OSABI_UNKNOWN.
   3) If you give it a mach-o-fat file, it will return osabi_seen_in_attached_dyld
   if that architecture exists in the fat file, otherwise it will return 
   GDB_OSABI_UNKNOWN.

   The sniffer code gets asked two questions - generically what architecture
   do you think we are - where we usually get handed the fat file, and we see
   if it matches what either what DYLD told us or what we guessed from the
   system & the executable file.  That's the job of this function.
   The sniffer also gets asked whether a bfd_object (usually one fork of the
   fat file) is the one that we want.  This function doesn't do that, and
   instead the code in generic_mach_o_osabi_sniffer_use_dyld does that job.
   So this function really only looks at fat archives.

*/

static enum gdb_osabi
generic_mach_o_osabi_sniffer_use_dyld_hint (bfd *abfd,
					    enum bfd_architecture arch,
					    unsigned long mach_32,
					    unsigned long mach_64)
{
  if (osabi_seen_in_attached_dyld == GDB_OSABI_UNKNOWN)
    return GDB_OSABI_UNKNOWN;

  bfd *nbfd = NULL;

  for (;;)
    {
      nbfd = bfd_openr_next_archived_file (abfd, nbfd);

      if (nbfd == NULL)
        break;

      /* We don't deal with FAT archives here.  So just skip it if we were
         handed a fat archive.  */
      if (bfd_check_format (nbfd, bfd_archive))
        return GDB_OSABI_UNKNOWN;

      if (!bfd_check_format (nbfd, bfd_object))
        continue;
      if (bfd_default_compatible (bfd_get_arch_info (nbfd),
                                  bfd_lookup_arch (arch,
                                                   mach_64))
          && osabi_seen_in_attached_dyld == GDB_OSABI_DARWIN64)
        return GDB_OSABI_DARWIN64;

      else if (bfd_default_compatible (bfd_get_arch_info (nbfd),
                                  bfd_lookup_arch (arch,
                                                   mach_32))
          && osabi_seen_in_attached_dyld == GDB_OSABI_DARWIN)
        return GDB_OSABI_DARWIN;

    }

  return GDB_OSABI_UNKNOWN;
}

enum gdb_osabi
generic_mach_o_osabi_sniffer (bfd *abfd, enum bfd_architecture arch, 
			      unsigned long mach_32,
			      unsigned long mach_64,
			      int (*query_64_bit_fn) ())
{
  enum gdb_osabi ret;
  ret = generic_mach_o_osabi_sniffer_use_dyld_hint (abfd, arch, mach_32, mach_64);

  if (ret == GDB_OSABI_DARWIN64 || ret == GDB_OSABI_DARWIN)
    return ret;

 if (bfd_check_format (abfd, bfd_archive))
    {
      bfd *nbfd = NULL;
      /* For a fat archive, look up each component and see which
	 architecture best matches the current architecture.  */
      if (strcmp (bfd_get_target (abfd), "mach-o-fat") == 0)
	{
	  enum gdb_osabi best = GDB_OSABI_UNKNOWN;
	  enum gdb_osabi cur = GDB_OSABI_UNKNOWN;
	  
	  for (;;)
	    {
	      nbfd = bfd_openr_next_archived_file (abfd, nbfd);

	      if (nbfd == NULL)
		break;
	      /* We can check the architecture of objects, and
		 "ar" archives.  Do that here.  */

	      if (!bfd_check_format (nbfd, bfd_object) 
		  && !bfd_check_format (nbfd, bfd_archive))
		continue;
	      
	      cur = generic_mach_o_osabi_sniffer (nbfd, arch,
						  mach_32, mach_64, 
						  query_64_bit_fn);
	      if (cur == GDB_OSABI_DARWIN64 &&
		  best != GDB_OSABI_DARWIN64 && query_64_bit_fn ())
		best = cur;
	      
	      if (cur == GDB_OSABI_DARWIN
		  && best != GDB_OSABI_DARWIN64 
		  && best != GDB_OSABI_DARWIN)
		best = cur;
	    }
	  return best;
	}
      else
	{
	  /* For an "ar" archive, look at the first object element
	     (there's an initial element in the archive that's not a
	     bfd_object, so we have to skip over that.)  And return
	     the architecture from that.  N.B. We can't close the
	     files we open here since the BFD archive code caches
	     them, and there's no way to get them out of the cache
	     without closing the whole archive.  */
	  for (;;)
	    {
	      nbfd = bfd_openr_next_archived_file (abfd, nbfd);
	      if (nbfd == NULL)
		break;
	      if (!bfd_check_format (nbfd, bfd_object))
		continue;
	      
	      /* .a files have to be homogenous, so return the result
	         for the first file.  */

	      return generic_mach_o_osabi_sniffer (nbfd, arch, 
						   mach_32, mach_64, 
						   query_64_bit_fn);
	    }
	}
    }

  if (!bfd_check_format (abfd, bfd_object))
    return GDB_OSABI_UNKNOWN;

  if (bfd_get_arch (abfd) == arch)
    {
      if (bfd_default_compatible (bfd_get_arch_info (abfd),
                                  bfd_lookup_arch (arch,
                                                   mach_64)))
        return GDB_OSABI_DARWIN64;

	  if (bfd_default_compatible (bfd_get_arch_info (abfd),
                                  bfd_lookup_arch (arch,
                                                   mach_32)))
        return GDB_OSABI_DARWIN;

      return GDB_OSABI_UNKNOWN;
    }

  return GDB_OSABI_UNKNOWN;

}

/* This is the common bit of the fast show stack trace.  Here we look
   up the sigtramp start & end, and use the regular backtracer to skip
   over the first few frames, which is the hard bit anyway.  Fills
   COUNT with the number of frames consumed, sets OUT_FI to the last
   frame we read.  Returns 1 if there's more to backtrace, and 0 if we
   are done, and -1 if there was an error.  Note, this is separate
   from COUNT, since you can reach main before you exceed
   COUNT_LIMIT.*/

int
fast_show_stack_trace_prologue (unsigned int count_limit, 
				unsigned int print_start,
				unsigned int print_end,
				unsigned int wordsize,
				CORE_ADDR *sigtramp_start_ptr,
				CORE_ADDR *sigtramp_end_ptr,
				unsigned int *count,
				struct frame_info **out_fi,
				void (print_fun) (struct ui_out * uiout, int *frame_num,
						  CORE_ADDR pc, CORE_ADDR fp))
{
  ULONGEST pc = 0;
  struct frame_id selected_frame_id;
  struct frame_info *selected_frame;

  if (*sigtramp_start_ptr == 0)
    {
      char *name;
      struct minimal_symbol *msymbol;
      struct objfile *ofile;
      struct objfile *temp;

      /* Some environments use a "shim" libSystem that patches some functions.
         So we need to search all libraries calling themselves libSystem for the
         sigtramp function.  I am still going to assume that only one of them
         actually implements sigtramp, however.  If that ever changes, we'll have to
         revise this...  */

      ALL_OBJFILES_SAFE (ofile, temp)
        {
          struct objfile *libsystem_objfile = NULL;

	  if (ofile->name == NULL 
	      || (strstr (ofile->name, "libSystem.B.dylib") == NULL
		  && strstr (ofile->name, "/usr/lib/system") != ofile->name))
	    continue;

          /* APPLE LOCAL - Check to see if the libSystem objfile has a
             separate debug info objfile */
          if (ofile->msymbols == NULL
              && ofile->separate_debug_objfile_backlink)
            libsystem_objfile = ofile->separate_debug_objfile_backlink;
          else
            libsystem_objfile = ofile;

          /* If libSystem isn't loaded yet, NULL it out so we don't look up 
             and cache incorrect un-slid or faux-slid address values.  */
          if (!target_check_is_objfile_loaded (libsystem_objfile))
            continue;
      
          /* If we have libSystem and it was loaded we should lookup sigtramp.  */
          /* Raise the load level and lookup the sigtramp symbol.  */
          objfile_set_load_state (libsystem_objfile, OBJF_SYM_ALL, 1);
          msymbol = lookup_minimal_symbol ("_sigtramp", NULL, libsystem_objfile);

          if (msymbol != NULL)
            {
              /* Shared libraries must be loaded for the code below to work since
                 we are getting the MSYMBOL value, then using that to look the
                 sigtramp range. If shared libraries aren't loaded, we could end
                 up getting and un-slid or faux-slid value that we will then try
                 and get the function bounds for which could return us the range
                 for a totally different function.  */
              pc = SYMBOL_VALUE_ADDRESS (msymbol);

              /* Warn if this is the second sigtramp we've found.  */
              if (*sigtramp_start_ptr != 0 && *sigtramp_start_ptr != (CORE_ADDR) -1)
                {
                  warning ("Found two versions of sigtramp, one at 0x%s and one at 0x%s."
                           "  Using the latter.",
                           paddr_nz (*sigtramp_start_ptr), paddr_nz (pc));
                }

              if (find_pc_partial_function (pc, &name, sigtramp_start_ptr, 
                                            sigtramp_end_ptr) == 0)
                {
                  warning
                    ("Couldn't find minimal bounds for \"_sigtramp\" - "
                     "backtraces may be unreliable");
                  *sigtramp_start_ptr = (CORE_ADDR) -1;
                  *sigtramp_end_ptr = (CORE_ADDR) -1;
                }
              else
                  break;
            }
        }
    }

  /* I call flush_cached_frames here before we start doing the
     backtrace.  You usually only call stack-list-frames-lite 
     (the parent of this) right when you've stopped.  But you may
     needed to raise the load level of the bottom-most frame to 
     get the backtrace right, and if you've done something like
     called a function before doing the backtrace, the bottom-most
     frame could have inaccurate data.  For instance, I've seen
     a case where the func for the bottom frame was errantly
     given as _start because there were no external symbols
     between the real function and _start...  This will set
     us back straight, and then we can do the backtrace accurately
     from here.  */
  /* Watch out, though.  flush_cached_frames unsets the currently
     selected frame.  So we need to restore that.  */
  selected_frame_id = get_frame_id (get_selected_frame (NULL));

  flush_cached_frames ();

  selected_frame = frame_find_by_id (selected_frame_id);
  if (selected_frame == NULL)
    select_frame (get_current_frame ());
  else
    select_frame (selected_frame);

  /* I have to do this twice because I want to make sure that if
     any of the early backtraces causes the load level of a library
     to be raised, I flush the current frame set & start over.  
     But I can't figure out how to flush the accumulated ui_out
     content and start afresh if this happens.  If we could
     make this an mi-only command, I could, but there isn't a
     way to do that generically.  You can redirect the output
     in the cli case, but you can't stuff the stream that you've
     gathered the new output to down the current ui_out.  You can
     do that with mi_out_put, but that's not a generic command.  
     This looks stupid, but shouldn't be all that inefficient.  */

  actually_do_stack_frame_prologue (count_limit, 
				    print_start,
				    print_end,
				    wordsize,
				    count,
				    out_fi,
				    NULL);

  return actually_do_stack_frame_prologue (count_limit,
					   print_start,
					   print_end,
					   wordsize,
					   count,
					   out_fi,
					   print_fun);

}


int
actually_do_stack_frame_prologue (unsigned int count_limit, 
				unsigned int print_start,
				unsigned int print_end,
				unsigned int wordsize,
				unsigned int *count,
				struct frame_info **out_fi,
				void (print_fun) (struct ui_out * uiout, int *frame_num,
						  CORE_ADDR pc, CORE_ADDR fp))
{
  CORE_ADDR fp;
  ULONGEST pc;
  struct frame_info *fi = NULL;
  int more_frames;
  int old_load_state;
  
  /* Get the first few frames.  If anything funky is going on, it will
     be here.  The second frame helps us get above frameless functions
     called from signal handlers.  Above these frames we have to deal
     with sigtramps and alloca frames, that is about all. */

 start_again:
  if (print_fun)
    ui_out_begin (uiout, ui_out_type_list, "frames");

  more_frames = 1;
  pc = 0;

  fi = get_current_frame ();
  if (fi == NULL)
    {
      more_frames = -1;
      goto count_finish;
    }

  /* Sometimes we can backtrace more accurately when we read in
     debug information.  So let's do that here for the first frame.  */

  old_load_state = pc_set_load_state (get_frame_pc (fi), OBJF_SYM_ALL, 0);
  if (old_load_state >= 0 && old_load_state != OBJF_SYM_ALL && print_fun == NULL)
    {
      flush_cached_frames ();
      goto start_again;
    }

  int frames_printed = 0;

  // Print the first frame (and any inlined frames that may be at this point)
  if (print_fun && 0 >= print_start && 0 < print_end)
    print_fun (uiout, &frames_printed, get_frame_pc (fi), get_frame_base (fi));

  /* if print_fun() listed inlined function psuedo-frames, "frames_printed" will
     be incremented from its initial value (always 0 here). e.g.
     frames_printed == 0, we printed one concrete frame
     frames_printed == 1, we printed a concrete frame plus an inlined frame.  */

  frames_printed++;
  if (frames_printed > 1)
    {
      /* In this case, we must have found and printed out some inlined
         frames already.  Therefore, we need to bring 'fi' up to our
         currently printed frame location, then increment i and
         proceed into the loop (if we're not already done). */
      int j;
      for (j = 0; j < (frames_printed - 1) && fi != NULL; j++)
        fi = get_prev_frame (fi);

      // At the top of the stack?  Then we're done here.
      if (fi == NULL)
        {
          more_frames = 0;
          goto count_finish;
        }
    }
  
  do
    {
      if (frames_printed >= count_limit)
	{
	  more_frames = 0;
	  goto count_finish;
	}

      fi = get_prev_frame (fi);
      if (fi == NULL)
	{
	  more_frames = 0;
	  goto count_finish;
	}

      pc = get_frame_pc (fi);
      fp = get_frame_base (fi);

  /* Sometimes we can backtrace more accurately when we read
     in debug information.  So let's do that here.  */

      old_load_state = pc_set_load_state (pc, OBJF_SYM_ALL, 0);
      if (old_load_state >= 0 && old_load_state != OBJF_SYM_ALL && print_fun == NULL)
	{
	  flush_cached_frames ();
	  goto start_again;
	}

      if (print_fun && frames_printed >= print_start && frames_printed < print_end)
        print_fun (uiout, &frames_printed, pc, fp);
      frames_printed++;

      /* If we printed out multiple frames (because of inlining) then we
         need to update fi appropriately)  */

      int j;
      for (j = frame_relative_level (fi); j < (frames_printed - 1) && fi != NULL; j++)
        fi = get_prev_frame (fi);

      if (fi == NULL)
        {
          more_frames = 0;
          goto count_finish;
        }

      if (!backtrace_past_main 
          && inside_main_func (fi)
	  && get_frame_type (fi) != INLINED_FRAME)
	{
	  more_frames = 0;
	  goto count_finish;
	}
    }
  while (frames_printed < 5);

 count_finish:
  *out_fi = fi;
  *count = frames_printed;
  return more_frames;
}

struct loaded_kext_info {
  char     name[KMOD_MAX_NAME];
  uuid_t   uuid;
  uint64_t address;
};

struct loaded_kexts_table {
  uint32_t  version;
  uint32_t  entry_size;          // the size of the OSKextLoadedKextSummary struct
  uint32_t  count;
  struct loaded_kext_info *kexts;
};

struct loaded_kexts_table *
get_list_of_loaded_kexts ()
{
  struct loaded_kexts_table *kext_table;
  ULONGEST val;
  struct minimal_symbol *msym = lookup_minimal_symbol ("gLoadedKextSummaries", NULL, NULL);
  if (msym == NULL)
    return NULL;

  // gLoadedKextSummaries points to a 
  // OSKextLoadedKextSummaryHeader structure.
  if (!safe_read_memory_unsigned_integer (SYMBOL_VALUE_ADDRESS (msym), TARGET_PTR_BIT / 8, &val))
    return NULL;

  if (val == 0)
    error ("gLoadedKextSummaries has an address of 0x0 - you must be attached to a live kernel or debugging with a core file.");

  kext_table = (struct loaded_kexts_table*) xmalloc (sizeof (struct loaded_kexts_table));
  if (kext_table == NULL)
    return NULL;

  // p has the address of the OSKextLoadedKextSummaryHeader struct.
  CORE_ADDR p = val;

  // Read the uint32_t version field
  if (!safe_read_memory_unsigned_integer (p, 4, &val))
    {
      xfree (kext_table);
      return NULL;
    }
  kext_table->version = (uint32_t) val;
  p += sizeof (uint32_t);

  // version 1 does not include an entry_size field.
  // versions 2 and later do.
  if (kext_table->version == 1)
    {
      // The version 1 OSKextLoadedKextSummary struct was
      // 64 + 16 + 8 + 8 + 8 + 4 + 4
      kext_table->entry_size = 112;
    }
  else
    {
      if (!safe_read_memory_unsigned_integer (p, 4, &val))
        {
          xfree (kext_table);
          return NULL;
        }
      kext_table->entry_size = (uint32_t) val;
      p += sizeof (uint32_t);
    }

  // Read the uint32_t kext count field
  if (!safe_read_memory_unsigned_integer (p, 4, &val))
    {
      xfree (kext_table);
      return NULL;
    }
  kext_table->count = (uint32_t) val;
  p += sizeof (uint32_t);

  
  // Skip a 4-byte reserved field on v2-and-later tables.
  if (kext_table->version > 1)
    p += sizeof (uint32_t);

  // quick sanity check on the off chance we're looking at uninitialized
  // memory - don't do anything crazy.
  if (kext_table->count == 0 || kext_table->count > 65535)
    return NULL;

  uint8_t *tmpbuf = (uint8_t*) xmalloc (kext_table->entry_size * kext_table->count);
  kext_table->kexts = (struct loaded_kext_info *) xmalloc 
                (sizeof (struct loaded_kext_info) * kext_table->count);

  if (kext_table->kexts == NULL || tmpbuf == NULL)
    {
      xfree (kext_table);
      xfree (tmpbuf);
      error ("Unable to allocate space to load kext infos.");
    }

  // Read the kext entries from kernel memory into TMPBUF.
  if (target_read_memory (p, (uint8_t *) tmpbuf, 
                        kext_table->entry_size * kext_table->count))
    {
      xfree (tmpbuf);
      xfree (kext_table->kexts);
      xfree (kext_table);
      error ("Unable to read kext infos from kernel.");
    }

  // Copy the fields we care about (swapping as we go) into our internal
  // representation.

  uint8_t *raw_kext_p = tmpbuf;
  int i;
  for (i = 0; i < kext_table->count; i++)
    {
      uint8_t *start_of_kext_entry = raw_kext_p;

      strlcpy ((char *) kext_table->kexts[i].name, (char *) raw_kext_p, KMOD_MAX_NAME);
      raw_kext_p += KMOD_MAX_NAME;

      memcpy (kext_table->kexts[i].uuid, raw_kext_p, sizeof (uuid_t));
      raw_kext_p += sizeof (uuid_t);

      kext_table->kexts[i].address = (uint64_t) extract_unsigned_integer (raw_kext_p, 8);

      raw_kext_p = start_of_kext_entry + kext_table->entry_size;
    }
  xfree (tmpbuf);

  return kext_table;
}

void
free_list_of_loaded_kexts (struct loaded_kexts_table *lks)
{
  if (lks && lks->kexts)
    xfree (lks->kexts);
  if (lks)
    xfree (lks);
}

/* Given the address of a Mach-O file header in memory, iterate over
   all of the load commands and use their addresses to create a 
   section_addr_info structure.

   The caller is responsible for freeing the section_addr_info returned;
   best done via a call to free_section_addr_info().

   Returns NULL if there was a problem or no matching kext was found. */

struct section_addr_info *
get_section_addresses_for_macho_in_memory (CORE_ADDR mh_addr)
{
  struct section_addr_info *addrs = NULL;
  if (!get_information_about_macho (NULL, mh_addr, NULL, 0, 1, NULL, NULL, NULL, NULL, NULL, &addrs))
    return NULL;
  return addrs;
}

/* Open a Mach-O file on disk, find the section addresses, return a filled in 
   section_addr_info.  It is the responsibility of the caller to free the 
   returned section addr's via free_section_addr_info().  
   NULL is returned if thee was a problem.  */

struct section_addr_info *
get_section_addrs_of_macho_on_disk (const char *filename)
{
  struct section_addr_info *addrs;
  if (!get_information_about_macho (filename, 0, NULL, 0, 0, NULL, NULL, NULL, NULL, NULL, &addrs))
    addrs = NULL;

  return addrs;
}


struct section_addr_info *
get_section_addresses_for_bfd (bfd *abfd)
{
  struct bfd_section *sect;
  int section_count = 0;
  for (sect = abfd->sections; sect; sect = sect->next)
    if (sect->name)
      section_count++;

  struct section_addr_info *sect_addrs = alloc_section_addr_info (section_count);
  sect_addrs->num_sections = section_count;
  sect_addrs->addrs_are_offsets = 0;

  int sectnum = 0;
  for (sect = abfd->sections; sect; sect = sect->next)
    {
      sect_addrs->other[sectnum].sectindex = sect->index;
      sect_addrs->other[sectnum].name = xstrdup (sect->name);
      sect_addrs->other[sectnum].addr = sect->vma;
      sectnum++;
    }

  return sect_addrs;
}

/* Open a Mach-O file on disk, find the intended load address (where the __TEXT segment
   will load aka where the Mach-O header will be in memory assuming no slide happens),
   return that address.
   OSABI may be set to a specific slice to disambiguate; set to GDB_OSABI_UNKNOWN if
   nothing more specific is known.
   Returns the __TEXT segment address or INVALID_ADDRESS if there was an error. */

CORE_ADDR
get_load_addr_of_macho_on_disk (const char *filename, enum gdb_osabi osabi)
{
  if (filename == NULL || filename[0] == '\0' || !file_exists_p (filename))
    return INVALID_ADDRESS;

  bfd *abfd = symfile_bfd_open_safe (filename, 0, osabi);
  if (abfd == NULL)
    return INVALID_ADDRESS;

  CORE_ADDR addr = INVALID_ADDRESS;

  if (!get_information_about_macho (NULL, 0, abfd, 0, 0, NULL, NULL, NULL, &addr, NULL, NULL))
    addr = INVALID_ADDRESS;

  bfd_close (abfd);

  return addr;
}

/* Given the address of a Mach-O file in memory (or alternatively, an already-open bfd pointer),
   find the UUID and/or OSABI of that image.  If a BFD is provided, the address is not needed.

   The input file can be specified in one of three ways:

    FILENAME input - file on local system to be opened, inspected, closed (NULL == no filename)
    MH_ADDR  input - address of memory we're interested in, if a BFD is not provided (INVALID_ADDRESS == no address)
    ABFD     input - already-opened BFD to use, if provided (NULL == no pre-existing bfd)

    REQUIRE_KERNEL input - if 1, the Mach-O must be for a kernel, 0 if any Mach-O is acceptable
    FORCE_LIVE_MEMORY_READS input - if 1 (and no BFD is provided), don't read out of 
                               symbol files/already-open BFD's, force reading out of live memory/corefile

   The following pieces of information can be retrieved about the file:

    UUID     output optional - if non-NULL, the memory pointed to will have the UUID copied in to it
    OSABI    output optional - if non-NULL, the osabi of the BFD will be copied in to it
    WORDSIZE output optional - if non-NULL, set to the the wordsize (4 or 8) of the binary
    INTENDED_LOAD_ADDRESS output optional - if non-NULL, the addr where this Mach-O's __TEXT seg was set to load
    SLIDE    output optional - if non-NULL, set to the slide that was applied to this Mach-O's __TEXT seg
    ADDRS    output optional - if non-NULL, is set to a pointer to a struct section_addr_info which describes
                               the load addresses of every section of the Mach-O image.  The memory allocated
                               here should be freed via free_section_addr_info().

    returns 1 if successful, UUID/OSABI/WORDSIZE/etc have been filled in
    returns 0 if there was a problem.  */

int
get_information_about_macho (const char *filename, CORE_ADDR mh_addr, bfd *abfd, 
                             int require_kernel, int force_live_memory_reads,
                             uuid_t *uuid, enum gdb_osabi *osabi, 
                             int *wordsize, CORE_ADDR *intended_load_address, CORE_ADDR *slide,
                             struct section_addr_info **addrs)
{
  bfd *mem_bfd = NULL;
  struct cleanup *bfd_cleanups = make_cleanup (null_cleanup, NULL);
  struct mach_header h;

  if (mh_addr == 0)
    mh_addr = INVALID_ADDRESS;

  int file_exists = file_exists_p (filename);

  if (file_exists == 0
      && mh_addr == INVALID_ADDRESS
      && abfd == NULL)
    {
      return 0;
    }

  // If we're called with multiple mach-o file methods specified, eliminate one of the extras
  if (file_exists && (mh_addr != INVALID_ADDRESS || abfd != NULL))
    {
      filename = NULL;
      file_exists = 0;
    }
  if (mh_addr != INVALID_ADDRESS && abfd != NULL)
    {
      mh_addr = INVALID_ADDRESS;
    }
      

  if (file_exists)
    {
      abfd = symfile_bfd_open_safe (filename, 0, gdbarch_osabi (current_gdbarch));
      if (abfd == NULL)
        return 0;
      make_cleanup_bfd_close (abfd);

      // we've got a bfd at this point, we're not going to refer to the file any longer
      filename = NULL;
      file_exists = 0;
    }

  if (abfd == NULL)
    {
      if (mh_addr == 0 || mh_addr == INVALID_ADDRESS)
        return 0;

      if (force_live_memory_reads)
        {
          // Force this to be read out of real memory
          make_cleanup (set_trust_readonly_cleanup, (void *) set_trust_readonly (0));
          make_cleanup (set_only_read_from_live_memory_cleanup, (void *) set_only_read_from_live_memory (1));
        }

      if (target_read_mach_header (mh_addr, &h) != 0)
        return 0;
      if (h.magic != MH_MAGIC && h.magic != MH_MAGIC_64)
        return 0;
      if (h.sizeofcmds > 15000)   // Sanity check to avoid reading non-macho data as mach-o
         return 0;

      int header_size = target_get_mach_header_size (&h);
      gdb_byte *buf = (gdb_byte *) xmalloc (h.sizeofcmds + header_size);
      make_cleanup (xfree, buf);
      if (target_read_memory (mh_addr, buf, h.sizeofcmds + header_size))
        {
          do_cleanups (bfd_cleanups);
          return 0;
        }

      mem_bfd = bfd_memopenr ("tempbfd", NULL, buf, h.sizeofcmds + header_size);
      if (mem_bfd == NULL)
        {
          do_cleanups (bfd_cleanups);
          return 0;
        }
      make_cleanup_bfd_close (mem_bfd);
     }
   else
    {
      mem_bfd = abfd;
    }

  if (bfd_check_format (mem_bfd, bfd_object) == 0)
    {
      do_cleanups (bfd_cleanups);
      return 0;
    }

  if (require_kernel && !bfd_mach_o_kernel_image (mem_bfd))
    {
      do_cleanups (bfd_cleanups);
      return 0;
    }

  if (uuid)
    {
      uuid_t mem_uuid;
      if (bfd_mach_o_get_uuid (mem_bfd, (unsigned char *) &mem_uuid, sizeof (uuid_t)))
        {
          memcpy (uuid, mem_uuid, sizeof (uuid_t));
        }
    }
  if (osabi)
    {
      *osabi = gdbarch_lookup_osabi_from_bfd (mem_bfd);
    }
  if (wordsize)
    {
      if (h.magic == MH_MAGIC)
        *wordsize = 4;
      else
        *wordsize = 8;
    }
  if ((intended_load_address || slide) && bfd_get_section_by_name (mem_bfd, TEXT_SEGMENT_NAME))
    {
      CORE_ADDR addr = bfd_section_vma (mem_bfd, bfd_get_section_by_name (mem_bfd, TEXT_SEGMENT_NAME));
      if (intended_load_address)
        *intended_load_address = addr;
      if (slide && mh_addr != INVALID_ADDRESS && mh_addr != 0)
        *slide = mh_addr - addr;
    }

  if (addrs)
    {
      *addrs = get_section_addresses_for_bfd (mem_bfd);
    }

  do_cleanups (bfd_cleanups);
  return 1;
}

/* Given an array of Mach-O LC_UUIDs to search for, look in the target
   (assumes target is the mach_kernel) for the array of loaded kexts, find
   the first kext with an LC_UUID that matches one of the entries in the array,
   return a section_addr_info structure based on the in-memory load commands.

   The caller is responsible for freeing *SECT_ADDRS - best done via
   a call to free_section_addr_info().

   Returns NULL if there was a problem or no matching kext was found.  */

struct section_addr_info *
macosx_get_kext_sect_addrs_from_kernel (const char *filename,
                                        uint8_t **kext_uuids, 
                                        const char *kext_bundle_ident)
{
  struct loaded_kexts_table *loaded_kexts = get_list_of_loaded_kexts ();
  if (loaded_kexts == NULL)
    return NULL;

  CORE_ADDR mh_addr = INVALID_ADDRESS;
  int found_match;
  int i;
  for (found_match = 0, i = 0; i < loaded_kexts->count && found_match == 0; i++)
    {
      int j = 0;
      while (kext_uuids[j] != 0)
        {
          if (memcmp (kext_uuids[j], loaded_kexts->kexts[i].uuid, sizeof (uuid_t)) == 0)
            {
              mh_addr = loaded_kexts->kexts[i].address;
              found_match = 1;
              break;
            }
          j++;
        }
    }
  if (mh_addr == INVALID_ADDRESS)
    return NULL;

  free_list_of_loaded_kexts (loaded_kexts);

  // We found a matching UUID.
  // Now look at the load commands in memory (create a temporary
  // memory bfd) to get the load addresses of each text/data section.

  return get_section_addresses_for_macho_in_memory (mh_addr);
}

static void
add_all_kexts_command (char *args, int from_tty)
{
#if !defined (USE_DEBUG_SYMBOLS_FRAMEWORK)
  error ("DebugSymbols framework not available, add-all-kexts command not unavailable.");
#else
  struct loaded_kexts_table *lks = get_list_of_loaded_kexts ();
  if (lks == NULL)
    error ("Unable to read list of kexts from the kernel memroy.");

  int i;
  for (i = 0; i < lks->count; i++)
    {
      // If we've already added the kext, don't add it a second time
      if (find_objfile_by_uuid (lks->kexts[i].uuid))
        continue;

      CFUUIDRef kext_uuid_ref = get_uuidref_for_uuid_t (lks->kexts[i].uuid);
      if (kext_uuid_ref == NULL)
        continue;
      const char *symbol_rich = macosx_locate_kext_executable_by_symfile_helper
                                           (kext_uuid_ref, lks->kexts[i].name);
      int have_symbol_rich_exe = 0;
      if (symbol_rich && file_exists_p (symbol_rich))
        have_symbol_rich_exe = 1;

      CFURLRef dsym_url = DBGCopyDSYMURLForUUID (kext_uuid_ref);
      char dsym_path[PATH_MAX];
      dsym_path[0] = '\0';
      int have_dsym_path = 0;
      if (dsym_url)
        if (CFURLGetFileSystemRepresentation (dsym_url, 1, (UInt8*) dsym_path, PATH_MAX))
          {
            dsym_path[PATH_MAX - 1] = '\0';
            if (file_exists_p (dsym_path))
              have_dsym_path = 1;
          }
      CFRelease (kext_uuid_ref);

      // At this point we may have the pathanme to the kext bundle executable
      // file (the "symbol rich executable") and we may have the pathname to
      // a dSYM ("dsym_path").

      struct section_addr_info *sect_addrs;
      sect_addrs = get_section_addresses_for_macho_in_memory (lks->kexts[i].address);
      if (sect_addrs == NULL)
        continue;

      if (have_symbol_rich_exe)
        {
          struct section_offsets *sect_offsets;
          int num_offsets;
          sect_offsets = convert_sect_addrs_to_offsets_via_on_disk_file
                        (sect_addrs, symbol_rich,
                         &num_offsets);
          symbol_file_add_name_with_addrs_or_offsets (symbol_rich, from_tty, NULL, sect_offsets, num_offsets, 0, OBJF_USERLOADED, OBJF_SYM_ALL, 0, NULL, NULL);
           xfree (sect_offsets);
        }
      else
        {
// Reading the kext out of kernel memory has several problems.
// The first of which is the fact that the in-kernel MachO load commands
// look like an object file (i.e. with no __TEXT segment) so just doing
// a bfd_memopenr() and adding that as an objfile will not work.
// You'll need to make changes in macho_calculate_offsets_for_dsym(),
// macho_calculate_dsym_offset(), macho_symfile_offsets() and maybe others
// to even get close.
// Also, this code path should probably not be executed for remote
// targets -- reading these out of kernel memory over a USB cable would be
// slow.
#if 0
          uint8_t *buf = (uint8_t*) xmalloc (lks->kexts[i].size);
          if (buf == NULL)
            {
              free_section_addr_info (sect_addrs);
              continue;
            }
           if (target_read_memory (lks->kexts[i].address, buf, lks->kexts[i].size))
            {
              free_section_addr_info (sect_addrs);
              continue;
            }
          const char *bfd_target_name = NULL;
          if (gdbarch_byte_order (current_gdbarch) == BFD_ENDIAN_LITTLE)
            bfd_target_name = "mach-o-le";
          if (gdbarch_byte_order (current_gdbarch) == BFD_ENDIAN_BIG)
            bfd_target_name = "mach-o-be";

          // note that we never free the kext memory we just transferred....
          bfd *abfd = bfd_memopenr (lks->kexts[i].name, bfd_target_name, 
                                    buf, lks->kexts[i].size);
          if (abfd == NULL || !bfd_check_format (abfd, bfd_object))
            {
              free_section_addr_info (sect_addrs);
              xfree (buf);
              continue;
            }
          symbol_file_add_bfd_safe (abfd, 0,
                                    0, NULL, 0,
                                    OBJF_USERLOADED, 
                                    OBJF_SYM_ALL,
                                    0, NULL, NULL);
#endif
        }
      free_section_addr_info (sect_addrs);
    }

  update_section_tables ();
  update_current_target ();
  breakpoint_update ();

  /* Getting new symbols may change our opinion about what is
     frameless.  */
  reinit_frame_cache ();

  free_list_of_loaded_kexts (lks);
#endif // USE_DEBUG_SYMBOLS_FRAMEWORK
}


/* INPUT: ADDR is an address which may have a kernel; 
   INPUT: FILE_UUID an optional pointer to a uuid_t of the kernel we're
          looking for.  An exact match will be enforced.  May be NULL.
   OUTPUT: DISCOVERED_UUID an optional pointer to a uuid_t which will
          be filled in with the UUID of the kernel image found.  
          May be NULL.

   Returns 1 if a kernel was found at ADDR.
   Returns 0 if a kernel was not found at ADDR.  */

static int
mach_kernel_starts_here_p (CORE_ADDR addr, uuid_t *file_uuid, uuid_t *discovered_uuid, enum gdb_osabi *discovered_osabi)
{
  uuid_t mem_uuid;
  enum gdb_osabi mem_osabi;
  if (!get_information_about_macho (NULL, addr, NULL, 1, 1, &mem_uuid, &mem_osabi, NULL, NULL, NULL, NULL))
    return 0;

  if (file_uuid)
    {
      if (memcmp (*file_uuid, mem_uuid, sizeof (uuid_t)) != 0)
        {
          warning ("Kernel found in memory at 0x%s has a UUID of %s but the binary specified to gdb has a UUID of %s\n",
                   paddr_nz (addr), puuid (*file_uuid), puuid (mem_uuid));
        }
    }
  if (discovered_osabi) 
    *discovered_osabi = mem_osabi;
  if (discovered_uuid)
    memcpy (*discovered_uuid, mem_uuid, sizeof (uuid_t));
  return 1;
}

/* Search the inferior's memory space for a kernel image.
   INPUT:  OFILE  optional - the mach_kernel objfile.  If we provided, UUID matching is enforced
   OUTPUT:  ADDR  optional - set to the address of mach_kernel in inferior, if found
   OUTPUT:  UUID_OUTPUT  optional - set to the UUID of the mach_kernel in inferior, if found
   RETURN: 1 if a kernel is found in memory
           0 if no kernel is found
   The caller should allocate space for ADDR and UUID.  If this information is not
   needed, they may be NULL.  
   Not setting ABFD means that every Mach-O image found in memory will need to be inspected
   to see if it is the kernel.  This will have a performance impact.  

   If we are given an OFILE, and the kernel is found at a slid address in memory, the OFILE
   will be relocated by this function.
*/

int
exhaustive_search_for_kernel_in_mem (struct objfile *ofile, CORE_ADDR *addr, uuid_t *uuid_output)
{

  // If this is a kernel, it may have been slid by the booter, try to find where it is in memory.
  uuid_t kernel_uuid;
  uuid_t *uuid = NULL; // NULL means we don't have an ABFD or could not find a UUID in ABFD

  uuid_t in_memory_uuid;
  enum gdb_osabi in_memory_osabi = GDB_OSABI_UNKNOWN;

  struct cleanup *override_trust_readonly;

  // If we're handed a pointer to a struct object_file which doesn't have a BFD in it, 
  // just ignore it altogether
  if (ofile && !ofile->obfd)
    ofile = NULL;

  // If we're given a symbol file and it ISN'T a kernel, this is not a kernel debug session.
  // If we aren't given a symbol file we'll try to search around memory to find one ...
  // FIXME this will be a problem if people use 'target remote' without a symbol file in
  // non-kernel situations.
  if (ofile && !bfd_mach_o_kernel_image (ofile->obfd))
    return 0;

  if (kaslr_memory_search_enabled == 0)
    return 0;

  /* We need to read data directly out of memory, we can't "trust" the read-only sections
     and read anything out of the symbol files (which may be at the wrong address at this 
     point). */
  override_trust_readonly = make_cleanup (set_trust_readonly_cleanup, 
                                          (void *) set_trust_readonly (0));
  make_cleanup (set_only_read_from_live_memory_cleanup,
                (void *) set_only_read_from_live_memory (1));

  if (ofile && bfd_mach_o_kernel_image (ofile->obfd) && bfd_get_section_by_name (ofile->obfd, TEXT_SEGMENT_NAME))
    {
      if (bfd_mach_o_get_uuid (ofile->obfd, kernel_uuid, sizeof (uuid_t)))
        {
          // The provided kernel bfd has a uuid, set UUID to point to it
          uuid = &kernel_uuid;
        }
    }

  CORE_ADDR cur_addr;
  CORE_ADDR stop_addr;
  CORE_ADDR stride = 0x100000;
  CORE_ADDR offset = 0x1000;

  int wordsize = gdbarch_tdep (current_gdbarch)->wordsize;
  if (wordsize == 4)
    {
      cur_addr = 1ULL << 31;
      stop_addr = UINT32_MAX;
    }
  else
    {
      cur_addr = 1ULL << 63;
      stop_addr = UINT64_MAX;
    }

  /* First, if we have a symbol file, see if the kernel was loaded unslid */

  int found_kernel = 0;
  uint64_t file_address = INVALID_ADDRESS;
  if (ofile && bfd_get_section_by_name (ofile->obfd, TEXT_SEGMENT_NAME))
    {
      file_address = bfd_section_vma (ofile->obfd, bfd_get_section_by_name (ofile->obfd, TEXT_SEGMENT_NAME));

      if (mach_kernel_starts_here_p (file_address, uuid, &in_memory_uuid, &in_memory_osabi))
        {
          cur_addr = file_address;
          found_kernel = 1;
        }
      else if (file_address != INVALID_ADDRESS)
        {
           offset = file_address & 0xfffff;
        }
    }

  /* Second, when the appropriate boot-args are set, the load 
     address of the kernel is written at a fixed address in 
     the kernel's low globals page.  See what's there.  */
  ULONGEST val = 0;
  if (!found_kernel
      && wordsize == 4
      && !safe_read_memory_unsigned_integer (0xffff0110, 4, &val)
      && val > cur_addr
      && val < stop_addr
      && mach_kernel_starts_here_p (val, uuid, &in_memory_uuid, &in_memory_osabi))
      {
        found_kernel = 1;
        cur_addr = val & 0xffffffff;
      }

  val = 0;
  if (!found_kernel
      && wordsize == 8
      && !safe_read_memory_unsigned_integer (0xffffff8000002010ULL, 8, &val)
      && val > cur_addr
      && val < stop_addr
      && mach_kernel_starts_here_p (val, uuid, &in_memory_uuid, &in_memory_osabi))
      {
        found_kernel = 1;
        cur_addr = val;
      }

  /* Third, on 32-bit iOS, 0xffff011c may have the address of the
     'version' string from the kernel's __TEXT,__const section.
     If so, we can search a much smaller section of memory.  */
  
  val = 0;
  // Read the uint32_t address of 'version' 
  if (!found_kernel
      && wordsize == 4
      && !safe_read_memory_unsigned_integer (0xffff011c, 4, &val)
      && val > cur_addr
      && val < stop_addr)
    {
      /* Start at 16MB before the version string */
      /* & ~0xfffff == round down to the nearest 1MB boundary 
         0x1000000 == 16MB */
      CORE_ADDR try_this_addr = (val & ~0xfffff) - 0x1000000;

      /* Don't try to examine anything before the lowest valid addr range for the kernel */
      if (try_this_addr < cur_addr)
        try_this_addr = cur_addr;

      while (!found_kernel && try_this_addr < val)
        {
          if (mach_kernel_starts_here_p (try_this_addr, uuid, &in_memory_uuid, &in_memory_osabi))
            {
              found_kernel = 1;
            }
          else if (mach_kernel_starts_here_p (try_this_addr + offset, uuid, &in_memory_uuid, &in_memory_osabi))
            {
              found_kernel = 1;
              try_this_addr += offset;
            }
          else
            {
              try_this_addr += stride;
            }
        }
      if (found_kernel)
        cur_addr = try_this_addr;
    }

  /* Fourth, maybe the current pc value is kernel code that is running.
     If so, we can search a much smaller section of memory.  */
  
  if (!found_kernel && stop_pc != 0 && stop_pc != INVALID_ADDRESS
      && stop_pc >= cur_addr && stop_pc < stop_addr)
    {
      /* Start at 32MB before the current pc value */
      /* & ~0xfffff == round down to the nearest 1MB boundary 
         0x2000000 == 32MB */
      CORE_ADDR try_this_addr = (stop_pc & ~0xfffff) - 0x2000000;

      /* Don't try to examine anything before the lowest valid addr range for the kernel */
      if (try_this_addr < cur_addr)
        try_this_addr = cur_addr;

      while (!found_kernel && try_this_addr < stop_pc)
        {
          if (mach_kernel_starts_here_p (try_this_addr, uuid, &in_memory_uuid, &in_memory_osabi))
            {
              found_kernel = 1;
            }
          else if (mach_kernel_starts_here_p (try_this_addr + offset, uuid, &in_memory_uuid, &in_memory_osabi))
            {
              found_kernel = 1;
              try_this_addr += offset;
            }
          else
            {
              try_this_addr += stride;
            }
        }
      if (found_kernel)
        cur_addr = try_this_addr;
    }


  /* Fifth, start iterating from the beginning of the possible kernel region of memory
     until we run out of address space or find a kernel.  */

  if (wordsize == 4 && !found_kernel)
    {
      printf_filtered ("Starting exhaustive search for kernel in memory, do 'set kaslr-memory-search 0' to disable this in the future.\n");
      while (!found_kernel && cur_addr != 0 && cur_addr < stop_addr)
        {
          if (mach_kernel_starts_here_p (cur_addr, uuid, &in_memory_uuid, &in_memory_osabi))
            {
              found_kernel = 1;
            }
          else if (mach_kernel_starts_here_p (cur_addr + offset, uuid, &in_memory_uuid, &in_memory_osabi))
            {
              found_kernel = 1;
              cur_addr += offset;
            }
          else
            {
              cur_addr += stride;
            }
        }
    }

  if (found_kernel)
    {
      int succeeded = 0;
      if (ofile)
        succeeded = slide_kernel_objfile (ofile, cur_addr, in_memory_uuid, in_memory_osabi);
      if (!succeeded)
        succeeded = try_to_find_and_load_kernel_via_uuid (cur_addr, in_memory_uuid, in_memory_osabi);

      if (succeeded)
        {
          do_cleanups (override_trust_readonly);
          if (uuid_output)
            memcpy (*uuid_output, &in_memory_uuid, sizeof (uuid_t));
          if (addr)
            *addr = cur_addr;
          return 1;
        }
    }

  do_cleanups (override_trust_readonly);
  return 0;
}

/* If the user specified the mach_kernel on the command line and we need to
   slide it to the actual location, this is the function.
   Returns 1 if kernel was slid successfully (or no slide was needed).  */

int
slide_kernel_objfile (struct objfile *o, CORE_ADDR in_memory_addr, uuid_t in_memory_uuid, enum gdb_osabi osabi)
{
  CORE_ADDR file_load_addr = INVALID_ADDRESS;
  if (o == NULL || o->obfd == NULL || in_memory_addr == 0 || in_memory_addr == INVALID_ADDRESS)
    return 0;
  if (!get_information_about_macho (NULL, INVALID_ADDRESS, o->obfd, 1, 0, NULL, NULL, NULL, &file_load_addr, NULL, NULL))
    return 0;
  if (file_load_addr == 0 || file_load_addr == INVALID_ADDRESS)
    return 0;

  if (osabi != GDB_OSABI_UNKNOWN)
    {
      const char *osabi_name = gdbarch_osabi_name (osabi);
#if defined (TARGET_I386)
      if (strcmp (osabi_name, "Darwin") == 0)
        set_architecture_from_string ("i386");
      else if (strcmp (osabi_name, "Darwin64") == 0)
        set_architecture_from_string ("i386:x86-64");
#endif
#if defined (TARGET_ARM)
      if (strcmp (osabi_name, "Darwin") == 0)
        set_architecture_from_string ("armv7");
      else if (strcmp (osabi_name, "DarwinV7") == 0)
        set_architecture_from_string ("armv7");
      else if (strcmp (osabi_name, "DarwinV7S") == 0)
        set_architecture_from_string ("armv7s");
#endif
      set_osabi_option (osabi_name);
    }

  if (in_memory_addr != file_load_addr)
    {
      kernel_slide = in_memory_addr - file_load_addr;
      slide_objfile (symfile_objfile, kernel_slide, NULL);
      update_section_tables ();
      update_current_target ();
      breakpoint_update ();

      /* Getting new symbols may change our opinion about what is
         frameless.  */
      reinit_frame_cache ();
      flush_cached_frames ();
    }
  else
   kernel_slide = 0;

  printf_filtered ("Kernel is located in memory at 0x%s with uuid of %s\n",
                 paddr_nz (in_memory_addr), puuid (in_memory_uuid));
  if (kernel_slide != 0)
    {
      printf_filtered ("Kernel slid 0x%s in memory.\n", paddr_nz (kernel_slide));
    }

  return 1;
}

/* The address of the kernel in memory has been identified, and we have the UUID, but the
   user did not give us a mach_kernel on the start up -- see if we can call out to the 
   com.apple.DebugSymbols DBGShellCommands command to track down the mach_kernel binary
   based on the UUID.  If so, load it at the correct address.  
   Returns 1 if we successfully loaded a kernel.
   Returns 0 if it did not load a kernel.  */

int 
try_to_find_and_load_kernel_via_uuid (CORE_ADDR in_memory_addr, uuid_t in_memory_uuid, enum gdb_osabi osabi)
{

  if (osabi != GDB_OSABI_UNKNOWN)
    {
      const char *osabi_name = gdbarch_osabi_name (osabi);
#if defined (TARGET_I386)
      if (strcmp (osabi_name, "Darwin") == 0)
        set_architecture_from_string ("i386");
      else if (strcmp (osabi_name, "Darwin64") == 0)
        set_architecture_from_string ("i386:x86-64");
#endif
#if defined (TARGET_ARM)
      if (strcmp (osabi_name, "Darwin") == 0)
        set_architecture_from_string ("armv7");
      else if (strcmp (osabi_name, "DarwinV7") == 0)
        set_architecture_from_string ("armv7");
      else if (strcmp (osabi_name, "DarwinV7S") == 0)
        set_architecture_from_string ("armv7s");
#endif
      set_osabi_option (osabi_name);
    }

  int loaded_kernel_for_user = 0;
  CFUUIDRef uuidref = get_uuidref_for_uuid_t (in_memory_uuid);
  CFStringRef uuid_string = CFUUIDCreateString(kCFAllocatorDefault, uuidref);
  if (uuid_string)
    {
      char *kernel_path = macosx_locate_executable_by_dbg_shell_command (uuid_string);
      if (!file_exists_p (kernel_path))
        {
          /* If we couldn't find the executable by calling the DBGShellCommands command,
             try looking up the dSYM via UUID and seeing if there is a binary sitting next
             to it.  */
          if (kernel_path != NULL)
            xfree (kernel_path);
          kernel_path = macosx_locate_kext_executable_by_symfile_helper (uuidref, "mach kernel");
        }
      CORE_ADDR on_disk_load_addr;
      if (get_information_about_macho (kernel_path, 0, NULL, 1, 0, NULL, NULL, NULL, &on_disk_load_addr, NULL, NULL))
        {
          kernel_slide = in_memory_addr - on_disk_load_addr;

          struct objfile *o = symbol_file_add_name_with_addrs_or_offsets (kernel_path, 1, NULL, NULL, 0, 1, 
                                                      OBJF_USERLOADED, OBJF_SYM_ALL, 0, NULL, NULL);
          xfree (kernel_path);

          if (o == NULL)
            {
              CFRelease (uuid_string);
              CFRelease (uuidref);
              return 0;
            }

          loaded_kernel_for_user = 1;

          if (kernel_slide != 0 && kernel_slide != INVALID_ADDRESS)
            slide_objfile (o, kernel_slide, NULL);

          /* This is our main executable.  */
          exec_bfd = o->obfd;

          update_section_tables ();
          update_current_target ();
          breakpoint_update ();

              /* Getting new symbols may change our opinion about what is
             frameless.  */
          reinit_frame_cache ();
          flush_cached_frames ();
        }
      CFRelease (uuid_string);
    }
  CFRelease (uuidref);

  printf_filtered ("Kernel is located in memory at 0x%s with uuid of %s\n",
                 paddr_nz (in_memory_addr), puuid (in_memory_uuid));

  if (kernel_slide != 0 && kernel_slide != INVALID_ADDRESS)
    {
      printf_filtered ("Kernel slid 0x%s in memory.\n", paddr_nz (kernel_slide));
    }

  if (loaded_kernel_for_user)
    {
      char *exe_for_uuid_cmd = get_dbg_shell_command ();
      char *cmd_for_printing = exe_for_uuid_cmd;
      if (exe_for_uuid_cmd)
        {
          char *bname = basename (exe_for_uuid_cmd);
          if (bname != NULL)
            cmd_for_printing = bname;
        }
      if (cmd_for_printing)
        printf_filtered ("Kernel binary has been loaded into gdb via %s.\n", cmd_for_printing);
      else
        printf_filtered ("Kernel binary has been loaded into gdb.\n");
    }

  return 1;
}

static void
maintenance_list_kexts (char *arg, int from_tty)
{
  struct loaded_kexts_table *kexts = get_list_of_loaded_kexts ();

  if (kexts == NULL)
    return;

  int padcount = 0;
  if (kexts->count > 9)
    padcount = 2;
  if (kexts->count > 99)
    padcount = 3;

  int i;
  for (i = 0; i < kexts->count; i++)
    printf_filtered ("%*d 0x%s %s %s\n",
                     padcount, i,
                     paddr_nz (kexts->kexts[i].address),
                     puuid (kexts->kexts[i].uuid),
                     kexts->kexts[i].name);

  free_list_of_loaded_kexts (kexts);
}


#ifdef NM_NEXTSTEP
#include "macosx-nat-infthread.h"
#endif

char *
macosx_pid_or_tid_to_str (ptid_t ptid)
{
  static char buf[64];
#ifdef NM_NEXTSTEP
  xsnprintf (buf, sizeof buf, "process %d thread 0x%x", ptid_get_pid (ptid), get_application_thread_port ((thread_t) ptid_get_tid (ptid)));
#else
  xsnprintf (buf, sizeof buf, "process %d thread 0x%x", ptid_get_pid (ptid), (unsigned int) ptid_get_tid (ptid));
#endif
  return buf;
}


/* On arm-native iOS systems the shared cache of libraries in memory doesn't
   have all of the nlist records -- and the nlist records it does have will
   have "<redacted>" as the only symbol name for every symbol to conserve
   address space.  The complete list of nlist records and the symbol names
   are stored on-disk as a special part of the dyld_shared_cache.
   This function will pull in the nlist records, strings, and list of
   dylibs/frameworks in the shared cache so we can get the correct
   symbols when we create objfiles for the shared cache libraries.  */

struct gdb_copy_dyld_cache_header
{
        char            magic[16];
        uint32_t        mappingOffset;
        uint32_t        mappingCount;
        uint32_t        imagesOffset;
        uint32_t        imagesCount;
        uint64_t        dyldBaseAddress;
        uint64_t        codeSignatureOffset;
        uint64_t        codeSignatureSize;
        uint64_t        slideInfoOffset;
        uint64_t        slideInfoSize;
        uint64_t        localSymbolsOffset;
        uint64_t        localSymbolsSize;
};
struct gdb_copy_dyld_cache_local_symbols_info
{
        uint32_t        nlistOffset;
        uint32_t        nlistCount;
        uint32_t        stringsOffset;
        uint32_t        stringsSize;
        uint32_t        entriesOffset;
        uint32_t        entriesCount;
};


/* DYLD_SHARED_CACHE_RAW has the struct dyld_cache_local_symbols_info,
   followed by the array of struct dyld_cache_local_symbols_entry's,
   followed by the nlist entries for all the dylibs in the shared
   cache, followed by the strings for those nlist records.  All in
   one big chunk.  The other pointers all point in to this buffer.  */
uint8_t *dyld_shared_cache_raw;

uint8_t *dyld_shared_cache_local_nlists = NULL;
int dyld_shared_cache_local_nlists_count = 0;
char *dyld_shared_cache_strings = NULL;
int dyld_shared_cache_strings_size = 0;
struct gdb_copy_dyld_cache_local_symbols_entry *dyld_shared_cache_entries = NULL;
int dyld_shared_cache_entries_count = 0;

void
free_dyld_shared_cache_local_syms ()
{
  if (dyld_shared_cache_raw)
    xfree (dyld_shared_cache_raw);
  dyld_shared_cache_raw = NULL;
  dyld_shared_cache_local_nlists = NULL;
  dyld_shared_cache_local_nlists_count = 0;
  dyld_shared_cache_strings = NULL;
  dyld_shared_cache_strings_size = 0;
  dyld_shared_cache_entries = NULL;
  dyld_shared_cache_entries_count = 0;
}


void
get_dyld_shared_cache_local_syms ()
{
#if defined (TARGET_ARM) && defined (NM_NEXTSTEP)

  if (dyld_shared_cache_raw != NULL)
    return;

  /* TODO: If the processDetachedFromSharedRegion flag is set in the
     dyld_all_image_infos struct (imported into the struct dyld_raw_infos
     as process_detached_from_shared_region in macosx-nat-dyld.c) then
     this process is not using the system-wide shared cache and we should
     not import/use these nlist records.  */

  int wordsize = gdbarch_tdep (current_gdbarch)->wordsize;
  int nlist_entry_size;
  if (wordsize == 4)
    nlist_entry_size = 12;
  else
    nlist_entry_size = 16;

  const char *osabi_name = gdbarch_osabi_name (gdbarch_osabi (current_gdbarch));
  const char *arch_name = NULL;
  if (strcmp (osabi_name, "Darwin") == 0)
    arch_name = "arm";
  else if (strcmp (osabi_name, "DarwinV6") == 0)
    arch_name = "armv6";
  else if (strcmp (osabi_name, "DarwinV7") == 0)
    arch_name = "armv7";
  else if (strcmp (osabi_name, "DarwinV7S") == 0)
    arch_name = "armv7s";
  else if (strcmp (osabi_name, "DarwinV7F") == 0)
    arch_name = "armv7";
  if (arch_name == NULL)
    return;
  char dsc_path[PATH_MAX];
  snprintf(dsc_path, sizeof(dsc_path), 
         "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_%s",
         arch_name);
  FILE *dsc = fopen (dsc_path, "r");
  if (dsc == NULL)
    return;
  struct gdb_copy_dyld_cache_header dsc_header;
  if (fread (&dsc_header, sizeof (dsc_header), 1, dsc) != 1)
    {
      fclose (dsc);
      return;
    }

  // We're dealing with an older dyld shared cache file that doesn't have 
  // this info.
  if (dsc_header.mappingOffset < sizeof (struct gdb_copy_dyld_cache_header))
    {
      fclose (dsc);
      return;
    }

  if (fseek (dsc, dsc_header.localSymbolsOffset, SEEK_SET) != 0)
    {
      fclose (dsc);
      return;
    }

  dyld_shared_cache_raw = (uint8_t *) xmalloc (dsc_header.localSymbolsSize);
  if (fread (dyld_shared_cache_raw, dsc_header.localSymbolsSize, 1, dsc) != 1)
    {
      free_dyld_shared_cache_local_syms ();
      fclose (dsc);
      return;
    }
  fclose (dsc);

  struct gdb_copy_dyld_cache_local_symbols_info *locsyms_header;
  locsyms_header = (struct gdb_copy_dyld_cache_local_symbols_info *) dyld_shared_cache_raw;

  dyld_shared_cache_local_nlists = dyld_shared_cache_raw + locsyms_header->nlistOffset;
  dyld_shared_cache_local_nlists_count = locsyms_header->nlistCount;

  dyld_shared_cache_strings = (char *) dyld_shared_cache_raw + locsyms_header->stringsOffset;
  dyld_shared_cache_strings_size = locsyms_header->stringsSize;

  dyld_shared_cache_entries = (struct gdb_copy_dyld_cache_local_symbols_entry *) dyld_shared_cache_raw + locsyms_header->entriesOffset;
  dyld_shared_cache_entries_count = locsyms_header->entriesCount;
#endif
}

struct gdb_copy_dyld_cache_local_symbols_entry *
get_dyld_shared_cache_entry (CORE_ADDR intended_load_addr)
{
  get_dyld_shared_cache_local_syms ();
  int i = 0;
  while (i < dyld_shared_cache_entries_count)
    {
      if (dyld_shared_cache_entries[i].dylibOffset == intended_load_addr - 0x30000000)
        return &dyld_shared_cache_entries[i];
      i++;
    }
  return NULL;
}


void
_initialize_macosx_tdep ()
{
  struct cmd_list_element *c;
  macosx_symbol_types_init ();

  add_info ("trampoline", info_trampoline_command,
            "Resolve function for DYLD trampoline stub and/or Objective-C call");
  c = add_com ("open", class_support, open_command, _("\
Open the named source file in an application determined by LaunchServices.\n\
With no arguments, open the currently selected source file.\n\
Also takes file:line to hilight the file at the given line."));
  set_cmd_completer (c, filename_completer);
  add_com_alias ("op", "open", class_support, 1);
  add_com_alias ("ope", "open", class_support, 1);

  add_com ("flushstack", class_maintenance, stack_flush_command,
           "Force gdb to flush its stack-frame cache (maintainer command)");

  add_com_alias ("flush", "flushregs", class_maintenance, 1);

  add_com ("update", class_obscure, update_command,
           "Re-read current state information from inferior.");
  
  add_setshow_boolean_cmd ("locate-dsym", class_obscure,
			    &dsym_locate_enabled, _("\
Set locate dSYM files using the DebugSymbols framework."), _("\
Show locate dSYM files using the DebugSymbols framework."), _("\
If set, gdb will try and locate dSYM files using the DebugSymbols framework."),
			    NULL, NULL,
			    &setlist, &showlist);

  add_setshow_boolean_cmd ("kaslr-memory-search", class_obscure,
			    &kaslr_memory_search_enabled, _("\
Set whether gdb should do a search through memory for the kernel on 'target remote'."), _("\
Show whether gdb should do a search through memory for the kernel on 'target remote'."), _("\
If set, gdb may look through memory for a kernel when doing 'target remote'"),
			    NULL, NULL,
			    &setlist, &showlist);

  add_cmd ("list-kexts", class_maintenance, 
           maintenance_list_kexts, 
           "List kexts loaded by the kernel (when kernel debugging).",
           &maintenancelist);

  add_setshow_boolean_cmd ("disable-aslr", class_obscure,
			   &disable_aslr_flag, _("\
Set if GDB should disable shared library address randomization."), _("\
Show if GDB should disable shared library address randomization."), NULL,
			   NULL, NULL,
			   &setlist, &showlist);

  c = add_cmd ("add-all-kexts", class_files, add_all_kexts_command, _("\
Usage: add-all-kexts\n\
Load the dSYMs for all of the kexts loaded in a live kernel/kernel coredump.\n\
You must be attached to a live kernel (usually via kdp) or be debugging a\n\
kernel coredump to use this command -- gdb will examine the kernel memory\n\
to find the list of kexts and what addresses they are loaded at.\n"),
               &cmdlist);
  set_cmd_completer (c, filename_completer);

}
