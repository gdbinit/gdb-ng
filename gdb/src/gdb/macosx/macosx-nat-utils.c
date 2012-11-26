/* Mac OS X support for GDB, the GNU debugger.
   Copyright 1997, 1998, 1999, 2000, 2001, 2002, 2004
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

#include "defs.h"
#include "top.h"
#include "inferior.h"
#include "target.h"
#include "symfile.h"
#include "symtab.h"
#include "objfiles.h"
#include "gdb.h"
#include "gdbcmd.h"
#include "gdbcore.h"
#include "gdbthread.h"
#include "regcache.h"
#include "environ.h"
#include "event-top.h"
#include "event-loop.h"
#include "inf-loop.h"
#include "gdb_stat.h"
#include "gdb_assert.h"
#include "exceptions.h"
#include "checkpoint.h"
#include "objc-lang.h"
#include "bfd.h"

#include "macosx-nat-inferior-debug.h"

#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>

#include <CoreFoundation/CFURLAccess.h>
#include <CoreFoundation/CFPropertyList.h>
#include "macosx-nat-utils.h"
#include "macosx-nat-dyld.h"

static const char *make_info_plist_path (const char *bundle, 
					 const char *bundle_suffix,
					 const char *plist_bundle_path);


/* Given a pathname to an application bundle
   ("/Developer/Examples/AppKit/Sketch/build/Sketch.app")
   find the full pathname to the executable inside the bundle.

   We can find it by looking at the Contents/Info.plist or we
   can fall back on the old reliable
     Sketch.app -> Sketch/Contents/MacOS/Sketch
   rule of thumb.  

   The returned string has been xmalloc()'ed and it is the responsibility of
   the caller to xfree it.  */

char *
macosx_filename_in_bundle (const char *filename, int mainline)
{
  const char *info_plist_filename = NULL;
  char *full_pathname = NULL;
  const void *plist = NULL;
  int shallow_bundle = 0;
  /* FIXME: For now, only do apps, if somebody has more energy
     later, then can do the !mainline case, and handle .framework
     and .bundle.  */

  if (!mainline)
    return NULL;

  /* Check for shallow bundles where the bundle relative property list path
     is "/Info.plist". Shallow bundles have the Info.plist and the
     executable right inside the bundle directory.  */
  info_plist_filename = make_info_plist_path (filename, ".app", "Info.plist");
  if (info_plist_filename)
    plist = macosx_parse_plist (info_plist_filename);

  if (plist == NULL)
    {
      info_plist_filename = make_info_plist_path (filename, ".xpc", "Info.plist");
      if (info_plist_filename)
        plist = macosx_parse_plist (info_plist_filename);
    }

  /* Did we find a valid property list in the shallow bundle?  */
  if (plist != NULL)
    {
      shallow_bundle = 1;
    }
  else
    {
      /* Check for a property list in a normal bundle.  */
      xfree ((char *) info_plist_filename);
      info_plist_filename = make_info_plist_path (filename, ".app", 
						  "Contents/Info.plist");
      if (info_plist_filename)
	plist = macosx_parse_plist (info_plist_filename);

      if (plist == NULL)
        {
          info_plist_filename = make_info_plist_path (filename, ".xpc", "Contents/Info.plist");
          if (info_plist_filename)
            plist = macosx_parse_plist (info_plist_filename);
        }
    }

  if (plist != NULL)
    {
      const char *bundle_exe_from_plist;
      
      bundle_exe_from_plist = macosx_get_plist_posix_value (plist, 
						     "CFBundleExecutable");
      macosx_free_plist (&plist);
      if (bundle_exe_from_plist != NULL)
	{
	  /* Length of the Info.plist directory without the NULL.  */
	  int info_plist_dir_len = strlen (info_plist_filename) - 
				   strlen ("Info.plist");
	  /* Length of our result including the NULL terminator.  */
	  int full_pathname_length = info_plist_dir_len + 
				     strlen (bundle_exe_from_plist) + 1;

	  /* Add the length for the MacOS directory for normal bundles.  */
	  if (!shallow_bundle)
	    full_pathname_length += strlen ("MacOS/");

	  /* Allocate enough space for our resulting path. */
	  full_pathname = xmalloc (full_pathname_length);
	  
	  if (full_pathname)
	    {
	      memcpy (full_pathname, info_plist_filename, info_plist_dir_len);
	      full_pathname[info_plist_dir_len] = '\0';
	      /* Only append the "MacOS/" if we have a normal bundle.  */
	      if (!shallow_bundle)
		strcat (full_pathname, "MacOS/");
	      /* Append the CFBundleExecutable value.  */
	      strcat (full_pathname, bundle_exe_from_plist);
	      gdb_assert ( strlen(full_pathname) + 1 == full_pathname_length );
	    }
	  xfree ((char *) bundle_exe_from_plist);
	}
    }


  if (info_plist_filename)
    xfree ((char *) info_plist_filename);
  return full_pathname;
}

/* Given a BUNDLE from the user such as
    /a/b/c/Foo.app
    /a/b/c/Foo.app/
    /a/b/c/Foo.app/Contents/MacOS/Foo
   (for BUNDLE_SUFFIX of ".app" and PLIST_BUNDLE_PATH of 
    "Contents/Info.plist") return the string
    /a/b/c/Foo.app/Contents/Info.plist
   The return string has been xmalloc()'ed; it is the caller's
   responsibility to free it.  The existance of the Info.plist has
   not been checked; this routine only does the string manipulation.  */

static const char *
make_info_plist_path (const char *bundle, const char *bundle_suffix,
		      const char *plist_bundle_path)
{
  char plist_path[PATH_MAX];
  char plist_realpath[PATH_MAX];
  char *bundle_suffix_pos = NULL;
  char *t = NULL;
  int bundle_suffix_len = strlen (bundle_suffix);

  /* Find the last occurrence of the bundle_suffix.  */
  for (t = strstr (bundle, bundle_suffix); t != NULL; 
       t = strstr (t+1, bundle_suffix))
    bundle_suffix_pos = t;

  if (bundle_suffix_pos != NULL && bundle_suffix_pos > bundle)
    {
      /* Length of the bundle directory name without the trailing directory
         delimiter.  */
      int bundle_dir_len = (bundle_suffix_pos - bundle) + bundle_suffix_len;
      /* Allocate enough memory for the bundle directory path with 
	 suffix, a directory delimiter, the relative plist bundle path, 
	 and a NULL terminator.  */
      int info_plist_len = bundle_dir_len + 1 + strlen (plist_bundle_path) + 1;

      if (info_plist_len < PATH_MAX)
	{
	  /* Copy the bundle directory name into the result.  */
	  memcpy (plist_path, bundle, bundle_dir_len);
	  /* Add a trailing directory delimiter and NULL terminate.  */
	  plist_path[bundle_dir_len] = '/';
	  plist_path[bundle_dir_len+1] = '\0';
	  /* Append the needed Info.plist path info.  */
	  strcat (plist_path, plist_bundle_path);
	  gdb_assert ( strlen(plist_path) + 1 == info_plist_len );
	  /* Resolve the path that we return.  */
	  if (realpath (plist_path, plist_realpath) == NULL)
	    return xstrdup (plist_path);
	  else
	    return xstrdup (plist_realpath);
	}
    }

  return NULL;
}

/* Given a valid PATH to a "Info.plist" files, parse the property list
   contents into an opaque type that can be used to extract key values. The 
   property list can be text XML, or a binary plist. The opaque plist pointer
   that is returned should be freed using a call to macosx_free_plist () when 
   no more values are required from the property list. A valid pointer to a 
   property list will be returned, or NULL if the file doesn't exist or if 
   there are any problems parsing the property list file. Valid property 
   list pointers should be released using a call to macosx_free_plist () 
   when the property list is no longer needed.  */

const void *
macosx_parse_plist (const char *path)
{
  CFPropertyListRef plist = NULL;
  const char url_header[] = "file://";
  char *url_text = NULL;
  CFURLRef url = NULL;
  CFAllocatorRef cf_alloc = kCFAllocatorDefault;
  size_t url_text_len = (sizeof (url_header) - 1) + strlen (path) + 1;
  url_text = xmalloc (url_text_len);

  /* Create URL text for the Info.plist file.  */
  strcpy (url_text, url_header);
  strcat (url_text, path);
  
  /* Generate a CoreFoundation URL from the URL text.  */
  url = CFURLCreateWithBytes (cf_alloc, (const UInt8 *)url_text, 
			      url_text_len, kCFStringEncodingUTF8, NULL);
  if (url)
    {
      /* Extract the contents of the file into a CoreFoundation data 
	 buffer.  */
      CFDataRef data = NULL;
      if (CFURLCreateDataAndPropertiesFromResource (cf_alloc, url, &data, 
						    NULL, NULL,NULL) 
						    && data != NULL)
	{
	  /* Create the property list from XML data or from the binary 
	     plist data.  */
	  plist = CFPropertyListCreateFromXMLData (cf_alloc, data, 
						   kCFPropertyListImmutable, 
						   NULL);
	  CFRelease (data);
	  if (plist != NULL)
	    {
	      /* Make sure the property list was a CFDictionary, free it and
		 NULL the pointer if it isn't.  */
	      if (CFGetTypeID (plist) != CFDictionaryGetTypeID ())
		{
		  CFRelease (plist);
		  plist = NULL;
		}
	    }
	}
      CFRelease (url);
    }

  xfree (url_text);
  return plist;
}


/* Return the string value suitable for use with posix file system calls for 
   KEY found in PLIST. NULL will be returned if KEY doesn't have a valid value
   in the the property list, if the value isn't a string, or if there were 
   errors extracting the value for KEY.  */
const char *
macosx_get_plist_posix_value (const void *plist, const char* key)
{
  char *value = NULL;
  if (plist == NULL)
    return NULL;
  CFStringRef cf_key = CFStringCreateWithCString (kCFAllocatorDefault, key, 
						  kCFStringEncodingUTF8);
  CFStringRef cf_value = CFDictionaryGetValue ((CFDictionaryRef) plist, cf_key);
  if (cf_value != NULL && CFGetTypeID (cf_value) == CFStringGetTypeID ())
    {
      CFIndex max_value_len = CFStringGetMaximumSizeOfFileSystemRepresentation 
								(cf_value);
      if (max_value_len > 0)
	{
	  value = (char *) xmalloc (max_value_len + 1);
	  if (value)
	    {
	      if (!CFStringGetFileSystemRepresentation (cf_value, value, 
							max_value_len))
		{
		  /* We failed to get a file system representation 
		     of the bundle executable, just free the buffer 
		     we malloc'ed.  */
		  xfree (value);
		  value = NULL;
		}
	    }
	}
    }
  if (cf_key)
    CFRelease (cf_key);
  return value;
}



/* Return the string value for KEY found in PLIST. NULL will be returned if
   KEY doesn't have a valid value in the the property list, if the value 
   isn't a string, or if there were errors extracting the value for KEY.  */
const char *
macosx_get_plist_string_value (const void *plist, const char* key)
{
  char *value = NULL;
  if (plist == NULL)
    return NULL;
  CFStringRef cf_key = CFStringCreateWithCString (kCFAllocatorDefault, key, 
						  kCFStringEncodingUTF8);
  CFStringRef cf_value = CFDictionaryGetValue ((CFDictionaryRef) plist, cf_key);
  if (cf_value != NULL && CFGetTypeID (cf_value) == CFStringGetTypeID ())
    {
      CFIndex max_value_len = CFStringGetLength (cf_value);
      max_value_len = CFStringGetMaximumSizeForEncoding (max_value_len, 
							 kCFStringEncodingUTF8);
      if (max_value_len > 0)
	{
	  value = xmalloc (max_value_len + 1);
	  if (value)
	    {
	      if (!CFStringGetCString (cf_value, value, max_value_len, 
				       kCFStringEncodingUTF8))
		{
		  /* We failed to get a file system representation 
		     of the bundle executable, just free the buffer 
		     we malloc'ed.  */
		  xfree (value);
		  value = NULL;
		}
	    }
	}
    }
  if (cf_key)
    CFRelease (cf_key);
  return value;
}

/* Free a property list pointer that was obtained from a call to 
   macosx_parse_plist.  */
void
macosx_free_plist (const void **plist)
{
  if (*plist != NULL)
    {
      CFRelease ((CFPropertyListRef)*plist);
      *plist = NULL;
    }
}

void
macosx_print_extra_stop_info (int code, CORE_ADDR address)
{
  ui_out_text (uiout, "Reason: ");
  switch (code)
    {
    case KERN_PROTECTION_FAILURE:
      ui_out_field_string (uiout, "access-reason", "KERN_PROTECTION_FAILURE");
      break;
    case KERN_INVALID_ADDRESS:
      ui_out_field_string (uiout, "access-reason", "KERN_INVALID_ADDRESS");
      break;
#if defined (TARGET_ARM)
    case 0x101:
      ui_out_field_string (uiout, "access-reason", "EXC_ARM_DA_ALIGN");
      break;

    case 0x102:
      ui_out_field_string (uiout, "access-reason", "EXC_ARM_DA_DEBUG");
      break;
#endif
    default:
      ui_out_field_int (uiout, "access-reason", code);
    }
  ui_out_text (uiout, " at address: ");
  ui_out_field_core_addr (uiout, "address", address);
  ui_out_text (uiout, "\n");
}


void
mach_check_error (kern_return_t ret, const char *file,
                  unsigned int line, const char *func)
{
  if (ret == KERN_SUCCESS)
    {
      return;
    }
  if (func == NULL)
    {
      func = "[UNKNOWN]";
    }

  error ("error on line %u of \"%s\" in function \"%s\": %s (0x%lx)\n",
         line, file, func, MACH_ERROR_STRING (ret), (unsigned long) ret);
}


void
mach_warn_error (kern_return_t ret, const char *file,
                 unsigned int line, const char *func)
{
  if (ret == KERN_SUCCESS)
    {
      return;
    }
  if (func == NULL)
    {
      func = "[UNKNOWN]";
    }

  warning ("error on line %u of \"%s\" in function \"%s\": %s (0x%ux)",
           line, file, func, MACH_ERROR_STRING (ret), ret);
}


/* This flag tells us whether we've determined that malloc
   is unsafe since the last time we stopped (excepting hand_call_functions.)
   -1 means we haven't checked yet.
   0 means it is safe
   1 means it is unsafe.
   If you set this, be sure to add a hand_call_cleanup to restore it.  */

static int malloc_unsafe_flag = -1;

static void
do_reset_malloc_unsafe_flag (void *unused)
{
  malloc_unsafe_flag = -1;
}

/* macosx_check_malloc_is_unsafe calls into LibC to see if the malloc lock is taken
   by any thread.  It returns 1 if malloc is locked, 0 if malloc is unlocked, and
   -1 if LibC doesn't support the malloc lock check function. */

static int
macosx_check_malloc_is_unsafe ()
{
  static struct cached_value *malloc_check_fn = NULL;
  struct cleanup *scheduler_cleanup;
  struct value *tmp_value = NULL;
  struct gdb_exception e;
  int success;

  if (malloc_unsafe_flag != -1)
      return malloc_unsafe_flag;

  if (malloc_check_fn == NULL)
    {
      if (lookup_minimal_symbol("malloc_gdb_po_unsafe", 0, 0))
        {
          struct type *func_type;
          func_type = builtin_type_int;
          func_type = lookup_function_type (func_type);
          func_type = lookup_pointer_type (func_type);
          malloc_check_fn = create_cached_function ("malloc_gdb_po_unsafe",
						   func_type);
        }
      else
	return -1;
    }

  if (debug_handcall_setup)
    printf_unfiltered ("Overriding debugger mode to call malloc check function.\n");

  scheduler_cleanup = make_cleanup_set_restore_scheduler_locking_mode
    (scheduler_locking_on);
  /* Suppress the objc runtime mode checking here.  */
  make_cleanup_set_restore_debugger_mode (NULL, 0);

  make_cleanup_set_restore_unwind_on_signal (1);

  TRY_CATCH (e, RETURN_MASK_ALL)
    {
      tmp_value = call_function_by_hand (lookup_cached_function (malloc_check_fn),
                                         0, NULL);
    }

  do_cleanups (scheduler_cleanup);

  /* If we got an error calling the malloc_check_fn, assume it is not
     safe to call... */

  if (e.reason != NO_ERROR)
    return 1;

  success = value_as_long (tmp_value);
  if (success == 0 || success == 1)
    {
      malloc_unsafe_flag = success;
      make_hand_call_cleanup (do_reset_malloc_unsafe_flag, 0);
      return success;
    }
  else
    {
      warning ("Got unexpected value from malloc_gdb_po_unsafe: %d.", success);
      return 1;
    }

  return -1;
}



/* This code implements the Mac OS X side of the safety checks given
   in target_check_safe_call.  The list of modules is defined in
   defs.h.  */

enum {
  MALLOC_SUBSYSTEM_INDEX = 0,
  LOADER_SUBSYSTEM_INDEX = 1,
  OBJC_SUBSYSTEM_INDEX = 2,
  SPINLOCK_SUBSYSTEM_INDEX = 3,
  LAST_SUBSYSTEM_INDEX = 4,
};

static char *macosx_unsafe_regexes[] = {"(^(m|c|re|v)?alloca*)|(::[^ ]*allocator)|(^szone_)",
					 "(^dlopen)|(^__dyld)|(^dyld)|(NSBundle load)|"
					"(NSBundle unload)|(CFBundleLoad)|(CFBundleUnload)",
					"(_class_lookup)|(^objc_lookUpClass)|(^look_up_class)",
                                        "(^__spin_lock)|(^pthread_mutex_lock)|(^pthread_mutex_unlock)|(^__spin_unlock)"};

/* This is the Mac OS X implementation of target_check_safe_call.  */
int
macosx_check_safe_call (int which, enum check_which_threads thread_mode)
{
  int retval = 1;
  regex_t unsafe_patterns[LAST_SUBSYSTEM_INDEX];
  int num_unsafe_patterns = 0;
  int depth = 0;

  static regex_t macosx_unsafe_patterns[LAST_SUBSYSTEM_INDEX];
  static int patterns_initialized = 0;
  
  if (!patterns_initialized)
    {
      int i;
      patterns_initialized = 1;

      for (i = 0; i < LAST_SUBSYSTEM_INDEX; i++)
	{
	  int err_code;
	  err_code = regcomp (&(macosx_unsafe_patterns[i]), 
			      macosx_unsafe_regexes[i],
			      REG_EXTENDED|REG_NOSUB);
	  if (err_code != 0)
	    {
	      char err_str[512];
	      regerror (err_code, &(macosx_unsafe_patterns[i]),
			err_str, 512);
	      internal_error (__FILE__, __LINE__,
			      "Couldn't compile unsafe call pattern %s, error %s", 
			      macosx_unsafe_regexes[i], err_str);
	    }
	}

    }

  /* Because check_safe_call will potentially scan all threads, which can be
     time consuming, we accumulate all the regexp patterns we are going to
     apply into UNSAFE_PATTERNS and pass them at one go to check_safe_call.  */

  if (which & MALLOC_SUBSYSTEM)
    {
      int malloc_unsafe;
      if (macosx_get_malloc_inited () == 0)
	{
	  ui_out_text (uiout, "Unsafe to run code: ");
	  ui_out_field_string (uiout, "problem", "malloc library is not initialized yet");
	  ui_out_text (uiout, ".\n");
	  return 0;
	}

      /* macosx_check_malloc_is_unsafe doesn't tell us about the current thread.
	 So if the caller has asked explicitly about the current thread only, or
	 the scheduler mode is set to off, just try the patterns.  */

      if (thread_mode == CHECK_CURRENT_THREAD 
	  || (thread_mode == CHECK_SCHEDULER_VALUE && !scheduler_lock_on_p ()))
          malloc_unsafe = -1;
      else
	malloc_unsafe = macosx_check_malloc_is_unsafe ();

      if (malloc_unsafe == 1)
	{
	  ui_out_text (uiout, "Unsafe to run code: ");
	  ui_out_field_string (uiout, "problem", "malloc zone lock is held for some zone.");
	  ui_out_text (uiout, ".\n");
	  return 0;
	}
      else if (malloc_unsafe == -1)
	{
	  unsafe_patterns[num_unsafe_patterns] 
	    = macosx_unsafe_patterns[MALLOC_SUBSYSTEM_INDEX];
	  num_unsafe_patterns++;
	  if (depth < 5)
	    depth = 5;
	}
    }

  if (which & OBJC_SUBSYSTEM)
    {
      struct cleanup *runtime_cleanup;
      enum objc_debugger_mode_result objc_retval = objc_debugger_mode_unknown;
      
      /* Again, the debugger mode requires you only run the current thread.  If the
	 caller requested information about the current thread, that means she will
	 be running the all threads - just with code on the current thread.  So we
	 shouldn't use the debugger mode.  */

      if (thread_mode == CHECK_ALL_THREADS
          || (thread_mode == CHECK_SCHEDULER_VALUE && scheduler_lock_on_p ()))
	{
	  objc_retval = make_cleanup_set_restore_debugger_mode (&runtime_cleanup, 1);
	  do_cleanups (runtime_cleanup);
	  if (objc_retval == objc_debugger_mode_success)
	    {
              /* This is cheating, but setting up the debugger mode checks all the
                 other states first, so if we get this, we're done.  */
	      return 1;
	    }
	}

      if (thread_mode == CHECK_CURRENT_THREAD
          || (thread_mode == CHECK_SCHEDULER_VALUE && !scheduler_lock_on_p ())
	  || objc_retval == objc_debugger_mode_fail_objc_api_unavailable)
        {

          /* If we have the new objc runtime, I am going to be a little more
             paranoid, and if any frames in the first 5 stack frames are in 
             libobjc, then I'll bail.  According to Greg, pretty much any routine
             in libobjc in the new runtime is likely to hold an objc lock.  */

          if (new_objc_runtime_internals ())
            {
              struct objfile *libobjc_objfile;
              
              libobjc_objfile = find_libobjc_objfile ();
              if (libobjc_objfile != NULL)
                {
                  struct frame_info *fi;
                  fi = get_current_frame ();
                  if (!fi)
                    {
                      warning ("Cancelling operation - can't find base frame of "
                               "the current thread to determine whether it is safe.");
                      return 0;
                    }
	      
                  while (frame_relative_level (fi) < 5)
                    {
                      struct obj_section *obj_sect = find_pc_section (get_frame_pc (fi));
                      if (obj_sect == NULL || obj_sect->objfile == libobjc_objfile)
                        {
                          warning ("Cancelling call - objc code on the current "
                                   "thread's stack makes this unsafe.");
                          return 0;
                        }
                      fi = get_prev_frame (fi);
                      if (fi == NULL)
                        break;
                    }
                }
            }
          else
            {
              unsafe_patterns[num_unsafe_patterns]
                = macosx_unsafe_patterns[OBJC_SUBSYSTEM_INDEX];
              num_unsafe_patterns++;
              if (depth < 5)
                depth = 5;
            }
        }
      else
        {
          ui_out_text (uiout, "Unsafe to run code: ");
          ui_out_field_string (uiout, "problem", "objc runtime lock is held");
          ui_out_text (uiout, ".\n");
          return 0;
        }
    }

  if (which & LOADER_SUBSYSTEM)
    {
      /* FIXME - There's a better way to do this in SL. */
      struct minimal_symbol *dyld_lock_p;
      int got_it_easy = 0;
      dyld_lock_p = lookup_minimal_symbol ("_dyld_global_lock_held", 0, 0);
      if (dyld_lock_p != NULL)
	{
	  ULONGEST locked;

	  if (safe_read_memory_unsigned_integer (SYMBOL_VALUE_ADDRESS (dyld_lock_p), 
						 4, &locked))
	    {
	      got_it_easy = 1;
	      if (locked == 1)
		return 0;
	    }
	}
	    
      if (!got_it_easy)
	{
	  unsafe_patterns[num_unsafe_patterns] 
	    = macosx_unsafe_patterns[LOADER_SUBSYSTEM_INDEX];
	  num_unsafe_patterns++;
	  if (depth < 5)
	    depth = 5;
	}
    }
  
  if (which & SPINLOCK_SUBSYSTEM)
    {
      unsafe_patterns[num_unsafe_patterns] 
	= macosx_unsafe_patterns[SPINLOCK_SUBSYSTEM_INDEX];
      num_unsafe_patterns++;
      if (depth < 1)
	depth = 1;
    }      

  if (num_unsafe_patterns > 0)
    { 
      retval = check_safe_call (unsafe_patterns, num_unsafe_patterns, depth, 
				thread_mode);
    }

  return retval;
}


#ifndef RTLD_LAZY

#define RTLD_LAZY	0x1
#define RTLD_NOW	0x2
#define RTLD_LOCAL	0x4
#define RTLD_GLOBAL	0x8

#if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)
#define RTLD_NOLOAD	0x10
#define RTLD_NODELETE	0x80
#define RTLD_FIRST	0x100	/* Mac OS X 10.5 and later */
#endif
#endif

static struct cached_value *dlerror_function;

struct value *
macosx_load_dylib (char *name, char *flags)
{
  /* We're basically just going to call dlopen, and return the
     cookie that it returns.  BUT, we also have to make sure that
     we can get the unlimited mode of the ObjC debugger mode, since
     if the runtime is present, it is very likely that the new library
     will change the runtime...  */

  struct cleanup *debugger_mode_cleanup;
  struct cleanup *sched_cleanup;
  static struct cached_value *dlopen_function = NULL; 
  struct value *arg_val[2];
  struct value *ret_val;
  int int_flags;
  enum objc_debugger_mode_result objc_retval;

  if (!macosx_check_safe_call (LOADER_SUBSYSTEM, CHECK_ALL_THREADS))
    error ("Cannot call into the loader at present, it is locked.");

  if (dlopen_function == NULL)
    {
      if (lookup_minimal_symbol ("dlopen", 0, 0))
	{
	  dlopen_function = create_cached_function ("dlopen", 
						    builtin_type_voidptrfuncptr);
	}
    }

  if (dlopen_function == NULL)
    error ("Can't find dlopen function, so it is not possible to load shared libraries.");

  if (dlerror_function == NULL)
    {
      if (lookup_minimal_symbol ("dlerror", 0, 0))
	{
	  dlerror_function = create_cached_function ("dlerror", 
						    builtin_type_voidptrfuncptr);
	}
    }

  /* Decode the flags:  */
  int_flags = 0;
  if (flags != NULL)
    {
      /* The list of flags should be in the form A|B|C, but I'm actually going to
         do an even cheesier job of parsing, and just look for the elements I want.  */
      if (strstr (flags, "RTLD_LAZY") != NULL)
	int_flags |= RTLD_LAZY;
      if (strstr (flags, "RTLD_NOW") != NULL)
	int_flags |= RTLD_NOW;
      if (strstr (flags, "RTLD_LOCAL") != NULL)
	int_flags |= RTLD_LOCAL;
      if (strstr (flags, "RTLD_GLOBAL") != NULL)
	int_flags |= RTLD_GLOBAL;
      if (strstr (flags, "RTLD_NOLOAD") != NULL)
	int_flags |= RTLD_NOLOAD;
      if (strstr (flags, "RTLD_NODELETE") != NULL)
	int_flags |= RTLD_NODELETE;
      if (strstr (flags, "RTLD_FIRST") != NULL)
	int_flags |= RTLD_FIRST;
    }

  /* If the user didn't pass in anything, set some sensible defaults.  */
  if (int_flags == 0)
    int_flags = RTLD_GLOBAL|RTLD_NOW;

  arg_val[1] = value_from_longest (builtin_type_int, int_flags);

  /* Have to do the hand_call function cleanups here, since if the debugger mode is
     already turned on, it may be turned on more permissively than we want.  */
  do_hand_call_cleanups (ALL_CLEANUPS);

  sched_cleanup = make_cleanup_set_restore_scheduler_locking_mode (scheduler_locking_on);

  /* Pass in level of -1 since loading a dylib will very likely change the ObjC runtime, and so
     we will have to get the write lock.  */

  objc_retval = make_cleanup_set_restore_debugger_mode (&debugger_mode_cleanup, -1);

  if (objc_retval == objc_debugger_mode_fail_objc_api_unavailable)
    if (target_check_safe_call (OBJC_SUBSYSTEM, CHECK_SCHEDULER_VALUE))
      objc_retval = objc_debugger_mode_success;

  if (objc_retval != objc_debugger_mode_success)
    error ("Not safe to call dlopen at this time.");

  arg_val[0] = value_coerce_array (value_string (name, strlen (name) + 1));

  ret_val = call_function_by_hand (lookup_cached_function (dlopen_function),
				   2, arg_val);
  do_cleanups (debugger_mode_cleanup);
  do_cleanups (sched_cleanup);

  /* Again we have to clear this out, since we don't want to preserve
     this version of the debugger mode.  */

  do_hand_call_cleanups (ALL_CLEANUPS);
  if (ret_val != NULL)
    {
      CORE_ADDR dlopen_token;
      dlopen_token = value_as_address (ret_val);
      if (dlopen_token == 0)
	{
	  /* This indicates an error in the attempt to
	     call dlopen.  Call dlerror to get a pointer 
	     to the error message.  */

	  char *error_str;
	  int error_str_len;
	  int read_error;
	  CORE_ADDR error_addr;

	  struct cleanup *scheduler_cleanup;

	  if (dlerror_function == NULL)
	    error ("dlopen got an error, but dlerror isn't available to report the error.");

	  scheduler_cleanup =
	    make_cleanup_set_restore_scheduler_locking_mode (scheduler_locking_on);

	  ret_val = call_function_by_hand (lookup_cached_function (dlerror_function),
								   0, NULL);
	  /* Now read the string out of the target.  */
	  error_addr = value_as_address (ret_val);
	  error_str_len = target_read_string (error_addr, &error_str, INT_MAX,
					      &read_error);
	  if (read_error == 0)
	    {
	      make_cleanup (xfree, error_str);
	      error ("Error calling dlopen for: \"%s\": \"%s\"", name, error_str);
	    }
	  else
	    error ("Error calling dlopen for \"%s\", could not fetch error string.",
		   name);
	  
	}
      else
	{
	  ui_out_field_core_addr (uiout, "handle", value_as_address (ret_val));
	  if (info_verbose)
	    printf_unfiltered("Return token was: %s.\n", paddr_nz (value_as_address (ret_val)));
	}
    }
  else if (info_verbose)
    printf_unfiltered("Return value was NULL.\n");

  return ret_val;
}


