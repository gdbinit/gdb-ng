#ifndef __GDB_TM_PPC_MACOSX_H__
#define __GDB_TM_PPC_MACOSX_H__

#ifndef GDB_MULTI_ARCH
#define GDB_MULTI_ARCH 1
#endif

char *ppc_throw_catch_find_typeinfo (struct frame_info *curr_frame,
                                     int exception_type);
#define THROW_CATCH_FIND_TYPEINFO(curr_frame, exception_type) \
  (ppc_throw_catch_find_typeinfo (curr_frame, exception_type))

#endif /* __GDB_TM_PPC_MACOSX_H__ */
