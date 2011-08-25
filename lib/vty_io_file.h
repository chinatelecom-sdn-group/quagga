/* VTY I/O for Files -- Header
 *
 * Copyright (C) 2010 Chris Hall (GMCH), Highwayman
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_VTY_IO_FILE_H
#define _ZEBRA_VTY_IO_FILE_H

#include "misc.h"

#include "vty_io.h"
#include "command_parse.h"

/*==============================================================================
 * Here are structures and other definitions which are shared by:
 *
 *   vty_io.c   -- the main VTY I/O stuff
 *
 * for I/O to files
 */

/*==============================================================================
 * Functions
 */
extern vty vty_config_read_open(int fd, const char* name, bool full_lex) ;
extern cmd_return_code_t uty_config_read_close(vio_vf vf, bool final) ;

extern cmd_return_code_t uty_file_read_open(vty_io vio, qstring name,
                                                          cmd_context context) ;
extern cmd_return_code_t uty_file_write_open(vty_io vio, qstring name,
                                 bool append, cmd_context context, bool after) ;

extern cmd_return_code_t uty_file_fetch_command_line(vio_vf vf,
                                                            cmd_action action) ;
extern cmd_return_code_t uty_file_out_push(vio_vf vf, bool final, bool all) ;

extern cmd_return_code_t uty_file_read_close(vio_vf vf, bool final) ;
extern cmd_return_code_t uty_file_write_close(vio_vf vf, bool final) ;


extern cmd_return_code_t uty_pipe_read_open(vty_io vio, qstring command,
                                                          cmd_context context) ;
extern cmd_return_code_t uty_pipe_write_open(vty_io vio, qstring command,
                                                  bool shell_cmd, bool after) ;
extern cmd_return_code_t uty_pipe_fetch_command_line(vio_vf vf,
                                                            cmd_action action) ;
extern cmd_return_code_t uty_pipe_out_push(vio_vf vf, bool final) ;
extern cmd_return_code_t uty_pipe_read_close(vio_vf vf, bool final) ;
extern cmd_return_code_t uty_pipe_write_close(vio_vf vf, bool final) ;
extern void uty_pipe_return_stop(vio_vf vf) ;
extern void uty_pipe_return_cancel(vio_vf vf) ;

#endif