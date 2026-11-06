/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef BC_GUI_H
#define BC_GUI_H

#include <stddef.h>

/** Run the editor until its window is closed; \a project_path may be NULL. */
int bc_gui_run(const char *project_path);

/** The bc_launcher shipped next to bc_tool (same build, same key). Defined in bc_tool_main.c. */
void bc_tool_launcher_path(char *out, size_t size);

#endif /* BC_GUI_H */
