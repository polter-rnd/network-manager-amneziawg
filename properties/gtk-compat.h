/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef GTK_COMPAT_H
#define GTK_COMPAT_H

#include <gtk/gtk.h>

#if GTK_CHECK_VERSION(4, 0, 0)
/* GtkCheckButton is no longer a GtkToggleButton in GTK4 */
#define AWG_CHECK_GET_ACTIVE(widget) gtk_check_button_get_active(GTK_CHECK_BUTTON(widget))
#define AWG_CHECK_SET_ACTIVE(widget, active) gtk_check_button_set_active(GTK_CHECK_BUTTON(widget), active)
#define AWG_EDITABLE_GET_TEXT(widget) gtk_editable_get_text(GTK_EDITABLE(widget))
#define AWG_EDITABLE_SET_TEXT(widget, text) gtk_editable_set_text(GTK_EDITABLE(widget), text)
#else
#define AWG_CHECK_GET_ACTIVE(widget) gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget))
#define AWG_CHECK_SET_ACTIVE(widget, active) gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), active)
#define AWG_EDITABLE_GET_TEXT(widget) gtk_entry_get_text(GTK_ENTRY(widget))
#define AWG_EDITABLE_SET_TEXT(widget, text) gtk_entry_set_text(GTK_ENTRY(widget), text)
#endif

#endif
