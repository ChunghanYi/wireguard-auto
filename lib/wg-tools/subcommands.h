/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef SUBCOMMANDS_H
#define SUBCOMMANDS_H

extern const char *PROG_NAME;
int show_main(int argc, const char *argv[]);
int showconf_main(int argc, const char *argv[]);
int set_main(int argc, const char *argv[]);
int setconf_main(int argc, const char *argv[]);
#if 0
int genkey_main(int argc, const char *argv[]);
#else
int genkey_main(int argc, const char *argv[], int mode);
#endif
int pubkey_main(int argc, const char *argv[]);

#endif
