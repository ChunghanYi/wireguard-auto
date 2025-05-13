/*
 * Routine to store curve25519 keypairs securely based on libsodium
 * Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
 */


#ifndef SEC_STORE_H
#define SEC_STORE_H

extern void store_curve25519_public(int mode, char *base64);
extern int store_curve25519_secret(int mode, char *base64);
extern int get_privatekey(int mode, char *private);
extern int get_pubkey(int mode, char *private);
extern bool initialize_curve25519(int mode, char *pubkey);

#endif
