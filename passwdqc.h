/*
 * Copyright (c) 2000-2002 by Solar Designer
 * Copyright (c) 2008,2009 by Dmitry V. Levin
 * See LICENSE
 */

#ifndef PASSWDQC_H__
#define PASSWDQC_H__

typedef struct {
	int min[5], max;
	int passphrase_words;
	int match_length;
	int similar_deny;
	int random_bits; // unused
} passwdqc_params_qc_t;

const char *passwdqc_check(const passwdqc_params_qc_t *params,
    const char *newpass, const char *oldpass, const char *name);

void passwdqc_free(char *dst);

#endif /* PASSWDQC_H__ */
