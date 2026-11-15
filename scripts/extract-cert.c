
// SPDX-License-Identifier: GPL-2.0
/*
 * Extract X.509 certificates from a PEM file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <err.h>

#include <openssl/opensslv.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#if OPENSSL_VERSION_NUMBER < 0x40000000L && !defined(OPENSSL_IS_BORINGSSL)
#include <openssl/engine.h>
#endif

#if OPENSSL_VERSION_NUMBER < 0x40000000L
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

static char *key_pass;
static BIO *wb;
static const char *cert_dst;
static bool kbuild_verbose;

static void display_openssl_errors(void)
{
	const char *file;
	const char *func;
	const char *data;
	int line;
	int flags;
	unsigned long e;

	while ((e = ERR_get_error_all(&file, &line, &func,
				      &data, &flags))) {
		if (kbuild_verbose) {
			fprintf(stderr,
				"OpenSSL error: %s:%d: %s\n",
				file ? file : "unknown",
				line,
				ERR_error_string(e, NULL));
			if (func)
				fprintf(stderr, "  Function: %s\n", func);
			if (data && (flags & ERR_TXT_STRING))
				fprintf(stderr, "  Data: %s\n", data);
		}
	}
}

#define ERR(cond, fmt, ...)					\
	do {							\
		if (cond) {					\
			display_openssl_errors();		\
			err(1, fmt, ##__VA_ARGS__);		\
		}						\
	} while (0)

static void write_cert(X509 *x509)
{
	if (!wb) {
		wb = BIO_new_file(cert_dst, "wb");
		ERR(!wb, "Can't open certificate output file %s",
		    cert_dst);
	}

	ERR(!i2d_X509_bio(wb, x509),
	    "Can't write certificate to %s", cert_dst);

	if (kbuild_verbose) {
		char *name = X509_NAME_oneline(
			X509_get_subject_name(x509), NULL, 0);

		if (name) {
			fprintf(stderr, "Extracted certificate: %s\n", name);
			OPENSSL_free(name);
		}
	}
}

static int pem_password_callback(char *buf, int size, int rwflag,
				 void *userdata)
{
	(void)rwflag;
	(void)userdata;

	if (!key_pass)
		return 0;

	if ((int)strlen(key_pass) >= size)
		return 0;

	memcpy(buf, key_pass, strlen(key_pass));
	return strlen(key_pass);
}

int main(int argc, char **argv)
{
	BIO *b;
	X509 *cert;
	const char *cert_src;
	const char *verbose_env;
	const char *pass_env;

	(void)argc;

	OpenSSL_add_all_algorithms();
	ERR_clear_error();

	verbose_env = getenv("KBUILD_VERBOSE");
	kbuild_verbose = verbose_env && atoi(verbose_env);

	pass_env = getenv("KBUILD_SIGN_PIN");
	if (pass_env)
		key_pass = strdup(pass_env);

	cert_src = argv[1];
	cert_dst = argv[2];

	if (!cert_src || !cert_dst)
		errx(1, "Usage: extract-cert <cert_src> <cert_dst>");

	if (!strcmp(cert_src, ""))
	{
		wb = BIO_new_file(cert_dst, "wb");
		ERR(!wb, "Can't create empty certificate file %s", cert_dst);
		BIO_free(wb);
		return 0;
	}

#if !defined(OPENSSL_IS_BORINGSSL)
	if (!strncmp(cert_src, "pkcs11:", 7)) {
#if OPENSSL_VERSION_NUMBER < 0x40000000L
		ENGINE *e;
		struct {
			const char *cert_id;
			const char *key_id;
		} parms = {
			.cert_id = cert_src,
			.key_id = NULL,
		};

		ENGINE_load_builtin_engines();
		e = ENGINE_by_id("pkcs11");
		ERR(!e, "Load PKCS#11 engine");

		ERR(!ENGINE_init(e), "Initialize PKCS#11 engine");

		if (key_pass)
			ERR(!ENGINE_ctrl_cmd_string(e, "PIN", key_pass, 0),
			    "Set PKCS#11 PIN");

		cert = ENGINE_load_certificate(e, parms.cert_id, NULL, NULL);
		ERR(!cert, "Load certificate from PKCS#11");

		write_cert(cert);
		X509_free(cert);

		ENGINE_finish(e);
		ENGINE_free(e);
#else
		errx(1,
		     "PKCS#11 certificates are not supported with OpenSSL 4.x");
#endif
		goto out;
	}
#endif

	b = BIO_new_file(cert_src, "rb");
	ERR(!b, "Can't open certificate file %s", cert_src);

	for (;;) {
		cert = PEM_read_bio_X509(b, NULL,
					 pem_password_callback, NULL);

		if (!cert) {
			unsigned long e = ERR_peek_last_error();

			if (wb && ERR_GET_LIB(e) == ERR_LIB_PEM &&
			    ERR_GET_REASON(e) == PEM_R_NO_START_LINE) {
				ERR_clear_error();
				break;
			}

			BIO_free(b);
			ERR(1, "Can't parse certificate file %s", cert_src);
		}

		write_cert(cert);
		X509_free(cert);
	}

	BIO_free(b);

out:
	if (wb)
		BIO_free(wb);

	free(key_pass);

	return 0;
}
