#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "hitch.h"

extern int fuzzy_main(int, char**);
static char* args[] = {
	"hitch", "--config=../fitch.conf", "--write-proxy-v2"
};
#define HITCH_PORT  "8080"

static SSL_CTX* ctx = NULL;

void LLVMFuzzerTestOneInput(const uint8_t* data, size_t len)
{
	static bool init = false;
	if (!init) {
		init = true;
		const size_t count = sizeof(args) / sizeof(args[0]);
		for (size_t i = 0; i < count; i++) args[i] = strdup(args[i]);
		fuzzy_main(count, args);

		ctx = SSL_CTX_new(TLSv1_2_method());
	}

	BIO* bio = BIO_new_ssl_connect(ctx);
	assert(bio != NULL);
	BIO_set_conn_hostname(bio, "127.0.0.1:" HITCH_PORT);

	int res = BIO_do_connect(bio);
	if (res == 1)
	{
		res = BIO_do_handshake(bio);
		assert(res == 1);
		SSL* ssl = NULL;
		BIO_get_ssl(bio, &ssl);
		SSL_write(ssl, data, len);
	}
	else {
		fprintf(stderr, "Connect failed\n");
	}
	BIO_free_all(bio);
}
