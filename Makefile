CC=gcc
OPENSSL_PREFIX := /opt/homebrew/opt/openssl
# CPPFLAGS=-Wall -Wextra
# LDFLAGS=
CPPFLAGS=-Wall -Wextra -I$(OPENSSL_PREFIX)/include
LDFLAGS=-L$(OPENSSL_PREFIX)/lib
LDLIBS=-lcrypto

DEPS=io.o libsecurity.o security.o

all: server client gen_cert

server: server.o $(DEPS)
client: client.o $(DEPS)
gen_cert: gen_cert.o $(DEPS)

clean:
	@find . -type f \
		! -name "*.c" \
		! -name "*.h" \
		! -name "*.cpp" \
		! -name "*.hpp" \
		! -name "Makefile" \
		! -name "README.md" -delete
	@find . -type d \( ! -name "." \) -exec rm -rf {} +
