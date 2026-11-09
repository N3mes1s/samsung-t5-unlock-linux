PREFIX ?= /usr/local
SBINDIR ?= $(PREFIX)/sbin

CC ?= cc
CFLAGS ?= -O2
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Werror -fstack-protector-strong \
	-D_FORTIFY_SOURCE=2 -fPIE
LDFLAGS += -pie

.PHONY: all check clean install

all: samsung-t5-unlock

samsung-t5-unlock: samsung-t5-unlock.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

check: samsung-t5-unlock
	./samsung-t5-unlock --self-test
	@if ./samsung-t5-unlock --self-test --probe >/dev/null 2>&1; then \
		echo "mutually exclusive operation test failed" >&2; \
		exit 1; \
	fi

install: samsung-t5-unlock
	install -D -m 0755 samsung-t5-unlock \
		$(DESTDIR)$(SBINDIR)/samsung-t5-unlock

clean:
	rm -f samsung-t5-unlock samsung-t5-unlock-sanitize
