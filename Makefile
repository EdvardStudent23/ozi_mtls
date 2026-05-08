# Makefile — orchestration for mTLS coursework + protocol comparison demo
.PHONY: pki serve serve-tls12 client-ok client-no-cert negative-tests \
        serve-http http-client serve-https https-client serve-ssh ssh-client \
        capture-valid capture-no-cert capture-wrong-ca \
        capture-http capture-https capture-ssh \
        decrypt-help clean

PYTHON ?= python3
KEYLOG ?= captures/keys.keylog
HTTP_PORT ?= 18080

# --- PKI ---

pki:
	bash pki/gen_pki.sh

# --- mTLS (port 8443) ---

serve:
	mkdir -p captures
	SSLKEYLOGFILE=$(KEYLOG) $(PYTHON) server.py --tls 1.3 --log INFO

serve-tls12:
	mkdir -p captures
	SSLKEYLOGFILE=$(KEYLOG) $(PYTHON) server.py --tls 1.2 --log INFO

client-ok:
	mkdir -p captures
	SSLKEYLOGFILE=$(KEYLOG) $(PYTHON) client.py --tls 1.3 --message "valid hello"

client-no-cert:
	mkdir -p captures
	SSLKEYLOGFILE=$(KEYLOG) $(PYTHON) client.py --tls 1.3 --no-client-cert --message "should fail"

# negative-tests: runs tests/negative.sh — generates rogue/expired certs on the fly,
# attempts mTLS handshake, expects server rejection. Server must already be running.
negative-tests:
	bash tests/negative.sh

# --- mTLS captures (run alongside the matching server) ---

capture-valid:
	sudo tcpdump -i lo0 -w captures/01_valid.pcapng "port 8443"

capture-no-cert:
	sudo tcpdump -i lo0 -w captures/02_no_client_cert.pcapng "port 8443"

capture-wrong-ca:
	sudo tcpdump -i lo0 -w captures/03_wrong_ca.pcapng "port 8443"

# --- Comparison protocols ---
# HTTP uses port 18080 because 8080 is occupied by Burp Suite on this host.

serve-http:
	$(PYTHON) compare/http_server.py --port $(HTTP_PORT)

http-client:
	$(PYTHON) compare/http_client.py --port $(HTTP_PORT)

serve-https:
	mkdir -p captures
	SSLKEYLOGFILE=$(KEYLOG) $(PYTHON) compare/https_server.py

https-client:
	mkdir -p captures
	SSLKEYLOGFILE=$(KEYLOG) $(PYTHON) compare/https_client.py

serve-ssh:
	$(PYTHON) compare/ssh_server.py

ssh-client:
	$(PYTHON) compare/ssh_client.py

capture-http:
	sudo tcpdump -i lo0 -w captures/06_plain_http.pcapng "port $(HTTP_PORT)"

capture-https:
	sudo tcpdump -i lo0 -w captures/07_https_server_only.pcapng "port 8444"

capture-ssh:
	sudo tcpdump -i lo0 -w captures/08_ssh.pcapng "port 2222"

decrypt-help:
	@echo "У Wireshark: Edit > Preferences > Protocols > TLS"
	@echo "  (Pre)-Master-Secret log filename = $(PWD)/$(KEYLOG)"

clean:
	rm -rf captures/*.pcapng captures/*.keylog
	rm -f pki/*.pem pki/*.key pki/*.srl pki/ssh_*
