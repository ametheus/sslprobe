
ssl2-server: rsa1024.pem bin/openssl-098
	bin/openssl-098 s_server -ssl2 -accept 10200 -cert rsa1024.pem -debug -msg

rsa1024.pem: rsa1024.key
	openssl req -x509 -new -key rsa1024.key -subj '/C=BQ/L=Low Earth Orbit/OU=International Space Station/CN=localhost' -out rsa1024.crt -days 3653
	cat rsa1024.key rsa1024.crt > rsa1024.pem
	rm  rsa1024.key rsa1024.crt
rsa1024.key:
	openssl genrsa -out rsa1024.key 1024

github-openssl:
	git clone https://github.com/openssl/openssl.git github-openssl
bin/openssl-098: github-openssl
	cd github-openssl && git checkout -- .
	cd github-openssl && git clean -qfd
	cd github-openssl && git checkout OpenSSL_0_9_8-stable
	cd github-openssl && ./config no-shared
	cd github-openssl && make -j 4 build_apps
	mv github-openssl/apps/openssl bin/openssl-098

bin/custom-openssl: openssl-latest
	cd openssl-latest && ./config -DOPENSSL_DH_MAX_MODULUS_BITS=16000 no-shared && cd ..
	cd openssl-latest && make -j 4 build_apps && cd ..
	mv openssl-latest/apps/openssl bin/custom-openssl

openssl-latest: openssl-latest.tar.gz
	mkdir temp
	cd temp && tar -xf ../openssl-latest.tar.gz && cd ..
	mv temp/openssl-* openssl-latest
	rm -r temp

openssl-latest.tar.gz: Makefile
	wget -qO openssl-latest.tar.gz https://openssl.org/source/openssl-1.1.0-pre5.tar.gz

