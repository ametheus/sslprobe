
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

