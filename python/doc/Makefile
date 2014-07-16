# -*- makefile -*-

all: en link zip

en: .PHONY
	make -C en all

link:
	mkdir -p dist/en
	for b in $$(find en -name _build); do \
		pushd dist/en; \
		ln -s ../../$$b/html $$(basename $$(dirname $$b)); \
		popd; \
	done

zip: 
	echo "Foo"
	find en \( -name '*~' -o -name '#*#'  \) -print -delete
	rm smap-docs.zip
	cd dist && zip -r ../smap-docs.zip .

.PHONY:
