TESTS= \
	decode-base64 \
	decode-rc4 \
	decode-single-byte-xor \
	decode-string-with-header \
	decode-from-global \
	decode-from-heap \
	decode-from-stack \
	decode-in-place \
	decode-global-stackstrings \
	decode-local-stackstrings \
	decode-split-stackstrings \
	decode-to-global \
	decode-to-heap \
	decode-to-output-buf \
	decode-to-stack \
	decode-string-by-index \
	decode-reencode-string \
	decode-wrapped-decoder \
	decode-to-stack-rep-mov \
    decode-substitution-cipher


clean:
	for test in $(TESTS); do \
		$(MAKE) -C $$test clean; \
	done


all:
	for test in $(TESTS); do \
		$(MAKE) -C $$test all; \
	done
