NAME=test-decode-from-heap

BUILDDIR=bin
SRC=$(NAME).c
LINUX=$(NAME)
WINDOWS=$(NAME)-32.exe
WINDOWS64=$(NAME)-64.exe

dir=@mkdir -p $(@D)

$(BUILDDIR)/$(LINUX): $(SRC)
	$(dir)
	clang $(SRC) -o $@
	rm -rf /tmp/ida; xvfb-run ida64 -c -A $@ 'Wait();qexit(0)' >/dev/null 2>&1 || true


$(BUILDDIR)/$(WINDOWS): $(SRC)
	$(dir)
	i686-w64-mingw32-clang -s $(SRC) -o $@
	rm -rf /tmp/ida; xvfb-run ida64 -c -A $@ 'Wait();qexit(0)' >/dev/null 2>&1 || true


$(BUILDDIR)/$(WINDOWS64): $(SRC)
	$(dir)
	x86_64-w64-mingw32-clang -s $(SRC) -o $@
	rm -rf /tmp/ida; xvfb-run ida64 -c -A $@ 'Wait();qexit(0)' >/dev/null 2>&1 || true


clean:
	rm -rf $(BUILDDIR)


all: $(BUILDDIR)/$(LINUX) $(BUILDDIR)/$(WINDOWS) $(BUILDDIR)/$(WINDOWS64)
