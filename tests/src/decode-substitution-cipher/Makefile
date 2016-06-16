NAME=test-decode-substitution-cipher

BUILDDIR=bin
SRC=$(NAME).c
LINUX=$(NAME)
WINDOWS=$(NAME).exe
WINDOWS64=$(NAME)64.exe

dir=@mkdir -p $(@D)

$(BUILDDIR)/$(LINUX): $(SRC)
	$(dir)
	clang $(SRC) -o $@


$(BUILDDIR)/$(WINDOWS): $(SRC)
	$(dir)
	i686-w64-mingw32-clang $(SRC) -o $@


$(BUILDDIR)/$(WINDOWS64): $(SRC)
	$(dir)
	x86_64-w64-mingw32-clang $(SRC) -o $@


clean:
	rm -rf $(BUILDDIR)/*~ $(BUILDDIR)/*.bak $(BUILDDIR)/*.exe $(BUILDDIR)/*.viv $(BUILDDIR)/*.swp $(BUILDDIR)/$(LINUX)


all: $(BUILDDIR)/$(LINUX) $(BUILDDIR)/$(WINDOWS) $(BUILDDIR)/$(WINDOWS64)
