############################################################################
##
##  Makefile for go121pluswin7 dll.
##

ROOT = ..\Detours
!include "$(ROOT)\system.mak"

CPPFLAGS=/nologo /LD /W4 /WX /we4777 /we4800 /Zi /MT /Gy /Gm- /Od /I $(ROOT)\include\ /DDETOUR_DEBUG=$(DETOURS_DEBUG) /D_WIN32_WINNT=0x501
LINKFLAGS=/release /incremental:no /nodefaultlib:oldnames.lib /export:DetourFinishHelperProcess,@1,NONAME  /export:HookedCreateProcessInternal /export:HookedLoadLibraryEx  /export:HookedGetProcAddress

LIBS=$(LIBD)\detours.lib kernel32.lib bcrypt.lib

!IF "$(DETOURS_TARGET_PROCESSOR)" == "X64"
DLL_ARCH="x86_64"
!ELSEIF "$(DETOURS_TARGET_PROCESSOR)" == "X86"
DLL_ARCH="x86"
!ELSEIF "$(DETOURS_TARGET_PROCESSOR)" == "ARM"
DLL_ARCH="arm"
!ELSEIF "$(DETOURS_TARGET_PROCESSOR)" == "ARM64"
DLL_ARCH="arm64"
!ENDIF

############################################################################

.SUFFIXES: .cpp .dll .h .obj .rc .res

all: detours.lib \
	go121pluswin7_$(DLL_ARCH).dll 

clean:
	-del *~ 2>nul
	-del go121pluswin7_$(DLL_ARCH).dll 2>nul
	cd $(ROOT)\src && $(MAKE) clean

realclean: clean
	-del go121pluswin7_* 2>nul
	-del *.obj *.pdb 2>nul
	-del /q /s $(LIBD) 2>nul
	cd $(ROOT)\src && $(MAKE) realclean

go121pluswin7_$(DLL_ARCH).dll : go121pluswin7.cpp
	cl $(CPPFLAGS) /Fe$@ $** /link $(LINKFLAGS) $(LIBS)

detours.lib :
	cd $(ROOT)\src && $(MAKE)
