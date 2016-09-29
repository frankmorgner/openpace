#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef _WIN32
#if defined(_MSC_VER) && (_MSC_VER >= 1900)
// needed for OpenSSL static link
// only for vs 2015 or later
#pragma comment(lib, "legacy_stdio_definitions.lib")
#include <stdio.h>
FILE * __cdecl __iob_func(void)
{
   static FILE *my_iob[3];
   my_iob[0] = stdin;
   my_iob[1] = stdout;
   my_iob[2] = stderr;
   return my_iob;
}
#endif

#if defined(_MSC_VER) && (_MSC_VER < 1700)
// only for vs 2012 or later
#include <Windows.h>
__declspec(noreturn) void __cdecl __report_rangecheckfailure()
{
	ExitProcess(1);
}
#endif
#endif
