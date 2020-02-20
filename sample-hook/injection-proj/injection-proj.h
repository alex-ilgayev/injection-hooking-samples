// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the INJECTIONPROJ_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// INJECTIONPROJ_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef INJECTIONPROJ_EXPORTS
#define INJECTIONPROJ_API __declspec(dllexport)
#else
#define INJECTIONPROJ_API __declspec(dllimport)
#endif

// This class is exported from the dll
class INJECTIONPROJ_API Cinjectionproj {
public:
	Cinjectionproj(void);
	// TODO: add your methods here.
};

extern INJECTIONPROJ_API int ninjectionproj;

INJECTIONPROJ_API int fninjectionproj(void);
