// injection-proj.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "injection-proj.h"


// This is an example of an exported variable
INJECTIONPROJ_API int ninjectionproj=0;

// This is an example of an exported function.
INJECTIONPROJ_API int fninjectionproj(void)
{
    return 0;
}

// This is the constructor of a class that has been exported.
Cinjectionproj::Cinjectionproj()
{
    return;
}
