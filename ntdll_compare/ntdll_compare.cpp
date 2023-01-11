#include "pch.h"
#include "ntdll/ntdll.h"

int main()
{
    while (true) { ntdll::ntdll_checking(); }
}