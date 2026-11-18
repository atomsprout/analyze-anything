/* Fixture source for shared libraries / DLLs. */
#ifdef _WIN32
#define API __declspec(dllexport)
#else
#define API __attribute__((visibility("default")))
#endif
API int fixture_add(int a, int b) { return a + b; }
API int fixture_value = 42;
