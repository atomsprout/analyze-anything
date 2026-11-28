/* Project-authored Apache-2.0 archive fixtures. No fixture code is ever executed. */
#ifdef AR_SECOND
int archive_fixture_version(void) { return 2; }
#else
int archive_fixture_add(int left, int right) { return left + right; }
#endif
