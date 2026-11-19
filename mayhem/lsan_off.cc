// Leak detection is off for every fuzz and standalone binary (SPEC 6.2 item 15);
// ASan and UBSan stay fully on.
extern "C" int __lsan_is_turned_off() { return 1; }
