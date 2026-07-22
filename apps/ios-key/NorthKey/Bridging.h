// Exposes the vendored C crypto to Swift: Argon2id (reference implementation, built with
// ARGON2_NO_THREADS) and zstd (built with ZSTD_DISABLE_ASM). Header search paths for these
// come from project.yml (Vendor/argon2/include, Vendor/zstd).

#include "argon2.h"
#include "zstd.h"
