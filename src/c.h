#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include "tomcrypt.h"

void perform_biometric_auth(void (*after_auth)(void* const, const char* const), void* const self);
