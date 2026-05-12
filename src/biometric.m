@import LocalAuthentication;

void perform_biometric_auth(void (*after_auth)(void* const, const char* const), void* const self) {
    @autoreleasepool {
        LAContext* ctx = [[LAContext alloc] init];
        [ctx evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
            localizedReason:@"Unlock the vault"
                      reply:^(BOOL success, NSError* error) {
                        const char* err_message = NULL;
                        if (!success) {
                            err_message = error.localizedDescription.UTF8String;
                        }
                        after_auth(self, err_message);
                      }];
    }
}
