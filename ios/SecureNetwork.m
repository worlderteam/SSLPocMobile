#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(SecureNetwork, NSObject)

RCT_EXTERN_METHOD(provisionIdentity:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(postWithMTLS:(NSString *)endpoint
                  body:(NSString *)body
                  headers:(NSDictionary *)headers
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getWithMTLS:(NSString *)endpoint
                  headers:(NSDictionary *)headers
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

+ (BOOL)requiresMainQueueSetup {
  return NO;
}

@end