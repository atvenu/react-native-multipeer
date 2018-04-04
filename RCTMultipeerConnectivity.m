#import "RCTMultipeerConnectivity.h"
#import "RCTEventDispatcher.h"
//#import "ObjectStore.h"

@implementation RCTMultipeerConnectivity

@synthesize bridge = _bridge;

RCT_EXPORT_MODULE()

RCT_EXPORT_METHOD(advertise:(NSString *)channel data:(NSDictionary *)data) {
  self.advertiser =
  [[MCNearbyServiceAdvertiser alloc] initWithPeer:self.peerID discoveryInfo:data serviceType:channel];
  self.advertiser.delegate = self;
  [self.advertiser startAdvertisingPeer];
}

RCT_EXPORT_METHOD(stopAdvertising)
{
    [self.advertiser stopAdvertisingPeer];
}

RCT_EXPORT_METHOD(browse:(NSString *)channel)
{
  self.browser = [[MCNearbyServiceBrowser alloc] initWithPeer:self.peerID serviceType:channel];
  self.browser.delegate = self;
  [self.browser startBrowsingForPeers];
}

RCT_EXPORT_METHOD(stopBrowsing)
{
    [self.browser stopBrowsingForPeers];
}

RCT_EXPORT_METHOD(invite:(NSString *)peerUUID callback:(RCTResponseSenderBlock)callback) {
  MCPeerID *peerID = [self.peers valueForKey:peerUUID];
  [self.browser invitePeer:peerID toSession:self.session withContext:nil timeout:30];
  callback(@[[NSNull null]]);
}

RCT_EXPORT_METHOD(rsvp:(NSString *)inviteID accept:(BOOL)accept callback:(RCTResponseSenderBlock)callback) {
  void (^invitationHandler)(BOOL, MCSession *) = [self.invitationHandlers valueForKey:inviteID];
  invitationHandler(accept, self.session);
  [self.invitationHandlers removeObjectForKey:inviteID];
  callback(@[[NSNull null]]);
}

RCT_EXPORT_METHOD(broadcast:(NSDictionary *)data callback:(RCTResponseSenderBlock)callback) {
  [self sendData:[self.connectedPeers allKeys] data:data callback:callback];
}

RCT_EXPORT_METHOD(send:(NSArray *)recipients data:(NSDictionary *)data callback:(RCTResponseSenderBlock)callback) {
  [self sendData:recipients data:data callback:callback];
}

RCT_EXPORT_METHOD(disconnect:(RCTResponseSenderBlock)callback) {
  [self.session disconnect];
  callback(@[[NSNull null]]);
}

// TODO: Waiting for module interop and/or streams over JS bridge

//RCT_EXPORT_METHOD(createStreamForPeer:(NSString *)peerUUID name:(NSString *)name callback:(RCTResponseSenderBlock)callback) {
//  NSError *error = nil;
//  NSString *outputStreamUUID = [[ObjectStore shared] putObject:[self.session startStreamWithName:name toPeer:[self.peers valueForKey:peerUUID] error:&error]];
//  if (error != nil) {
//    callback(@[[error description]]);
//  }
//  else {
//    callback(@[[NSNull null], outputStreamUUID]);
//  }
//}

- (instancetype)init {
  self = [super init];
  self.peers = [NSMutableDictionary dictionary];
  self.connectedPeers = [NSMutableDictionary dictionary];
  self.invitationHandlers = [NSMutableDictionary dictionary];
  self.peerID = [[MCPeerID alloc] initWithDisplayName:[[NSUUID UUID] UUIDString]];
  NSArray *certs =  [NSArray arrayWithObject:(id)self.getClientCertificate];
  self.session = [[MCSession alloc] initWithPeer:self.peerID securityIdentity:certs encryptionPreference:MCEncryptionRequired];
  self.session.delegate = self;
    
  return self;
}

- (SecIdentityRef)getClientCertificate
{
    SecIdentityRef identity = nil;
//    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
//    NSString *documentsDirectoryPath = [paths objectAtIndex:0];
//    NSString *myFilePath = [documentsDirectoryPath stringByAppendingPathComponent:@"aps.p12"];
    NSString *myFilePath = [[NSBundle mainBundle] pathForResource:@"aps" ofType:@"p12"];
    NSLog(@"myFilePath: %@", myFilePath);
    NSData *PKCS12Data = [NSData dataWithContentsOfFile:myFilePath];
    
    CFDataRef inPKCS12Data = (__bridge CFDataRef)PKCS12Data;
    CFStringRef password = CFSTR("p");
    const void *keys[] = { kSecImportExportPassphrase };//kSecImportExportPassphrase };
    const void *values[] = { password };
    CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    OSStatus securityError = SecPKCS12Import(inPKCS12Data, options, &items);
    CFRelease(options);
    CFRelease(password);
    if (securityError == errSecSuccess) {
        NSLog(@"Success opening p12 certificate. Items: %ld", CFArrayGetCount(items));
        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
        identity = (SecIdentityRef)CFDictionaryGetValue(identityDict, kSecImportItemIdentity);
    } else {
        NSLog(@"Error opening Certificate.");
    }

    return identity;
}

- (void)sendData:(NSArray *)recipients data:(NSDictionary *)data callback:(RCTResponseSenderBlock)callback {
  NSError *error = nil;
  NSMutableArray *peers = [NSMutableArray array];
  for (NSString *peerUUID in recipients) {
    [peers addObject:[self.peers valueForKey:peerUUID]];
  }
  NSData *jsonData = [NSJSONSerialization dataWithJSONObject:data options:0 error:&error];
  [self.session sendData:jsonData toPeers:peers withMode:MCSessionSendDataReliable error:&error];
  if (error == nil) {
    callback(@[[NSNull null]]);
  }
  else {
    callback(@[[error description]]);
  }
}

- (void)browser:(MCNearbyServiceBrowser *)browser foundPeer:(MCPeerID *)peerID withDiscoveryInfo:(NSDictionary *)info {
  if ([peerID.displayName isEqualToString:self.peerID.displayName]) return;
  [self.peers setValue:peerID forKey:peerID.displayName];
  if (info == nil) {
    info = [NSDictionary dictionary];
  }
  [self.bridge.eventDispatcher sendDeviceEventWithName:@"RCTMultipeerConnectivityPeerFound"
                               body:@{
                                 @"peer": @{
                                   @"id": peerID.displayName,
                                   @"info": info
                                 }
                               }];
}

- (void)browser:(MCNearbyServiceBrowser *)browser lostPeer:(MCPeerID *)peerID {
  if ([peerID.displayName isEqualToString:self.peerID.displayName]) return;
  [self.bridge.eventDispatcher sendDeviceEventWithName:@"RCTMultipeerConnectivityPeerLost"
                               body:@{
                                 @"peer": @{
                                   @"id": peerID.displayName
                                 }
                               }];
  [self.peers removeObjectForKey:peerID.displayName];
}

- (void)advertiser:(MCNearbyServiceAdvertiser *)advertiser didReceiveInvitationFromPeer:(MCPeerID *)peerID withContext:(NSData *)context invitationHandler:(void (^)(BOOL accept, MCSession *session))invitationHandler {
  NSString *invitationUUID = [[NSUUID UUID] UUIDString];
  [self.invitationHandlers setValue:[invitationHandler copy] forKey:invitationUUID];
  [self.bridge.eventDispatcher sendDeviceEventWithName:@"RCTMultipeerConnectivityInviteReceived"
                              body:@{
                                @"invite": @{
                                  @"id": invitationUUID
                                },
                                @"peer": @{
                                  @"id": peerID.displayName
                                }
                              }];
}

- (void)session:(MCSession *)session peer:(MCPeerID *)peerID didChangeState:(MCSessionState)state {
  if ([peerID.displayName isEqualToString:self.peerID.displayName]) return;
  if (state == MCSessionStateConnected) {
    [self.connectedPeers setValue:peerID forKey:peerID.displayName];
    [self.bridge.eventDispatcher sendDeviceEventWithName:@"RCTMultipeerConnectivityPeerConnected"
                                 body:@{
                                   @"peer": @{
                                     @"id": peerID.displayName
                                   }
                                 }];
  }
  else if (state == MCSessionStateConnecting) {
    [self.bridge.eventDispatcher sendDeviceEventWithName:@"RCTMultipeerConnectivityPeerConnecting"
                                 body:@{
                                   @"peer": @{
                                     @"id": peerID.displayName
                                   }
                                 }];
  }
  else if (state == MCSessionStateNotConnected) {
    [self.bridge.eventDispatcher sendDeviceEventWithName:@"RCTMultipeerConnectivityPeerDisconnected"
                                 body:@{
                                   @"peer": @{
                                     @"id": peerID.displayName
                                   }
                                 }];
    [self.connectedPeers removeObjectForKey:peerID.displayName];

  }
}
- (void)session:(MCSession *)session didReceiveCertificate:(NSArray *)certificate fromPeer:     (MCPeerID *)peerID certificateHandler:(void (^)(BOOL accept))certificateHandler
{
    
    SecCertificateRef myCert;
    myCert = (__bridge SecCertificateRef)[certificate objectAtIndex:0];    // 1
    
    SecPolicyRef myPolicy = SecPolicyCreateBasicX509();         // 2
//    SecPolicyRef myPolicy = SecPolicyCreateSSL(YES, CFSTR("www.atvenu.com"));
    
    SecCertificateRef certArray[1] = { myCert };
    CFArrayRef myCerts = CFArrayCreate(
                                       NULL, (void *)certArray,
                                       1, NULL);
    SecTrustRef myTrust;
    OSStatus status = SecTrustCreateWithCertificates(
                                                     myCerts,
                                                     myPolicy,
                                                     &myTrust);  // 3
    NSArray* anchors = @[ (__bridge id)myCert ];
    SecTrustSetAnchorCertificates(myTrust,(__bridge CFTypeRef)anchors);
    
    SecTrustResultType trustResult;
    if (status == noErr) {
        status = SecTrustEvaluate(myTrust, &trustResult);       // 4
    }
    
    status = SecTrustGetTrustResult(myTrust, &trustResult);
    
    //...
    if (trustResult == kSecTrustResultConfirm || trustResult == kSecTrustResultProceed || trustResult == kSecTrustResultUnspecified)                           // 5
    {
        certificateHandler(YES);
    }
    
    // ...
    if (myPolicy)
        CFRelease(myPolicy);
}

// TODO: Waiting for module interop and/or streams over JS bridge

//- (void)session:(MCSession *)session didReceiveStream:(NSInputStream *)stream withName:(NSString *)streamName fromPeer:(MCPeerID *)peerID {
//  NSString *streamId = [[ObjectStore shared] putObject:stream];
//  [self.bridge.eventDispatcher sendDeviceEventWithName:@"RCTMultipeerConnectivityStreamOpened"
//                               body:@{
//                                 @"stream": @{
//                                   @"id": streamId,
//                                   @"name": streamName
//                                 },
//                                 @"peer": @{
//                                   @"id": peerID.displayName
//                                 }
//                               }];
//}

- (void)session:(MCSession *)session didReceiveData:(NSData *)data fromPeer:(MCPeerID *)peerID {
  NSError *error = nil;
  id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
  NSDictionary *parsedJSON = [NSDictionary dictionary];

  if([object isKindOfClass:[NSDictionary class]]) {
    parsedJSON = object;
  }

  [self.bridge.eventDispatcher sendDeviceEventWithName:@"RCTMultipeerConnectivityDataReceived"
                               body:@{
                                 @"sender": @{
                                   @"id": peerID.displayName
                                 },
                                 @"data": parsedJSON
                               }];
}

// TODO: Support file transfers once we have a general spec for representing files
//
//- (void)session:(MCSession *)session didFinishReceivingResourceWithName:(NSString *)resourceName fromPeer:(MCPeerID *)peerID atURL:(NSURL *)localURL withError:(NSError *)error {
//  NSURL *destinationURL = [NSURL fileURLWithPath:@"/path/to/destination"];
//  if (![[NSFileManager defaultManager] moveItemAtURL:localURL toURL:destinationURL error:&error]) {
//    NSLog(@"[Error] %@", error);
//  }
//}
//
//- (void)session:(MCSession *)session
//didStartReceivingResourceWithName:(NSString *)resourceName fromPeer:(MCPeerID *)peerID withProgress:(NSProgress *)progress
//{
//
//}


@end
