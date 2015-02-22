# apns
APNS(Apple Push Notification Service) implemented in Rust

[![Build Status](https://travis-ci.org/back2mach/apns.svg?branch=master)](https://travis-ci.org/back2mach/apns)

### Config

```rust
let cert_file = Path::new("ck.pem");
let private_key_file = Path::new("no_pwd.pem");
let ca_file = Path::new("ca.pem");
let sandbox_environment = false;
let apns = apns::APNS::new(sandbox_environment, cert_file, private_key_file, ca_file);
```
### Send Payload

```rust
let alert = apns::PayloadAPSAlert{localized_key: loc_key, localized_args: vec![]};
let aps = apns::PayloadAPS{alert: alert, badge: Some(1), sound: Some(sound.mp4)};
let payload = apns::Payload{aps: aps, source_id: Some(source_id), message_type: Some(message_type), target_id: Some(target_id)};
apns.send_payload(payload, device_token);
```

### Feedback Service

```rust
apns.get_feedback();
```

