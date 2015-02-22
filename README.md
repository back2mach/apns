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

### Payload Alert(Plain Format)

```rust
let alert = apns::PayloadAPSAlert::Plain("Hello world");
```

### Payload Alert(Localized Format)

```rust
let alert = apns::PayloadAPSAlert::Localized(loc_key, loc_args);
```

### Send Payload

```rust
let aps = apns::PayloadAPS{alert: alert, badge: Some(1), sound: Some(sound), content_available: None};

// Custom data
let mut map = HashMap::new();
map.insert("source_id", "from");
map.insert("target_id", "to");
map.insert("message_type", "msg");
let payload = apns::Payload{aps: aps, info: Some(map)};

apns.send_payload(payload, device_token);
```

### Feedback Service

```rust
apns.get_feedback();
```




