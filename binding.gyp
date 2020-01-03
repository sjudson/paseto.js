{
  "targets": [
    {
      "target_name": "extcrypto_addon",
      "sources": [ "./extcrypto/extcrypto.cc" ],
      "include_dirs": [ "<!(node -e \"require('nan')\")" ]
    }
  ]
}
