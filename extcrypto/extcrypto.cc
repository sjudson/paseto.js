// extcrypto.cc - some openssl wrappers to extend RSA support
#include <node.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/bn.h>

namespace extcrypto {

  using v8::Exception;
  using v8::Function;
  using v8::FunctionCallbackInfo;
  using v8::Isolate;
  using v8::Local;
  using v8::Null;
  using v8::Object;
  using v8::String;
  using v8::Value;


  void async_ret(Isolate* isolate, Local<Function> cb, Local<String> statement) {
    const unsigned argc = 2;
    Local<Value> argv[argc] = { Null(isolate), statement };

    cb->Call(Null(isolate), argc, argv);
  }


  void async_eret(Isolate* isolate, Local<Function> cb, Local<String> statement) {
    const unsigned argc = 1;
    Local<Value> argv[argc] = { Exception::Error(statement) };

    cb->Call(Null(isolate), argc, argv);
  }


  void keygen(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    Local<Function> cb;

    bool async = args.Length() > 0;
    if (async) { cb = Local<Function>::Cast(args[0]); }

    BIGNUM* exp = BN_new();
    BN_set_word(exp, RSA_F4); // 65537

    RSA* rsa    = RSA_new();
    unsigned kg = RSA_generate_key_ex(rsa, 2048, exp, NULL);

    if (!kg) {
      if (!async) {
        args.GetReturnValue().Set(String::NewFromUtf8(isolate, "Unable to generate key"));
        return;
      }

      return async_eret(isolate, cb, String::NewFromUtf8(isolate, "Unable to generate key"));
    }

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);

    unsigned kl = BIO_pending(bio);
    char* key   = (char *) calloc(kl + 1, 1);
    BIO_read(bio, key, kl);

    BIO_vfree(bio);
    RSA_free(rsa);
    BN_free(exp);

    if (!async) {
      args.GetReturnValue().Set(String::NewFromUtf8(isolate, key));
      return;
    }

    async_ret(isolate, cb, String::NewFromUtf8(isolate, key));
  }


  void extract(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate  = args.GetIsolate();
    Local<String> pem = Local<String>::Cast(args[0]);
    Local<Function> cb;

    bool async = args.Length() > 1;
    if (async) { cb = Local<Function>::Cast(args[1]); }

    String::Utf8Value ipem(pem);
    char* skey(*ipem);

    BIO* bio = BIO_new(BIO_s_mem());
    RSA* rsa = RSA_new();

    BIO_write(bio, skey, strlen(skey));
    PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL);
    PEM_write_bio_RSAPublicKey(bio, rsa);

    unsigned kl = BIO_pending(bio);
    char* pkey  = (char *) calloc(kl + 1, 1);
    BIO_read(bio, pkey, kl);

    BIO_vfree(bio);
    RSA_free(rsa);

    if (!async) {
      args.GetReturnValue().Set(String::NewFromUtf8(isolate, pkey));
      return;
    }

    async_ret(isolate, cb, String::NewFromUtf8(isolate, pkey));
  }


  void init(Local<Object> exports) {
    NODE_SET_METHOD(exports, "keygen", keygen);
    NODE_SET_METHOD(exports, "extract", extract);
  }


  NODE_MODULE(NODE_GYP_MODULE_NAME, init)
}
