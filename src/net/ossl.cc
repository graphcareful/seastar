/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
 * Copyright 2015 Cloudius Systems
 */

#include <seastar/net/tls.hh>
#include <seastar/net/stack.hh>
#include <seastar/core/gate.hh>
#include <seastar/util/later.hh>

#include <openssl/provider.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

namespace seastar {

template<typename T, auto fn>
struct ssl_deleter {
    void operator()(T* ptr) { fn(ptr); }
};

template<typename T, auto fn>
using ssl_handle = std::unique_ptr<T, ssl_deleter<T, fn>>;

using bio_ptr = ssl_handle<BIO, BIO_free>;
using evp_pkey_ptr = ssl_handle<EVP_PKEY, EVP_PKEY_free>;
using x509_ptr = ssl_handle<X509, X509_free>;
using x509_store_ptr = ssl_handle<X509_STORE, X509_STORE_free>;
using x509_store_ctx_ptr = ssl_handle<X509_STORE_CTX, X509_STORE_CTX_free>;
using pkcs12 = ssl_handle<PKCS12, PKCS12_free>;
using ssl_ctx_ptr = ssl_handle<SSL_CTX, SSL_CTX_free>;
using ssl_ptr = ssl_handle<SSL, SSL_free>;

/// TODO: use non global ossl lib context
///
class tls::dh_params::impl {
public:
    static int level_to_bits(level l) {
        switch (l) {
            case level::LEGACY:
                return 1776;
            case level::MEDIUM:
                return 2432;
            case level::HIGH:
                return 3248;
            case level::ULTRA:
                return 15424;
            default:
                throw std::runtime_error(format("Unknown value of dh_params::level: {:d}", static_cast<std::underlying_type_t<level>>(l)));
        }
    }

    static evp_pkey_ptr make_evp_pkey(level l) {
        /// Instantiate new Diffie-Hellman key context
        EVP_PKEY *pkey = nullptr;
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(nullptr, "DH", nullptr);

        OSSL_PARAM params[3];
        unsigned int bits = level_to_bits(l);
        char group[] = "group";
        params[0] = OSSL_PARAM_construct_utf8_string("type", group, strlen(group));
        params[1] = OSSL_PARAM_construct_uint("pbits", &bits);
        params[2] = OSSL_PARAM_construct_end();

        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_CTX_set_params(pctx, params);
        EVP_PKEY_generate(pctx, &pkey);
        EVP_PKEY_CTX_free(pctx);
        return evp_pkey_ptr(pkey);
    }

    impl(level l) : _pkey(make_evp_pkey(l)) {}

    impl(EVP_PKEY* pkey) : _pkey(pkey) {}

    impl(const blob& pkcs3, x509_crt_format fmt)
        : _pkey([&] {
            bio_ptr key_bio(BIO_new_mem_buf(pkcs3.begin(), pkcs3.size()));
            auto pkey_temp = EVP_PKEY_new();
            if(fmt == x509_crt_format::PEM) {
                if (nullptr == PEM_read_bio_Parameters(key_bio.get(), &pkey_temp)) {
                    EVP_PKEY_free(pkey_temp);
                    throw std::system_error(0, error_category());
                }
            } else if (fmt == x509_crt_format::DER) {
                if(nullptr == d2i_KeyParams_bio(EVP_PKEY_DH, &pkey_temp, key_bio.get())){
                    EVP_PKEY_free(pkey_temp);
                    throw std::system_error(0, error_category());
                }
            } else {
                throw std::invalid_argument("Unknown x509_crt_format selected");
            }
            return evp_pkey_ptr(pkey_temp);
        }())
    {}

    EVP_PKEY* get() const { return _pkey.get(); }

    operator EVP_PKEY*() const { return _pkey.get(); }

private:
    evp_pkey_ptr _pkey;
};

class tls::certificate_credentials::impl {
    struct cert_key_pair{
        x509_ptr cert;
        evp_pkey_ptr key;
    };

public:
    impl() : _creds([] {
        auto store = X509_STORE_new();
        if(store == nullptr) {
            throw std::bad_alloc();
        }
        return store;
    }()) {}

    static X509* parse_x509_cert(const blob& b, x509_crt_format fmt, X509** cert){
        bio_ptr cert_bio(BIO_new_mem_buf(b.begin(), b.size()));
        X509* x509_cert = X509_new();
        if(fmt == tls::x509_crt_format::PEM) {
            if (nullptr == PEM_read_bio_X509(cert_bio.get(), &x509_cert, nullptr, nullptr)) {
                X509_free(x509_cert);
                return nullptr;
            }
        } else if(fmt == tls::x509_crt_format::DER) {
            if (nullptr == d2i_X509_bio(cert_bio.get(), &x509_cert)){
                X509_free(x509_cert);
                return nullptr;
            }
        }
        *cert = x509_cert;
        return *cert;
    }

    void set_x509_trust(const blob& b, x509_crt_format fmt) {
        auto store_ctx = x509_store_ctx_ptr(X509_STORE_CTX_new());
        X509* x509_cert = nullptr;
        if(nullptr == parse_x509_cert(b, fmt, &x509_cert)){
            throw std::system_error(0, tls::error_category());
        }
        X509_STORE_add_cert(*this, x509_cert);
    }

    void set_x509_crl(const blob& b, x509_crt_format fmt) {
        auto store_ctx = x509_store_ctx_ptr(X509_STORE_CTX_new());
        bio_ptr cert_bio(BIO_new_mem_buf(b.begin(), b.size()));
        X509_CRL* x509_crl = X509_CRL_new();
        if(fmt == x509_crt_format::PEM) {
            if (nullptr == PEM_read_bio_X509_CRL(cert_bio.get(), &x509_crl, nullptr, nullptr)){
                X509_CRL_free(x509_crl);
                throw std::system_error(0, tls::error_category());
            }
        } else if (fmt == x509_crt_format::DER){
            if (nullptr == d2i_X509_CRL_bio(cert_bio.get(), &x509_crl)){
                X509_CRL_free(x509_crl);
                throw std::system_error(0, tls::error_category());
            }
        } else {
            throw std::runtime_error("Unsupported cert format");
        }
        X509_STORE_add_crl(*this, x509_crl);
    }

    void set_x509_key(const blob& cert, const blob& key, x509_crt_format fmt) {
        // Theres no interface to add cert-key pair to the certificate store as
        // the store represents the root and intermediate chain. Exposed for later
        // use when the ssl socket is created
        X509* x509_tmp = nullptr;
        if(nullptr == parse_x509_cert(cert, fmt, &x509_tmp)){
            throw std::system_error(0, tls::error_category());
        }
        auto x509_cert = x509_ptr(x509_tmp);
        bio_ptr key_bio(BIO_new_mem_buf(key.begin(), key.size()));
        auto pkey_temp = EVP_PKEY_new();
        if (nullptr == PEM_read_bio_PrivateKey(key_bio.get(), &pkey_temp, nullptr, nullptr)) {
            EVP_PKEY_free(pkey_temp);
            throw std::system_error(0, tls::error_category());
        }
        auto pkey = evp_pkey_ptr(pkey_temp);
        _ck_pair = std::make_optional(cert_key_pair{.cert = std::move(x509_cert), .key = std::move(pkey)});
    }

    void set_simple_pkcs12(const blob& b, x509_crt_format fmt, const sstring& password) {
        // Load the PKCS12 file
        bio_ptr bio(BIO_new_mem_buf(b.begin(), b.size()));
        PKCS12 *p12_tmp = nullptr;
        if(nullptr == d2i_PKCS12_bio(bio.get(), &p12_tmp)) {
            throw std::system_error(0, tls::error_category());
        }
        auto p12 = pkcs12(p12_tmp);
        // Extract the certificate and private key from PKCS12, using provided password
        EVP_PKEY *pkey = nullptr;
        X509 *cert = nullptr;
        if (!PKCS12_parse(p12.get(), password.c_str(), &pkey, &cert, nullptr)) {
            throw std::system_error(0, tls::error_category());
        }
        X509_STORE_add_cert(*this, cert);
        EVP_PKEY_free(pkey);
    }

    void dh_params(const tls::dh_params& dh) {
        // Theres no interface to add DH params to the certificate store as the store
        // represents the root and intermediate chain. Exposed for later use when
        auto cpy = std::make_unique<tls::dh_params::impl>(dh._impl->get());
        _dh_params = std::move(cpy);
    }

    void set_client_auth(client_auth ca) {
        _client_auth = ca;
    }
    client_auth get_client_auth() const {
        return _client_auth;
    }

    operator X509_STORE*() const { return _creds.get(); }

    const std::optional<cert_key_pair>& get_cert_key_pair() const {
        return _ck_pair;
    }

private:
    friend class credentials_builder;
    friend class session;

    x509_store_ptr _creds;
    std::optional<cert_key_pair> _ck_pair;
    std::unique_ptr<tls::dh_params::impl> _dh_params;
    client_auth _client_auth = client_auth::NONE;
    bool _load_system_trust = false;
    dn_callback _dn_callback;
};

namespace tls {
class session : public enable_lw_shared_from_this<session> {
public:
    enum class type {
        CLIENT, SERVER
    };

    session(type t, shared_ptr<tls::certificate_credentials> creds,
            std::unique_ptr<net::connected_socket_impl> sock, tls_options options = {})
            : _type(t), _sock(std::move(sock)), _creds(creds->_impl),
              _in(_sock->source()), _out(_sock->sink()),
              _in_sem(1), _out_sem(1), _system_trust_sem(1), _options(std::move(options)),
            _rbio(BIO_new(BIO_s_mem())) , _wbio(BIO_new(BIO_s_mem())),
            _ctx(make_ssl_context()),
            _ssl(SSL_new(_ctx.get())) {
        if (!_ssl) {
            throw 5;
        }
        /// TODO: This hardcodes the ssl state to work in server mode
        SSL_set_accept_state(_ssl.get());
        // SSL_set_bio transfers ownership of the read and write bios to the SSL
        // instance
        SSL_set_bio(_ssl.get(), _rbio.get(), _wbio.get());
    }

    typedef temporary_buffer<char> buf_type;

    typedef net::fragment* frag_iter;

    future<> encrypt_and_send_data(){
        scattered_message<char> msg;
        return do_with(std::move(msg), [this](scattered_message<char>& msg){
            return repeat([this, &msg]{
                buf_type buf(4096);
                auto n = BIO_read(_wbio.get(), buf.get_write(), buf.size());
                msg.append(std::move(buf));
                if(n <= 0) {
                    return make_ready_future<stop_iteration>(stop_iteration::yes);
                }
                return make_ready_future<stop_iteration>(stop_iteration::no);
            }).then([this, &msg](){
                return _out.put(std::move(msg).release());
            });
        });
    }

    future<> do_put(frag_iter i, frag_iter e) {
        return do_for_each(i, e, [this](net::fragment& f){
            auto ptr = f.base;
            auto size = f.size;
            size_t off = 0;
            // SSL_write isn't guaranteed to write entire fragments at a time
            // continue to write until all is consumed by openssl
            return repeat([this, ptr, size, off]() mutable {
                if(off == size) {
                    return make_ready_future<stop_iteration>(stop_iteration::yes);
                }
                auto res = SSL_write(_ssl.get(), ptr + off, size - off);
                if(res > 0){
                    off += res;
                } else if(res < 0){
                    _error = std::make_exception_ptr(std::system_error(res, error_category()));
                    return make_exception_future<stop_iteration>(_error);
                }
                return encrypt_and_send_data().then([]{
                    return make_ready_future<stop_iteration>(stop_iteration::no);
                });
            });
        });
    }

    future<> put(net::packet p){
        if (_error) {
            return make_exception_future<>(_error);
        }
        if (!connected()) {
            return handshake().then([this, p = std::move(p)]() mutable {
               return put(std::move(p));
            });
        }
        /// TODO(rob) remove hardcoded constant
        /// Idea is to prevent multiple calls to SSL_write/BIO_read by combining
        /// the small amount of data into one fragment
        if (p.nr_frags() > 1 && p.len() <= 16000) {
            p.linearize();
        }

        auto i = p.fragments().begin();
        auto e = p.fragments().end();
        return with_semaphore(_out_sem, 1, std::bind(&session::do_put, this, i, e)).finally([p = std::move(p)] {});
    }

    future<> handshake() {
        if(connected()) {
            return make_ready_future<>();
        }
        // acquire both semaphores to sync both read & write
        return with_semaphore(_in_sem, 1, [this] {
            return with_semaphore(_out_sem, 1, [this] {
                /// TODO: Must we call wait for input first or will WANT_WRITE
                /// condition suffice?
                return do_handshake().handle_exception([this](auto ep) {
                    if (!_error) {
                        _error = ep;
                    }
                    return make_exception_future<>(_error);
                });
            });
        });
    }

    future<> do_handshake() {
        static const auto default_buffer_len = 4096;
        std::array<char, default_buffer_len> buf{};
        scattered_message<char> msg;
        auto n = SSL_accept(_ssl.get());
        auto ssl_err = SSL_get_error(_ssl.get(), n);
        switch (ssl_err) {
        case SSL_ERROR_NONE:
            break;
        case SSL_ERROR_WANT_READ:
        {
            do {
                // Here we need to read data out of the write bio (the bio
                // written to by the SSL session) to transport back to the
                // client
                n = BIO_read(_wbio.get(), buf.data(), buf.size());
                if (n > 0) {
                    msg.append_static(buf.data(), n);
                } else if (!BIO_should_retry(_wbio.get())) {
                    throw 5;
                }
            } while (n > 0);
            // Send data back to client
            auto p = std::move(msg).release();
            return do_put(p.fragments().begin(), p.fragments().end());
        }
        case SSL_ERROR_WANT_WRITE:
            // Expecting more data from the other end
            return wait_for_input().then(std::bind(&session::handshake, this));
        default:
            throw 5;
        }
        return make_ready_future<>();
    }

    future<buf_type> do_get() {
        // Check if there is encrypted data sitting in ssls internal buffers
        auto avail = SSL_pending(_ssl.get());
        buf_type buf(avail);
        if(avail < 0){
            // error
        } else if (avail == 0){
            return wait_for_input().then(std::bind(&session::do_get, this));
        }
        return do_with(std::move(buf), [this](buf_type& buf){
            return repeat([this, &buf](){
                // Read decrypted data from ssls internal buffers
                auto bytes_read = SSL_read(_ssl.get(), buf.get_write(), buf.size());
                if(bytes_read == 0) {
                    return make_ready_future<stop_iteration>(stop_iteration::yes);
                } else if(bytes_read < 0) {
                    /// error
                    return make_ready_future<stop_iteration>(stop_iteration::yes);
                }
                return make_ready_future<stop_iteration>(stop_iteration::no);
            }).then([&buf]{ return std::move(buf); });
        });
    }

    future<temporary_buffer<char>> get() {
        if (_error) {
            return make_exception_future<temporary_buffer<char>>(_error);
        }
        // if (_shutdown || eof()) {
        //     return make_ready_future<temporary_buffer<char>>();
        // }
        if (!connected()) {
            return handshake().then(std::bind(&session::get, this));
        }
        return with_semaphore(_in_sem, 1, std::bind(&session::do_get, this)).then([this](temporary_buffer<char> buf) {
            if (buf.empty()) { //  && !eof()) {
                return handshake().then(std::bind(&session::get, this));
            }
            return make_ready_future<temporary_buffer<char>>(std::move(buf));
        });
    }

private:
    bool connected() const {
        return SSL_is_init_finished(_ssl.get());
    }

    bool out_avail() const {
        return BIO_ctrl_pending(_wbio.get()) > 0;
    }

    bool in_avail() const {
        return BIO_ctrl_pending(_rbio.get()) > 0;
    }

    future<> wait_for_input() {
        if(in_avail()) {
            return make_ready_future<>();
        }
        return _in.get().then([this](buf_type buf){
            // Write the received data to the "read bio".  This bio is consumed
            // by the SSL struct.  Think of this of writing encrypted data into
            // the SSL session
            auto gh = _read_gate.hold();
            (void)do_with(std::move(buf), [this](auto& buf){
                return do_until(
                    [&buf]{ return buf.empty(); },
                    [&]{
                        int n = BIO_write(_rbio.get(), buf.get(), buf.size());
                        if(n == 0) {
                            // TODO: kosher?
                            return yield();
                        } else if (n < 0) {
                            return make_exception_future<>(std::system_error(0, std::system_category()));
                        }
                        buf.trim(n);
                        return make_ready_future();
                    });
            }).finally([gh]{});
        }).handle_exception([](auto ep){
            return make_exception_future(ep);
        });
    }

    ssl_ctx_ptr make_ssl_context(){
        // Make sure when creating the OpenSSL context, to use the correct library
        // context.  This ensures that the SSL_CTX uses shard local memory.

        /// TODO: Should be using the libcontext
        // auto ssl_ctx = SSL_CTX_ptr(SSL_CTX_new_ex(
        //     ssl_ctx_service.local().get_ossl_context(), nullptr, TLS_method()));

        if(_type != type::SERVER) {
            // For now only, servers are supported
            throw 5;
        }

        auto ssl_ctx = ssl_ctx_ptr(SSL_CTX_new(TLS_method()));
        if (!ssl_ctx) {
            throw 5;
        }

        // Do not verify the client's credentials, TODO: Configurable
        SSL_CTX_set_verify(ssl_ctx.get(), SSL_VERIFY_NONE, nullptr);
        SSL_CTX_set1_cert_store(ssl_ctx.get(), *_creds);
        if(!SSL_CTX_set0_tmp_dh_pkey(ssl_ctx.get(), *_creds->_dh_params)){
            throw 5;
        }

        auto& ck_pair = _creds->get_cert_key_pair();
        if(!ck_pair) {
            throw 5;
        }

        // Load private key and certificate and verify that the private key and
        // public key match.  Can also provide a cert chain here
        if (!SSL_CTX_use_cert_and_key(ssl_ctx.get(), ck_pair->cert.get(), ck_pair->key.get(), nullptr, 1)) {
            throw 5;
        }
        return ssl_ctx;
    }

private:
    type _type;

    std::unique_ptr<net::connected_socket_impl> _sock;
    shared_ptr<tls::certificate_credentials::impl> _creds;
    data_source _in;
    data_sink _out;
    std::exception_ptr _error;

    bool _maybe_load_system_trust = false;
    semaphore _in_sem, _out_sem, _system_trust_sem;
    tls_options _options;

    buf_type _input;
    gate _read_gate;
    bio_ptr _rbio, _wbio;
    ssl_ctx_ptr _ctx;
    ssl_ptr _ssl;
};
} // namespace tls
} // namespace seastar
