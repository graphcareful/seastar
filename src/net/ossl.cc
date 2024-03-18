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

#ifdef SEASTAR_MODULE
module;
#endif

#include <system_error>

#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/safestack.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#ifdef SEASTAR_MODULE
module seastar;
#else
#include "net/tls-impl.hh"
#include <seastar/net/tls.hh>
#include <seastar/core/sstring.hh>
#include <seastar/net/stack.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/with_timeout.hh>
#include <seastar/util/later.hh>
#endif

namespace seastar {

class ossl_error_category : public std::error_category {
public:
    constexpr ossl_error_category() noexcept : std::error_category{} {}
    const char * name() const noexcept override {
        return "OpenSSL";
    }
    std::string message(int) const override {
        return "";
    }
};

const std::error_category& tls::error_category() {
    static const ossl_error_category ec;
    return ec;
}

class ossl_error : public std::system_error {
public:
    ossl_error() : std::system_error(0, tls::error_category(), build_error()) {}

    ossl_error(const sstring& msg)
      : std::system_error(0, tls::error_category(), format("{}: {}", msg, build_error())) {}

    ossl_error(int ec, const sstring& msg)
      : std::system_error(ec, tls::error_category(), format("{}: {}", msg, build_error())) {}

private:
    static sstring build_error(){
        sstring msg = "{";
        std::array<char, 256> buf{};
        for (auto code = ERR_get_error(); code != 0; code = ERR_get_error()) {
            ERR_error_string_n(code, buf.data(), buf.size());
            msg += fmt::format("{{{}: {}}}", code, buf.data());
        }
        msg += "}";

        return msg;
    }
};

template<typename T, auto fn>
struct ssl_deleter {
    void operator()(T* ptr) { fn(ptr); }
};

template<typename T, auto fn>
using ssl_handle = std::unique_ptr<T, ssl_deleter<T, fn>>;

using bio_ptr = ssl_handle<BIO, BIO_free>;
using evp_pkey_ptr = ssl_handle<EVP_PKEY, EVP_PKEY_free>;
using x509_ptr = ssl_handle<X509, X509_free>;
using x509_crl_ptr = ssl_handle<X509_CRL, X509_CRL_free>;
using x509_store_ptr = ssl_handle<X509_STORE, X509_STORE_free>;
using x509_store_ctx_ptr = ssl_handle<X509_STORE_CTX, X509_STORE_CTX_free>;
using pkcs12 = ssl_handle<PKCS12, PKCS12_free>;
using ssl_ctx_ptr = ssl_handle<SSL_CTX, SSL_CTX_free>;
using ssl_ptr = ssl_handle<SSL, SSL_free>;

/// TODO: Implement the DH params impl struct
///
class tls::dh_params::impl {
public:
    impl(level) {}
    impl(const blob&, x509_crt_format){}

    EVP_PKEY* get() const { return _pkey.get(); }

    operator EVP_PKEY*() const { return _pkey.get(); }

private:
    evp_pkey_ptr _pkey;
};

tls::dh_params::dh_params(level lvl) : _impl(std::make_unique<impl>(lvl))
{}

tls::dh_params::dh_params(const blob& b, x509_crt_format fmt)
        : _impl(std::make_unique<impl>(b, fmt)) {
}

// TODO(rob) some small amount of code duplication here
tls::dh_params::~dh_params() {
}

tls::dh_params::dh_params(dh_params&&) noexcept = default;
tls::dh_params& tls::dh_params::operator=(dh_params&&) noexcept = default;

class tls::certificate_credentials::impl {
    struct server_credentials{
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

    static x509_ptr parse_x509_cert(const blob& b, x509_crt_format fmt){
        bio_ptr cert_bio(BIO_new_mem_buf(b.begin(), b.size()));
        switch(fmt) {
        case tls::x509_crt_format::PEM:
            return x509_ptr(PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr));
        case tls::x509_crt_format::DER:
            return x509_ptr(d2i_X509_bio(cert_bio.get(), nullptr));
        default:
            throw std::invalid_argument("Unsupported cert format");
        }
        return nullptr;
    }

    static x509_crl_ptr parse_x509_crl(const blob& b, x509_crt_format fmt){
        bio_ptr cert_bio(BIO_new_mem_buf(b.begin(), b.size()));
        switch(fmt) {
        case x509_crt_format::PEM:
            return x509_crl_ptr(PEM_read_bio_X509_CRL(cert_bio.get(), nullptr, nullptr, nullptr));
        case x509_crt_format::DER:
            return x509_crl_ptr(d2i_X509_CRL_bio(cert_bio.get(), nullptr));
        default:
            throw std::invalid_argument("Unsupported cert format");
        }
        return nullptr;
    }

    void set_x509_trust(const blob& b, x509_crt_format fmt) {
        auto store_ctx = x509_store_ctx_ptr(X509_STORE_CTX_new());
        if (!store_ctx) {
            throw ossl_error("Failed to allocate X509_STORE_CTX object");
        }
        if (auto x509_cert = parse_x509_cert(b, fmt)) {
            X509_STORE_add_cert(*this, x509_cert.get());
        } else {
            throw ossl_error("Failed to parse x509 trust");
        }
    }

    void set_x509_crl(const blob& b, x509_crt_format fmt) {
        auto store_ctx = x509_store_ctx_ptr(X509_STORE_CTX_new());
        if (!store_ctx) {
            throw ossl_error("Failed to allocate X509_STORE_CTX object");
        }
        if (auto x509_crl = parse_x509_crl(b, fmt)) {
            X509_STORE_add_crl(*this, x509_crl.get());
        } else {
            throw ossl_error("Failed to parse x509 CRL");
        }
    }

    void set_x509_key(const blob& cert, const blob& key, x509_crt_format fmt) {
        if(auto x509_cert = parse_x509_cert(cert, fmt)){
            bio_ptr key_bio(BIO_new_mem_buf(key.begin(), key.size()));
            if (auto pkey = evp_pkey_ptr(PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr))) {
                if (!X509_verify(x509_cert.get(), pkey.get())) {
                    throw ossl_error("Failed to verify cert/key pair");
                }
                X509_STORE_add_cert(*this, x509_cert.get());
                _server_creds = server_credentials{.cert = std::move(x509_cert), .key = std::move(pkey)};
            } else {
                throw ossl_error("Error attempting to parse private key");
            }
        } else {
            throw ossl_error("Error when attempting to parse x509 certificate");
        }
    }

    void set_simple_pkcs12(const blob& b, x509_crt_format fmt, const sstring& password) {
        // Load the PKCS12 file
        bio_ptr bio(BIO_new_mem_buf(b.begin(), b.size()));
        if (auto p12 = pkcs12(d2i_PKCS12_bio(bio.get(), nullptr))) {
            // Extract the certificate and private key from PKCS12, using provided password
            EVP_PKEY *pkey = nullptr;
            X509 *cert = nullptr;
            STACK_OF(X509) *ca = nullptr;
            if (!PKCS12_parse(p12.get(), password.c_str(), &pkey, &cert, &ca)) {
                throw ossl_error("Failed to extract cert key pair from pkcs12 file");
            }
            // Ensure signature validation checks pass before continuing
            if (!X509_verify(cert, pkey)) {
                X509_free(cert);
                EVP_PKEY_free(pkey);
                throw ossl_error("Failed to verify cert/key pair");
            }
            _server_creds = server_credentials{.cert = x509_ptr(cert), .key = evp_pkey_ptr(pkey)};
            X509_STORE_add_cert(*this, cert);
            // store retains certificate
            X509_free(cert);

            // Iterate through all elements in the certificate chain, adding them to the store
            if (ca != nullptr) {
                auto num_elements = sk_X509_num(ca);
                while (num_elements > 0) {
                    auto e = sk_X509_pop(ca);
                    X509_STORE_add_cert(*this, e);
                    // store retains certificate
                    X509_free(e);
                    num_elements -= 1;
                }
            }
        } else {
            throw ossl_error("Failed to parse pkcs12 file");
        }
    }

    void dh_params(const tls::dh_params&) {}

    std::vector<cert_info> get_x509_info() const {
        return {};
    }

    std::vector<cert_info> get_x509_trust_list_info() const {
        return {};
    }

    void set_client_auth(client_auth ca) {
        _client_auth = ca;
    }
    client_auth get_client_auth() const {
        return _client_auth;
    }

    void set_priority_string(const sstring&) {}

    void set_dn_verification_callback(dn_callback cb) {
        _dn_callback = std::move(cb);
    }

    operator X509_STORE*() const { return _creds.get(); }

    const server_credentials& get_server_credentials() const {
        return _server_creds;
    }

    future<> set_system_trust() {
        return make_ready_future<>();
    }

private:
    friend class credentials_builder;
    friend class session;

    x509_store_ptr _creds;

    server_credentials _server_creds;
    std::shared_ptr<tls::dh_params::impl> _dh_params;
    client_auth _client_auth = client_auth::NONE;
    // bool _load_system_trust = false;
    dn_callback _dn_callback;
};

tls::certificate_credentials::certificate_credentials()
        : _impl(make_shared<impl>()) {
}

tls::certificate_credentials::~certificate_credentials() {
}

tls::certificate_credentials::certificate_credentials(
        certificate_credentials&&) noexcept = default;
tls::certificate_credentials& tls::certificate_credentials::operator=(
        certificate_credentials&&) noexcept = default;

void tls::certificate_credentials::set_x509_trust(const blob& b,
        x509_crt_format fmt) {
    _impl->set_x509_trust(b, fmt);
}

void tls::certificate_credentials::set_x509_crl(const blob& b,
        x509_crt_format fmt) {
    _impl->set_x509_crl(b, fmt);

}
void tls::certificate_credentials::set_x509_key(const blob& cert,
        const blob& key, x509_crt_format fmt) {
    _impl->set_x509_key(cert, key, fmt);
}

void tls::certificate_credentials::set_simple_pkcs12(const blob& b,
        x509_crt_format fmt, const sstring& password) {
    _impl->set_simple_pkcs12(b, fmt, password);
}

future<> tls::certificate_credentials::set_system_trust() {
    return _impl->set_system_trust();
}

void tls::certificate_credentials::set_priority_string(const sstring& prio) {
    _impl->set_priority_string(prio);
}

void tls::certificate_credentials::set_dn_verification_callback(dn_callback cb) {
    _impl->set_dn_verification_callback(std::move(cb));
}

std::optional<std::vector<cert_info>> tls::certificate_credentials::get_cert_info() const noexcept {
    if (_impl == nullptr) {
        return std::nullopt;
    }

    try {
        auto result = _impl->get_x509_info();
        return result;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::vector<cert_info>> tls::certificate_credentials::get_trust_list_info() const noexcept {
    if (_impl == nullptr) {
        return std::nullopt;
    }

    try {
        auto result = _impl->get_x509_trust_list_info();
        return result;
    } catch (...) {
        return std::nullopt;
    }
}

void tls::certificate_credentials::enable_load_system_trust() {}

void tls::certificate_credentials::set_client_auth(client_auth ca) {
    _impl->set_client_auth(ca);
}

tls::server_credentials::server_credentials()
    : server_credentials(dh_params{})
{}

tls::server_credentials::server_credentials(shared_ptr<dh_params> dh)
    : server_credentials(*dh)
{}

tls::server_credentials::server_credentials(const dh_params& dh) {
    _impl->dh_params(dh);
}

tls::server_credentials::server_credentials(server_credentials&&) noexcept = default;
tls::server_credentials& tls::server_credentials::operator=(
        server_credentials&&) noexcept = default;

void tls::server_credentials::set_client_auth(client_auth ca) {
    _impl->set_client_auth(ca);
}

namespace tls {

/**
 * Session wraps gnutls session, and is the
 * actual conduit for an TLS/SSL data flow.
 *
 * We use a connected_socket and its sink/source
 * for IO. Note that we need to keep ownership
 * of these, since we handle handshake etc.
 *
 * The implmentation below relies on OpenSSL, for the gnutls implementation
 * see tls.cc and the CMake option 'Seastar_WITH_OSSL'
 */
class session : public enable_shared_from_this<session>, public session_impl {
public:
    typedef temporary_buffer<char> buf_type;
    typedef net::fragment* frag_iter;

    enum class type {
        CLIENT, SERVER
    };

    session(type t, shared_ptr<tls::certificate_credentials> creds,
            std::unique_ptr<net::connected_socket_impl> sock, sstring name = { }, std::optional<tls_options> options = std::nullopt)
            : _type(t), _sock(std::move(sock)), _creds(creds->_impl), _hostname(
                   std::move(name)), _in(_sock->source()), _out(_sock->sink()),
                   _in_sem(1), _out_sem(1),  _options(options.value_or(tls_options{})),
                   _in_bio(BIO_new(BIO_s_mem())) , _out_bio(BIO_new(BIO_s_mem())),
                   _ctx(make_ssl_context()),
                   _ssl(SSL_new(_ctx.get())) {
        if (!_ssl){
            BIO_free(_in_bio);
            BIO_free(_out_bio);
            throw ossl_error();
        }
        if (t == type::SERVER) {
            SSL_set_accept_state(_ssl.get());
        } else {
            SSL_set_connect_state(_ssl.get());
        }
        // SSL_set_bio transfers ownership of the read and write bios to the SSL instance
        SSL_set_bio(_ssl.get(), _in_bio, _out_bio);
    }

    session(type t, shared_ptr<certificate_credentials> creds,
            connected_socket sock, sstring name = { },
            std::optional<tls_options> options = std::nullopt)
            : session(t, std::move(creds), net::get_impl::get(std::move(sock)),
                      std::move(name), options) {}

    // This method pulls encrypted data from the SSL context and writes
    // it to the underlying socket.
    future<> pull_encrypted_and_send(){
        auto msg = make_lw_shared<scattered_message<char>>();
        return do_until(
            [this] { return BIO_ctrl_pending(_out_bio) == 0; },
            [this, msg]{
                // TODO(rob) avoid magic numbers
                buf_type buf(4096);
                auto n = BIO_read(_out_bio, buf.get_write(), buf.size());
                if (n > 0){
                    buf.trim(n);
                    msg->append(std::move(buf));
                } else if (!BIO_should_retry(_out_bio)) {
                    return make_exception_future<>(ossl_error());
                }
                return make_ready_future<>();
        }).then([this, msg](){
            if(msg->size() > 0){
                return _out.put(std::move(*msg).release());
            }
            return make_ready_future<>();
        });
    }

    // This method puts unencrypted data is written into the SSL context.
    // This data is later able to be retrieved in its encrypted form by reading
    // from the associated _out_bio
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
                auto bytes_written = SSL_write(_ssl.get(), ptr + off, size - off);
                if(bytes_written <= 0){
                    const auto ec = SSL_get_error(_ssl.get(), bytes_written);
                    if (ec == SSL_ERROR_WANT_READ || ec == SSL_ERROR_WANT_WRITE) {
                        /// TODO(rob) handle this condition
                    }
                    return make_exception_future<stop_iteration>(ossl_error());
                }
                off += bytes_written;
                /// Regardless of error, continue to send fragments
                return pull_encrypted_and_send().then([]{
                    return make_ready_future<stop_iteration>(stop_iteration::no);
                });
            });
        });
    }

    future<> put(net::packet p){
        if (_error) {
            return make_exception_future<>(_error);
        }
        if (_shutdown) {
            return make_exception_future<>(std::system_error(EPIPE, std::system_category()));
        }
        if (!connected()) {
            return handshake().then([this, p = std::move(p)]() mutable {
               return put(std::move(p));
            });
        }

        // We want to make sure that we write to the underlying bio with as large
        // packets as possible. This is because eventually this translates to a
        // sendmsg syscall. Further it results in larger TLS records which makes
        // encryption/decryption faster. Hence to avoid cases where we would do
        // an extra syscall for something like a 100 bytes header we linearize the
        // packet if it's below the max TLS record size.
        // TODO(Rob): Avoid magic numbers
        if (p.nr_frags() > 1 && p.len() <= 16000) {
            p.linearize();
        }

        auto i = p.fragments().begin();
        auto e = p.fragments().end();
        return with_semaphore(_out_sem, 1, std::bind(&session::do_put, this, i, e)).finally([p = std::move(p)] {});
    }

    future<> do_handshake() {
        if (connected()) {
            return make_ready_future<>();
        }
        if (_type == type::CLIENT && !_hostname.empty()) {
            SSL_set_tlsext_host_name(_ssl.get(), _hostname.data());
        }

        return do_until(
            [this]{ return connected() || eof(); },
            [this]{
                return wait_for_input().then([this]{
                    auto n = SSL_accept(_ssl.get());
                    auto ssl_err = SSL_get_error(_ssl.get(), n);
                    switch (ssl_err) {
                    case SSL_ERROR_NONE:
                        break;
                    case SSL_ERROR_WANT_READ:
                        return pull_encrypted_and_send();
                    case SSL_ERROR_WANT_WRITE:
                        break;
                    default:
                        return make_exception_future<>(ossl_error());
                    }
                    return make_ready_future<>();
                });
            });
    }

    future<> wait_for_input() {
        if (eof()) {
            return make_ready_future<>();
        }
        return _in.get().then([this](buf_type data) {
            if (data.empty()) {
                _eof = true;
                return make_ready_future<>();
            }
            // Write the received data to the "read bio".  This bio is consumed
            // by the SSL struct.  Think of this of writing encrypted data into
            // the SSL session
            auto buf = make_lw_shared<buf_type>(std::move(data));
            return do_until(
              [buf]{ return buf->empty(); },
              [this, buf]{
                  const auto n = BIO_write(_in_bio, buf->get(), buf->size());
                  if (n <= 0) {
                      return make_exception_future<>(ossl_error(n,  "Error while waiting for input"));
                  }
                  buf->trim_front(n);
                  return make_ready_future();
              }).finally([buf]{});
        }).handle_exception([](auto ep){
            return make_exception_future(ep);
        });
    }

    future<buf_type> do_get() {
        // Check if there is encrypted data sitting in ssls internal buffers, otherwise wait
        // for data and use a
        auto f = make_ready_future<>();
        auto avail = BIO_ctrl_pending(_in_bio);
        if (avail == 0) {
            if (eof()) {
                return make_ready_future<buf_type>(buf_type());
            }
            f = wait_for_input();
        }
        return f.then([this]() {
            const auto buf_size = 4096;
            buf_type buf(buf_size);
            // Read decrypted data from ssls internal buffers
            auto bytes_read = SSL_read(_ssl.get(), buf.get_write(), buf_size);
            if (bytes_read <= 0) {
                const auto ec = SSL_get_error(_ssl.get(), bytes_read);
                if (ec == SSL_ERROR_ZERO_RETURN && connected()) {
                    // Client has initiated shutdown by sending EOF
                    _eof = true;
                    close();
                    return make_ready_future<buf_type>(buf_type());
                }
                return make_exception_future<buf_type>(ossl_error(ec, "error via SSL_read"));
            }
            buf.trim(bytes_read);
            return make_ready_future<buf_type>(std::move(buf));
        });
    }

    future<buf_type> get() {
        if (_error) {
            return make_exception_future<temporary_buffer<char>>(_error);
        }
        if (_shutdown || eof()) {
            return make_ready_future<temporary_buffer<char>>(buf_type());
        }
        if (!connected()) {
            return handshake().then(std::bind(&session::get, this));
        }
        return with_semaphore(_in_sem, 1, std::bind(&session::do_get, this)).then([](temporary_buffer<char> buf) {
            // TODO(rob) - maybe re-handshake?
            return make_ready_future<temporary_buffer<char>>(std::move(buf));
        });
    }

    future<> do_shutdown() {
        /// TODO(rob) - Is yield the right option here
        if(_error || !connected()) {
            return make_ready_future();
        }
        auto res = SSL_shutdown(_ssl.get());
        if (res == 1){
            // Shutdown has completed successfully
            return make_ready_future<>();
        } else if (res == 0) {
            // Shutdown process is ongoing and has not yet completed, peer has not yet replied
            return yield().then([this](){
                return do_shutdown();
            });
        }
        // Shutdown was not successful
        auto f = make_ready_future<>();
        auto err = SSL_get_error(_ssl.get(), res);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE){
            if (err == SSL_ERROR_WANT_READ) {
                f = wait_for_input();
            }
            return f.then([]{ return yield(); }).then([this]{
                if (!eof()) {
                    return do_shutdown();
                }
                return make_ready_future<>();
            });
        }

        // Fatal error
        return make_exception_future<>(ossl_error(res, "fatal error during ssl shutdown"));
    }

    bool eof() const {
        return _eof;
    }

    bool connected() const {
        return SSL_is_init_finished(_ssl.get());
    }

    // Identical (or almost) portion of implementation
    //
    future<> wait_for_eof() {
        if (!_options.wait_for_eof_on_shutdown) {
            return make_ready_future();
        }

        // read records until we get an eof alert
        // since this call could time out, we must not ac
        return with_semaphore(_in_sem, 1, [this] {
            if (_error || !connected()) {
                return make_ready_future();
            }
            return repeat([this] {
                if (eof()) {
                    return make_ready_future<stop_iteration>(stop_iteration::yes);
                }
                return do_get().then([](auto) {
                   return make_ready_future<stop_iteration>(stop_iteration::no);
                });
            });
        });
    }
    future<> handshake() {
        // TODO(rob) - make this work
        // if (_creds->need_load_system_trust()) {
        //     return _creds->maybe_load_system_trust().then([this] {
        //        return handshake();
        //     });
        // }
        // acquire both semaphores to sync both read & write
        return with_semaphore(_in_sem, 1, [this] {
            return with_semaphore(_out_sem, 1, [this] {
                return do_handshake().handle_exception([this](auto ep) {
                    if (!_error) {
                        _error = ep;
                    }
                    return make_exception_future<>(_error);
                });
            });
        });
    }

    future<> shutdown() {
        // first, make sure any pending write is done.
        // bye handshake is a flush operation, but this
        // allows us to not pay extra attention to output state
        //
        // we only send a simple "bye" alert packet. Then we
        // read from input until we see EOF. Any other reader
        // before us will get it instead of us, and mark _eof = true
        // in which case we will be no-op.
        return with_semaphore(_out_sem, 1,
                        std::bind(&session::do_shutdown, this)).then(
                        std::bind(&session::wait_for_eof, this)).finally([me = shared_from_this()] {});
        // note moved finally clause above. It is theorethically possible
        // that we could complete do_shutdown just before the close calls
        // below, get pre-empted, have "close()" finish, get freed, and
        // then call wait_for_eof on stale pointer.
    }
    void close() noexcept {
        // only do once.
        if (!std::exchange(_shutdown, true)) {
            auto me = shared_from_this();
            // running in background. try to bye-handshake us nicely, but after 10s we forcefully close.
            (void)with_timeout(timer<>::clock::now() + std::chrono::seconds(10), shutdown()).finally([this] {
                _eof = true;
                try {
                    (void)_in.close().handle_exception([](std::exception_ptr) {}); // should wake any waiters
                } catch (...) {
                }
                try {
                    (void)_out.close().handle_exception([](std::exception_ptr) {});
                } catch (...) {
                }
                // make sure to wait for handshake attempt to leave semaphores. Must be in same order as
                // handshake aqcuire, because in worst case, we get here while a reader is attempting
                // re-handshake.
                return with_semaphore(_in_sem, 1, [this] {
                    return with_semaphore(_out_sem, 1, [] {});
                });
            }).then_wrapped([me = std::move(me)](future<> f) { // must keep object alive until here.
                f.ignore_ready_future();
            });
        }
    }
    // helper for sink
    future<> flush() noexcept {
        return with_semaphore(_out_sem, 1, [this] {
            return _out.flush();
        });
    }

    seastar::net::connected_socket_impl & socket() const {
        return *_sock;
    }

    future<std::optional<session_dn>> get_distinguished_name() {
        using result_t = std::optional<session_dn>;
        return make_exception_future<result_t>(std::nullopt);
    }

    future<std::vector<subject_alt_name>> get_alt_name_information(std::unordered_set<subject_alt_name_type>) {
        using result_t = std::vector<subject_alt_name>;
        return make_exception_future<result_t>(std::runtime_error("unimplemented"));
    }


private:
    std::optional<session_dn> extract_dn_information() const {
        return std::nullopt;
    }

    ssl_ctx_ptr make_ssl_context(){
        auto ssl_ctx = ssl_ctx_ptr(SSL_CTX_new(TLS_method()));
        if (!ssl_ctx) {
            throw ossl_error();
        }

        SSL_CTX_set_verify(ssl_ctx.get(), SSL_VERIFY_NONE, nullptr);
        SSL_CTX_set1_cert_store(_ctx.get(), *_creds);

        auto& server_creds = _creds->get_server_credentials();
        if (server_creds.cert == nullptr && server_creds.key == nullptr) {
            throw ossl_error("Certificate and key credentials missing");
        } else if (server_creds.key == nullptr) {
            if(!SSL_CTX_use_certificate(ssl_ctx.get(), server_creds.cert.get())) {
                throw ossl_error("Failed to load certificate");
            }
        } else {
            if (!SSL_CTX_use_cert_and_key(ssl_ctx.get(), server_creds.cert.get(), server_creds.key.get(), nullptr, 1)) {
                throw ossl_error("Failed to load cert/key pair");
            }
        }
        return ssl_ctx;
    }

private:
    type _type;

    std::unique_ptr<net::connected_socket_impl> _sock;
    shared_ptr<tls::certificate_credentials::impl> _creds;
    const sstring _hostname;
    data_source _in;
    data_sink _out;
    std::exception_ptr _error;

    bool _eof = false;
    // bool _maybe_load_system_trust = false;
    semaphore _in_sem, _out_sem;
    tls_options _options;

    bool _shutdown = false;
    buf_type _input;
    gate _read_gate;
    BIO* _in_bio;
    BIO* _out_bio;
    ssl_ctx_ptr _ctx;
    ssl_ptr _ssl;
};
} // namespace tls

future<connected_socket> tls::wrap_client(shared_ptr<certificate_credentials> cred, connected_socket&& s, sstring name, std::optional<tls_options> options) {
    session_ref sess(seastar::make_shared<session>(session::type::CLIENT, std::move(cred), std::move(s), std::move(name), options));
    connected_socket sock(std::make_unique<tls_connected_socket_impl>(std::move(sess)));
    return make_ready_future<connected_socket>(std::move(sock));
}

future<connected_socket> tls::wrap_server(shared_ptr<server_credentials> cred, connected_socket&& s) {
    session_ref sess(seastar::make_shared<session>(session::type::SERVER, std::move(cred), std::move(s)));
    connected_socket sock(std::make_unique<tls_connected_socket_impl>(std::move(sess)));
    return make_ready_future<connected_socket>(std::move(sock));
}

} // namespace seastar

// TODO(rob) fix
const int seastar::tls::ERROR_UNKNOWN_COMPRESSION_ALGORITHM = 0;
const int seastar::tls::ERROR_UNKNOWN_CIPHER_TYPE = 1;
const int seastar::tls::ERROR_INVALID_SESSION = 2;
const int seastar::tls::ERROR_UNEXPECTED_HANDSHAKE_PACKET = 3;
const int seastar::tls::ERROR_UNKNOWN_CIPHER_SUITE = 4;
const int seastar::tls::ERROR_UNKNOWN_ALGORITHM = 5;
const int seastar::tls::ERROR_UNSUPPORTED_SIGNATURE_ALGORITHM = 6;
const int seastar::tls::ERROR_SAFE_RENEGOTIATION_FAILED = 7;
const int seastar::tls::ERROR_UNSAFE_RENEGOTIATION_DENIED = 8;
const int seastar::tls::ERROR_UNKNOWN_SRP_USERNAME = 9;
const int seastar::tls::ERROR_PREMATURE_TERMINATION = 10;
