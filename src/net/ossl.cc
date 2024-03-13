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
#include <seastar/util/log.hh>
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

logger netlogger("net");

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

    static std::shared_ptr<EVP_PKEY> make_evp_pkey(level l) {
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
        return std::shared_ptr<EVP_PKEY>(pkey, [](EVP_PKEY * ptr){
            EVP_PKEY_free(ptr);
        });
    }

    impl(level l) : _pkey(make_evp_pkey(l)) {}

    impl(const blob& pkcs3, x509_crt_format fmt)
        : _pkey([&] {
            bio_ptr key_bio(BIO_new_mem_buf(pkcs3.begin(), pkcs3.size()));
            EVP_PKEY* pkey_temp = EVP_PKEY_new();
            if(fmt == x509_crt_format::PEM) {
                if (nullptr == PEM_read_bio_Parameters(key_bio.get(), &pkey_temp)) {
                    EVP_PKEY_free(pkey_temp);
                    throw ossl_error();
                }
            } else if (fmt == x509_crt_format::DER) {
                if(nullptr == d2i_KeyParams_bio(EVP_PKEY_DH, &pkey_temp, key_bio.get())){
                    EVP_PKEY_free(pkey_temp);
                    throw ossl_error();
                }
            } else {
                throw std::invalid_argument("Unknown x509_crt_format selected");
            }
            return std::shared_ptr<EVP_PKEY>(pkey_temp, [](auto ptr){
                EVP_PKEY_free(ptr);
            });
        }())
    {}

    EVP_PKEY* get() const { return _pkey.get(); }

    operator EVP_PKEY*() const { return _pkey.get(); }

private:
    std::shared_ptr<EVP_PKEY> _pkey;
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
            throw ossl_error();
        }
        X509_STORE_add_cert(*this, x509_cert);
        _certs.push_back(x509_ptr(x509_cert));
    }

    void set_x509_crl(const blob& b, x509_crt_format fmt) {
        auto store_ctx = x509_store_ctx_ptr(X509_STORE_CTX_new());
        bio_ptr cert_bio(BIO_new_mem_buf(b.begin(), b.size()));
        X509_CRL* x509_crl = X509_CRL_new();
        if(fmt == x509_crt_format::PEM) {
            if (nullptr == PEM_read_bio_X509_CRL(cert_bio.get(), &x509_crl, nullptr, nullptr)){
                X509_CRL_free(x509_crl);
                throw ossl_error();
            }
        } else if (fmt == x509_crt_format::DER){
            if (nullptr == d2i_X509_CRL_bio(cert_bio.get(), &x509_crl)){
                X509_CRL_free(x509_crl);
                throw ossl_error();
            }
        } else {
            throw std::invalid_argument("Unsupported cert format");
        }
        X509_STORE_add_crl(*this, x509_crl);
        _crls.push_back(x509_crl_ptr(x509_crl));
    }

    void set_x509_key(const blob& cert, const blob& key, x509_crt_format fmt) {
        // Theres no interface to add cert-key pair to the certificate store as
        // the store represents the root and intermediate chain. Exposed for later
        // use when the ssl socket is created
        X509* x509_tmp = nullptr;
        if(nullptr == parse_x509_cert(cert, fmt, &x509_tmp)){
            throw ossl_error();
        }
        auto x509_cert = x509_ptr(x509_tmp);
        bio_ptr key_bio(BIO_new_mem_buf(key.begin(), key.size()));
        auto pkey_temp = EVP_PKEY_new();
        if (nullptr == PEM_read_bio_PrivateKey(key_bio.get(), &pkey_temp, nullptr, nullptr)) {
            EVP_PKEY_free(pkey_temp);
            throw ossl_error();
        }
        auto pkey = evp_pkey_ptr(pkey_temp);
        _ck_pair = std::make_optional(cert_key_pair{.cert = std::move(x509_cert), .key = std::move(pkey)});
    }

    void set_simple_pkcs12(const blob& b, x509_crt_format fmt, const sstring& password) {
        // Load the PKCS12 file
        bio_ptr bio(BIO_new_mem_buf(b.begin(), b.size()));
        PKCS12 *p12_tmp = nullptr;
        if(nullptr == d2i_PKCS12_bio(bio.get(), &p12_tmp)) {
            throw ossl_error();
        }
        auto p12 = pkcs12(p12_tmp);
        // Extract the certificate and private key from PKCS12, using provided password
        EVP_PKEY *pkey = nullptr;
        X509 *cert = nullptr;
        if (!PKCS12_parse(p12.get(), password.c_str(), &pkey, &cert, nullptr)) {
            throw ossl_error();
        }
        X509_STORE_add_cert(*this, cert);
        EVP_PKEY_free(pkey);
    }

    std::vector<cert_info> get_x509_info() const {
        return {};
    }

    std::vector<cert_info> get_x509_trust_list_info() const {
        return {};
    }

    void dh_params(const tls::dh_params& dh) {
        auto cpy = std::make_shared<tls::dh_params::impl>(*dh._impl);
        _dh_params = std::move(cpy);
    }

    void set_client_auth(client_auth ca) {
        _client_auth = ca;
    }
    client_auth get_client_auth() const {
        return _client_auth;
    }

    void set_priority_string(const sstring& prio) {
        // if (SSL_set_cipher_list(_ssl.get(), prio) != 1) {
        // if (SSL_CTX_set_cipher_list(_ctx.get(), prio) != 1) {
        //     // Handle error
        // }
    }

    void set_dn_verification_callback(dn_callback cb) {
        _dn_callback = std::move(cb);
    }


    operator X509_STORE*() const { return _creds.get(); }

    const std::optional<cert_key_pair>& get_cert_key_pair() const {
        return _ck_pair;
    }

    future<> set_system_trust() {
        /// TODO: Must have access to the ssl context to call this method
        /// SSL_CTX_set0_verify_cert_store(_ssl.get(), _creds.get());
        // _load_system_trust = false;
        return make_ready_future<>();
    }

    // bool need_load_system_trust() const {
    //     return _load_system_trust;
    // }

private:
    friend class credentials_builder;
    friend class session;

    x509_store_ptr _creds;

    // Must retain the certs and CRLs as X509_STORE_add_cert will not take
    // ownership of the pointers when certs are added to the store
    std::vector<x509_ptr> _certs;
    std::vector<x509_crl_ptr> _crls;
    std::optional<cert_key_pair> _ck_pair;
    std::shared_ptr<tls::dh_params::impl> _dh_params;
    client_auth _client_auth = client_auth::NONE;
    // bool _load_system_trust = false;
    dn_callback _dn_callback;
};

/// TODO(rob) - some code duplication here
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

void tls::certificate_credentials::enable_load_system_trust() {
    // _impl->_load_system_trust = true;
}

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

class scattered_bio {
public:
    explicit scattered_bio(sstring name, data_sink& out) : _name(name), _out(out) {
        initialize_bio();
    }

    ~scattered_bio() {
        // assert(_closed);
        if (_bio != nullptr) {
            BIO_free(_bio);
        }
        if (_method != nullptr) {
            BIO_meth_free(_method);
        }
    }

    BIO* bio() const {
        return _bio;
    }

    bool empty() const { return _p.len() == 0; }

    void bio_clear() {
        BIO_clear_retry_flags(_bio);
    }

    future<> do_flush() {
        if (!empty()) {
            auto old_p = std::exchange(_p, net::packet());
            netlogger.info("Inside do flush! {} - writing {} bytes", _name, old_p.len());
            return _out.put(std::move(old_p)).then([this](){ return _out.flush(); });
        }
        return make_ready_future<>();
    }


private:
    static scattered_bio* from_stored_bio_ptr(void* ptr) {
        return static_cast<scattered_bio*>(ptr);
    }

    static int do_bio_write(BIO* bio, const char * data, int size) {
        netlogger.info("Within scattered_bio::do_bio_write");
        if (!bio || !data) {
            return 0;
        }

        scattered_bio* ptr = from_stored_bio_ptr(BIO_get_data(bio));
        if (ptr == nullptr || ptr->_bio != bio) {
            return 0;
        }

        if (size == 0) {
            ptr->_closed = true;
            return 0;
        }
        netlogger.info("Performing scattered_bio::do_bio_write: {} - size: {}", ptr->_name, size);
        ptr->_p.append(net::packet(data, size_t(size)));
        return size;
    }

    static int do_bio_read(BIO* bio, char * data, int size) {
        netlogger.info("Within scattered_bio::do_read");

        if (!bio || !data) {
            return 0;
        }

        scattered_bio *ptr = from_stored_bio_ptr(BIO_get_data(bio));
        if (ptr == nullptr || ptr->_bio != bio) {
            return 0;
        }

        if (ptr->_p.len() == 0) {
            // indicate theres no data, retry later
            BIO_set_retry_read(ptr->_bio);
            return -1;
        }

        netlogger.info("Performing scattered_bio::do_read: {}", ptr->_name);
        const auto begin = ptr->_p.fragments().begin();
        const auto end = ptr->_p.fragments().end();
        auto cur = begin;
        size_t bytes_read = 0;
        netlogger.info("Total buffer size: {} requested read: {}", ptr->_p.len(), size);

        while(cur != end && bytes_read < size) {
            const auto bytes_remaining = size - bytes_read;
            const auto bytes_to_copy = std::min(cur->size, bytes_remaining);
            netlogger.info("Frag size: {}, Bytes remaining: {}, to copy: {}", cur->size, bytes_remaining, bytes_to_copy);
            std::memcpy(data, cur->base, bytes_to_copy);
            data += bytes_to_copy;
            bytes_read += bytes_to_copy;
            cur++;
        }
        ptr->_p.trim_front(bytes_read);
        netlogger.info("Bytes read: {}", bytes_read);
        return bytes_read;
    }

    static long do_bio_ctrl(BIO* bio, int cmd, long larg, void* parg) {
        if (!bio) {
            return 0;
        }

        scattered_bio *ptr = from_stored_bio_ptr(BIO_get_data(bio));
        if (ptr == nullptr || ptr->_bio != bio) {
            return 0;
        }
        // netlogger.info("Performing scattered_bio::do_bio_ctrl: {}", cmd);

        switch(cmd) {
        case BIO_CTRL_RESET:
            ptr->_p = net::packet();
            ptr->_closed = false;
            break;
        case BIO_CTRL_EOF:
            return 0;
        case BIO_CTRL_FLUSH:
            // ptr->do_flush().get();
            return 1;
        case BIO_CTRL_GET_CLOSE:
            return ptr->_closed;
        case BIO_CTRL_SET_CLOSE:
            ptr->_closed = (bool)larg;
            break;
        case BIO_CTRL_PENDING:
            return ptr->_p.len();
        case BIO_CTRL_GET_KTLS_RECV:
        case BIO_CTRL_GET_KTLS_SEND:
            // Explicity ignore
            return 1;
        default:
            // Unsupported command
            // netlogger.info("do_bio_ctrl didn't run unsupported command: {}", cmd);
            return 0;
        };
        // Success
        return 1;
    }

    static int do_bio_gets(BIO *, char *, int) {
        netlogger.info("inside do_bio_gets");
        return 1;
    }

    static int do_bio_puts(BIO*, const char*) {
        netlogger.info("inside do_bio_puts");
        return 1;
    }

    void initialize_bio() {
        const int index = BIO_get_new_index();
        if (index < 0) {
            throw ossl_error("Couldn't get index for BIO_METHOD");
        }

        _method = BIO_meth_new(index | BIO_TYPE_MEM, "scattered_bio");
        if (_method == nullptr) {
            throw ossl_error("Couldn't allocate BIO_METHOD");
        }

        BIO_meth_set_write(_method, &do_bio_write);
        BIO_meth_set_read(_method, &do_bio_read);
        BIO_meth_set_ctrl(_method, &do_bio_ctrl);
        BIO_meth_set_puts(_method, &do_bio_puts);
        BIO_meth_set_gets(_method, &do_bio_gets);

        _bio = BIO_new(_method);
        if (_bio == nullptr) {
            BIO_meth_free(_method);
            _method = nullptr;
            throw ossl_error("Couldn't make custom BIO");
        }

        // Internally store the 'this' pointer within the BIO so the static functions
        // above may access the state within the respective instance of this class
        BIO_set_data(_bio, this);
    }

    sstring _name;
    data_sink& _out;
    BIO_METHOD* _method;
    BIO* _bio;
    net::packet _p;
    bool _closed{false};
};

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
                   _in_bio(scattered_bio("in_bio", _out)) , _out_bio(scattered_bio("out_bio", _out)),
                   _ctx(make_ssl_context()),
                   _ssl(SSL_new(_ctx.get())) {
        if (!_ssl){
            throw ossl_error();
        }
        if (t == type::SERVER) {
            switch(_creds->get_client_auth()) {
                case client_auth::NONE:
                default:
                    SSL_CTX_set_verify(_ctx.get(), SSL_VERIFY_NONE, nullptr);
                    break;
                case client_auth::REQUEST:
                    SSL_CTX_set_verify(_ctx.get(), SSL_VERIFY_PEER, nullptr);
                    break;
                case client_auth::REQUIRE:
                    SSL_CTX_set_verify(_ctx.get(), SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
                    break;
            }
            SSL_set_accept_state(_ssl.get());
        } else {
            SSL_set_connect_state(_ssl.get());
        }
        // SSL_set_bio transfers ownership of the read and write bios to the SSL
        // instance
        SSL_set_bio(_ssl.get(), _in_bio.bio(), _out_bio.bio());
    }

    session(type t, shared_ptr<certificate_credentials> creds,
            connected_socket sock, sstring name = { },
            std::optional<tls_options> options = std::nullopt)
            : session(t, std::move(creds), net::get_impl::get(std::move(sock)),
                      std::move(name), options) {}

    // This method pulls encrypted data from the SSL context and writes
    // it to the underlying socket.
    future<> pull_encrypted_and_send(){
        netlogger.info("Inside pull encryped and send");
        // BIO_flush(_out_bio.bio());
        // TODO
        // BIO_clear_retry_flags()
        // will need to call this
        return _out_bio.do_flush();
    }

    // This method puts unencrypted data is written into the SSL context.
    // This data is later able to be retrieved in its encrypted form by reading
    // from the associated _out_bio
    future<> do_put(frag_iter i, frag_iter e) {
        netlogger.info("Inside session::do_put");
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
                        netlogger.warn("Unimplemented WANT READ/WRITE");
                    }
                    return make_exception_future<stop_iteration>(ossl_error());
                }
                off += bytes_written;
                return make_ready_future<stop_iteration>(stop_iteration::no);
            });
        });
    }

    future<> put(net::packet p){
        netlogger.info("Inside session::put");
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

        auto i = p.fragments().begin();
        auto e = p.fragments().end();
        return with_semaphore(_out_sem, 1, std::bind(&session::do_put, this, i, e)).finally([p = std::move(p)] {});
    }

    future<> do_handshake() {
        netlogger.info("Inside of session::do_handshake");
        if (connected()) {
            return make_ready_future<>();
        }
        if (_type == type::CLIENT && !_hostname.empty()) {
            SSL_set_tlsext_host_name(_ssl.get(), _hostname.data());
        }

        return do_until(
            [this]{ return connected(); },
            [this]{
                return wait_for_input().then([this]{
                    netlogger.info("Calling SSL_accept");
                    auto n = SSL_accept(_ssl.get());
                    auto ssl_err = SSL_get_error(_ssl.get(), n);
                    switch (ssl_err) {
                    case SSL_ERROR_NONE:
                        break;
                    case SSL_ERROR_WANT_READ:
                        netlogger.info("SSL_accept: ERR_WANT_READ");
                        return pull_encrypted_and_send().then([this]{
                            _in_bio.bio_clear();
                        });
                        break;
                    case SSL_ERROR_WANT_WRITE:
                        netlogger.info("SSL_accept: ERR_WANT_WRITE");
                        break;
                    default:
                        netlogger.info("Failed to complete SSL handlshake: {}", ssl_err);
                        return make_exception_future<>(ossl_error());
                    }
                    return make_ready_future<>();
                });
            }).then([]{
                netlogger.info("SSL handshake complete");
            });
    }

    future<> wait_for_input() {
        // if (eof()) {
        //     return make_ready_future<>();
        // }
        netlogger.info("Inside session::wait_for_input");
        return _in.get().then([this](buf_type data) {
            if (data.empty()) {
                netlogger.info("BUF EMPTY");
                _eof = true;
                return make_ready_future<>();
            }
            // Write the received data to the "read bio".  This bio is consumed
            // by the SSL struct.  Think of this of writing encrypted data into
            // the SSL session
            netlogger.info("Read {} bytes over the wire", data.size());
            const auto n = BIO_write(_in_bio.bio(), data.get(), data.size());
            netlogger.info("Wrote {} bytes over to SSL in bio", n);
            if (n <= 0) {
                return make_exception_future<>(ossl_error(n,  "Error while waiting for input"));
            }
            return make_ready_future();
        }).handle_exception([](auto ep){
            return make_exception_future(ep);
        });
    }

    future<buf_type> do_get() {
        netlogger.info("Inside of session::do_get()");
        // Check if there is encrypted data sitting in ssls internal buffers, otherwise wait
        // for data and use a
        auto f = make_ready_future<>();
        auto avail = BIO_ctrl_pending(_in_bio.bio());
        if (avail == 0) {
            if (eof()) {
                return make_ready_future<buf_type>(buf_type());
            }
            f = wait_for_input();
        }
        return f.then([this, avail]() {
            buf_type buf(avail);
            // Read decrypted data from ssls internal buffers
            auto bytes_read = SSL_read(_ssl.get(), buf.get_write(), avail);
            if (bytes_read <= 0) {
                const auto ec = SSL_get_error(_ssl.get(), bytes_read);
                if (ec == SSL_ERROR_ZERO_RETURN) {
                    // Client has initiated shutdown by sending EOF
                    netlogger.info("Detected SSL_ERROR_ZERO_RETURN");
                    _eof = true;
                    close();
                    return make_ready_future<buf_type>(buf_type());
                } else if (ec == SSL_ERROR_WANT_READ) {
                    netlogger.info("Detected SSL_ERROR_WANT_READ");
                    return pull_encrypted_and_send().then(std::bind(&session::do_get, this));
                }
                return make_exception_future<buf_type>(ossl_error(ec, "error via SSL_read"));
            }
            buf.trim(bytes_read);
            netlogger.info("Read {} bytes via internal SSL buffers", bytes_read);
            return make_ready_future<buf_type>(std::move(buf));
        });
    }

    future<buf_type> get() {
        netlogger.info("Inside of session::get()");
        if (_error) {
            return make_exception_future<temporary_buffer<char>>(_error);
        }
        if (eof()) { // TODO(rob) - or _shutdown
            return make_ready_future<temporary_buffer<char>>(buf_type());
        }
        if (!connected()) {
            return handshake().then(std::bind(&session::get, this));
        }
        return with_semaphore(_in_sem, 1, std::bind(&session::do_get, this)).then([](temporary_buffer<char> buf) {
            // TODO(rob) - maybe re-handshake?
            netlogger.info("Returning buffer of size: {}", buf.size());
            return make_ready_future<temporary_buffer<char>>(std::move(buf));
        });
    }

    future<> do_shutdown() {
        netlogger.info("Inside session::do_shutdown");
        /// TODO(rob) - Is yield the right option here
        if(_error || !connected()) {
            return make_ready_future();
        }
        auto res = SSL_shutdown(_ssl.get());
        if (res == 1){
            // Shutdown has completed successfully
            netlogger.info("Session shutdown gracefully");
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

    template<typename Fn>
    static std::optional<sstring> get_ossl_string(Fn f, const x509_ptr& cert){
        X509_NAME *name = f(cert.get());
        if (name == nullptr) {
            return std::nullopt;
        }
        char *name_str = X509_NAME_oneline(name, NULL, 0);
        if (name_str == nullptr) {
            return std::nullopt;
        }
        sstring ossl_str(name_str);
        OPENSSL_free(name_str);
        return ossl_str;
    }

    void verify() {
        auto res = SSL_get_verify_result(_ssl.get());
        if (res != X509_V_OK) {
            sstring stat_str(X509_verify_cert_error_string(res));
            auto dn = extract_dn_information();
            if (dn) {
                std::stringstream ss;
                ss << stat_str;
                if (stat_str.back() != ' ') {
                    ss << ' ';
                }
                ss << "(Issuer=[" << dn->issuer << "], Subject=[" << dn->subject << "])";
                stat_str = ss.str();
            }
            throw verification_error(stat_str);
        }
        // A success return code does not signify if a cert was presented or not, that must be explicitly
        // queried via SSL_get_peer_cert
        auto peer_cert = SSL_get_peer_certificate(_ssl.get());
        if(peer_cert == nullptr && _type == type::SERVER){
            if(_creds->get_client_auth() == client_auth::REQUIRE) {
                // No peer certificate was returned even though it was requested and required
                throw ossl_error(res, "Error within SSL verify");
            }
            return;
        }
        if (_creds->_dn_callback) {
            auto dn = extract_dn_information();
            assert(dn.has_value());

            session_type t;
            switch (_type) {
            case type::CLIENT:
                t = session_type::CLIENT;
                break;
            case type::SERVER:
                t = session_type::SERVER;
                break;
            }

            _creds->_dn_callback(t, std::move(dn->subject), std::move(dn->issuer));
            return;
        }
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
        netlogger.info("wait_for_eof: {}", _options.wait_for_eof_on_shutdown);
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
        netlogger.info("Inside of session::shutdown");
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
            netlogger.info("Invoking shutdown routine within session::close");
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

    /// TODO(rob) - implement these methods
    future<std::optional<session_dn>> get_distinguished_name() {
        using result_t = std::optional<session_dn>;
        return make_exception_future<result_t>(std::runtime_error("unimplemented"));
    }

    future<std::vector<subject_alt_name>> get_alt_name_information(std::unordered_set<subject_alt_name_type>) {
        using result_t = std::vector<subject_alt_name>;
        return make_exception_future<result_t>(std::runtime_error("unimplemented"));
    }


private:
    std::optional<session_dn> extract_dn_information() const {
        auto peer_cert = x509_ptr(SSL_get_peer_certificate(_ssl.get()));
        if(!peer_cert) {
            return std::nullopt;
        }
        auto subject = get_ossl_string(X509_get_subject_name, peer_cert);
        auto issuer = get_ossl_string(X509_get_issuer_name, peer_cert);
        if(!subject || !issuer) {
            throw ossl_error("error while extracting certificate DN strings");
        }
        return session_dn{.subject= std::move(*subject), .issuer = std::move(*issuer)};
    }

    ssl_ctx_ptr make_ssl_context(){
        // Make sure when creating the OpenSSL context, to use the correct library
        // context.  This ensures that the SSL_CTX uses shard local memory.

        // auto ssl_ctx = SSL_CTX_ptr(SSL_CTX_new_ex(
        //     ssl_ctx_service.local().get_ossl_context(), nullptr, TLS_method()));
        auto ssl_ctx = ssl_ctx_ptr(SSL_CTX_new(TLS_method()));
        if (!ssl_ctx) {
            throw ossl_error();
        }

        // Do not verify the client's credentials, TODO: Configurable
        SSL_CTX_set_verify(ssl_ctx.get(), SSL_VERIFY_NONE, nullptr);
        SSL_CTX_set1_cert_store(ssl_ctx.get(), *_creds);
        // TODO: BUG  - this does not work
        // if(!SSL_CTX_set0_tmp_dh_pkey(ssl_ctx.get(), *_creds->_dh_params)){
        //     throw ossl_eror();
        // }

        auto& ck_pair = _creds->get_cert_key_pair();
        if(!ck_pair) {
            throw ossl_error();
        }

        // Load private key and certificate and verify that the private key and
        // public key match.  Can also provide a cert chain here
        if (!SSL_CTX_use_cert_and_key(ssl_ctx.get(), ck_pair->cert.get(), ck_pair->key.get(), nullptr, 1)) {
            throw ossl_error();
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
    scattered_bio _in_bio;
    scattered_bio _out_bio;
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
