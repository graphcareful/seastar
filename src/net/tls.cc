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

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <system_error>
#include <variant>

#include <seastar/core/loop.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/seastar.hh>
#include <seastar/core/sstring.hh>
#include <seastar/core/semaphore.hh>
#include <seastar/core/timer.hh>
#include <seastar/core/print.hh>
#include <seastar/core/with_timeout.hh>
#include <seastar/net/tls.hh>
#include <seastar/net/stack.hh>
#include <seastar/util/std-compat.hh>
#include <seastar/util/variant_utils.hh>

namespace seastar {

class blob_wrapper: public gnutls_datum_t {
public:
    blob_wrapper(const tls::blob& in)
            : gnutls_datum_t {
                    reinterpret_cast<uint8_t *>(const_cast<char *>(in.data())),
                    unsigned(in.size()) } {
    }
};

class gnutlsinit {
public:
    gnutlsinit() {
        gnutls_global_init();
    }
    ~gnutlsinit() {
        gnutls_global_deinit();
    }
};

// Helper to ensure gnutls legacy init
// is handled properly with regards to
// object life spans. Could be better,
// this version will not destroy the
// gnutls stack until process exit.
class gnutlsobj {
public:
    gnutlsobj() {
        static gnutlsinit init;
    }
};

// Note: we are not using gnutls++ interfaces, mainly because we
// want to keep _our_ interface reasonably non-gnutls (well...)
// and once we get to this level, their abstractions don't help
// that much anyway. And they are sooo c++98...
class gnutls_error_category : public std::error_category {
public:
    constexpr gnutls_error_category() noexcept : std::error_category{} {}
    const char * name() const noexcept {
        return "GnuTLS";
    }
    std::string message(int error) const {
        return gnutls_strerror(error);
    }
};

static const gnutls_error_category glts_errorc;

// Checks a gnutls return value.
// < 0 -> error.
static void gtls_chk(int res) {
    if (res < 0) {
        throw std::system_error(res, glts_errorc);
    }
}

namespace {

// helper for gnutls-functions for receiving a string
// arguments
//  func - the gnutls function that is returning a string (e.g. gnutls_x509_crt_get_issuer_dn)
//  args - the arguments to func that come before the char array's ptr and size args
// returns
//  pair<int, string> - [gnutls error code, extracted string],
//                      in case of no errors, the error code is zero
static auto get_gtls_string = [](auto func, auto... args) noexcept {
    size_t size = 0;
    int ret = func(args..., nullptr, &size);

    // by construction, we expect the SHORT_MEMORY_BUFFER error code here
    if (ret != GNUTLS_E_SHORT_MEMORY_BUFFER) {
        return std::make_pair(ret, sstring{});
    }
    assert(size != 0);
    sstring res(sstring::initialized_later{}, size - 1);
    ret = func(args..., res.data(), &size);
    return std::make_pair(ret, res);
};

}

class tls::dh_params::impl : gnutlsobj {
    static gnutls_sec_param_t to_gnutls_level(level l) {
        switch (l) {
            case level::LEGACY: return GNUTLS_SEC_PARAM_LEGACY;
#if GNUTLS_VERSION_NUMBER >= 0x030300
            case level::MEDIUM: return GNUTLS_SEC_PARAM_MEDIUM;
#else
            case level::MEDIUM: return GNUTLS_SEC_PARAM_NORMAL;
#endif
            case level::HIGH: return GNUTLS_SEC_PARAM_HIGH;
            case level::ULTRA: return GNUTLS_SEC_PARAM_ULTRA;
            default:
                throw std::runtime_error(format("Unknown value of dh_params::level: {:d}", static_cast<std::underlying_type_t<level>>(l)));
        }
    }
    using dh_ptr = std::unique_ptr<std::remove_pointer_t<gnutls_dh_params_t>, void(*)(gnutls_dh_params_t)>;

    static dh_ptr new_dh_params() {
        gnutls_dh_params_t params;
        gtls_chk(gnutls_dh_params_init(&params));
        return dh_ptr(params, &gnutls_dh_params_deinit);
    }
public:
    impl(dh_ptr p) 
        : _params(std::move(p)) 
    {}
    impl(level lvl)
#if GNUTLS_VERSION_NUMBER >= 0x030506
        : _params(nullptr, &gnutls_dh_params_deinit)
        , _sec_param(to_gnutls_level(lvl))
#else        
        : impl([&] {
            auto bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH, to_gnutls_level(lvl));
            auto ptr = new_dh_params();
            gtls_chk(gnutls_dh_params_generate2(ptr.get(), bits));
            return ptr;
        }())
#endif
    {}
    impl(const blob& pkcs3, x509_crt_format fmt)
        : impl([&] {
            auto ptr = new_dh_params();
            blob_wrapper w(pkcs3);
            gtls_chk(gnutls_dh_params_import_pkcs3(ptr.get(), &w, gnutls_x509_crt_fmt_t(fmt)));
            return ptr;
        }()) 
    {}
    impl(const impl& v)
        : impl([&v] {
            auto ptr = new_dh_params();
            gtls_chk(gnutls_dh_params_cpy(ptr.get(), v));
            return ptr;
        }()) 
    {}
    ~impl() = default;

    operator gnutls_dh_params_t() const {
        return _params.get();
    }
#if GNUTLS_VERSION_NUMBER >= 0x030506
    std::optional<gnutls_sec_param_t> sec_param() const {
        return _sec_param;
    }
#endif
private:
    dh_ptr _params;
#if GNUTLS_VERSION_NUMBER >= 0x030506
    std::optional<gnutls_sec_param_t> _sec_param;
#endif
};

tls::dh_params::dh_params(level lvl) : _impl(std::make_unique<impl>(lvl))
{}

tls::dh_params::dh_params(const blob& b, x509_crt_format fmt)
        : _impl(std::make_unique<impl>(b, fmt)) {
}

tls::dh_params::~dh_params() {
}

tls::dh_params::dh_params(dh_params&&) noexcept = default;
tls::dh_params& tls::dh_params::operator=(dh_params&&) noexcept = default;

class tls::certificate_credentials::impl: public gnutlsobj {
public:
    impl()
            : _creds([] {
                gnutls_certificate_credentials_t xcred;
                gnutls_certificate_allocate_credentials(&xcred);
                if (xcred == nullptr) {
                    throw std::bad_alloc();
                }
                return xcred;
            }()), _priority(nullptr, &gnutls_priority_deinit)
    {}
    ~impl() {
        if (_creds != nullptr) {
            gnutls_certificate_free_credentials (_creds);
        }
    }

    operator gnutls_certificate_credentials_t() const {
        return _creds;
    }

    void set_x509_trust(const blob& b, x509_crt_format fmt) {
        blob_wrapper w(b);
        gtls_chk(
                gnutls_certificate_set_x509_trust_mem(_creds, &w,
                        gnutls_x509_crt_fmt_t(fmt)));
    }
    void set_x509_crl(const blob& b, x509_crt_format fmt) {
        blob_wrapper w(b);
        gtls_chk(
                gnutls_certificate_set_x509_crl_mem(_creds, &w,
                        gnutls_x509_crt_fmt_t(fmt)));
    }
    void set_x509_key(const blob& cert, const blob& key, x509_crt_format fmt) {
        blob_wrapper w1(cert);
        blob_wrapper w2(key);
        gtls_chk(
                gnutls_certificate_set_x509_key_mem(_creds, &w1, &w2,
                        gnutls_x509_crt_fmt_t(fmt)));
    }
    void set_simple_pkcs12(const blob& b, x509_crt_format fmt,
            const sstring& password) {
        blob_wrapper w(b);
        gtls_chk(
                gnutls_certificate_set_x509_simple_pkcs12_mem(_creds, &w,
                        gnutls_x509_crt_fmt_t(fmt), password.c_str()));
    }
    void dh_params(const tls::dh_params& dh) {
#if GNUTLS_VERSION_NUMBER >= 0x030506
        auto sec_param = dh._impl->sec_param();
        if (sec_param) {
            gnutls_certificate_set_known_dh_params(*this, *sec_param);
            return;
        }
#endif
        auto cpy = std::make_unique<tls::dh_params::impl>(*dh._impl);
        gnutls_certificate_set_dh_params(*this, *cpy);
        _dh_params = std::move(cpy);
    }
    future<> set_system_trust() {
        return async([this] {
            gtls_chk(gnutls_certificate_set_x509_system_trust(_creds));
            _load_system_trust = false; // should only do once, for whatever reason
        });
    }
    void set_client_auth(client_auth ca) {
        _client_auth = ca;
    }
    client_auth get_client_auth() const {
        return _client_auth;
    }
    void set_priority_string(const sstring& prio) {
        const char * err = prio.c_str();
        try {
            gnutls_priority_t p;
            gtls_chk(gnutls_priority_init(&p, prio.c_str(), &err));
            _priority.reset(p);
        } catch (...) {
            std::throw_with_nested(std::invalid_argument(std::string("Could not set priority: ") + err));
        }
    }
    gnutls_priority_t get_priority() const {
        return _priority.get();
    }

    void set_dn_verification_callback(dn_callback cb) {
        _dn_callback = std::move(cb);
    }
private:
    friend class credentials_builder;
    friend class session;

    bool need_load_system_trust() const {
        return _load_system_trust;
    }
    future<> maybe_load_system_trust() {
        return with_semaphore(_system_trust_sem, 1, [this] {
            if (!_load_system_trust) {
                return make_ready_future();
            }
            return set_system_trust();
        });
    }

    gnutls_certificate_credentials_t _creds;
    std::unique_ptr<tls::dh_params::impl> _dh_params;
    std::unique_ptr<std::remove_pointer_t<gnutls_priority_t>, void(*)(gnutls_priority_t)> _priority;
    client_auth _client_auth = client_auth::NONE;
    bool _load_system_trust = false;
    semaphore _system_trust_sem {1};
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

tls::server_credentials::server_credentials()
#if GNUTLS_VERSION_NUMBER < 0x030600
    : server_credentials(dh_params{})
#endif
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
 */
class session : public enable_lw_shared_from_this<session> {
public:
    enum class type
        : uint32_t {
            CLIENT = GNUTLS_CLIENT, SERVER = GNUTLS_SERVER,
    };

    session(type t, shared_ptr<tls::certificate_credentials> creds,
            std::unique_ptr<net::connected_socket_impl> sock, sstring name = { }, bool enable_dn_fetch = false)
            : _type(t), _sock(std::move(sock)), _creds(creds->_impl), _hostname(
                    std::move(name)), _in(_sock->source()), _out(_sock->sink()),
                    _in_sem(1), _out_sem(1), _output_pending(
                    make_ready_future<>()), _session([t] {
                gnutls_session_t session;
                gtls_chk(gnutls_init(&session, GNUTLS_NONBLOCK|uint32_t(t)));
                return session;
            }(), &gnutls_deinit) {
        gtls_chk(gnutls_set_default_priority(*this));
        gtls_chk(
                gnutls_credentials_set(*this, GNUTLS_CRD_CERTIFICATE,
                        *_creds));
        if (_type == type::SERVER) {
            switch (_creds->get_client_auth()) {
                case client_auth::NONE:
                default:
                    gnutls_certificate_server_set_request(*this, GNUTLS_CERT_IGNORE);
                    break;
                case client_auth::REQUEST:
                    gnutls_certificate_server_set_request(*this, GNUTLS_CERT_REQUEST);
                    break;
                case client_auth::REQUIRE:
                    gnutls_certificate_server_set_request(*this, GNUTLS_CERT_REQUIRE);
                    break;
            }
            if (_creds->get_client_auth() != client_auth::NONE) {
                if (enable_dn_fetch) {
                    _session_dn = std::make_unique<promise<std::optional<session_dn>>>();
                }
            }
        }

        auto prio = _creds->get_priority();
        if (prio) {
            gtls_chk(gnutls_priority_set(*this, prio));
        }

        gnutls_transport_set_ptr(*this, this);
        gnutls_transport_set_vec_push_function(*this, &vec_push_wrapper);
        gnutls_transport_set_pull_function(*this, &pull_wrapper);

        // This would be nice, because we preferably want verification to
        // abort hand shake so peer immediately knows we bailed...
#if GNUTLS_VERSION_NUMBER >= 0x030406
        if (_type == type::CLIENT) {
            gnutls_session_set_verify_function(*this, &verify_wrapper);
        }
#endif
    }
    session(type t, shared_ptr<certificate_credentials> creds,
            connected_socket sock, sstring name = { }, bool enable_dn_fetch = false)
            : session(t, std::move(creds), net::get_impl::get(std::move(sock)),
                    std::move(name), enable_dn_fetch) {
    }

    ~session() {
        assert(_output_pending.available());
    }

    typedef temporary_buffer<char> buf_type;

    sstring cert_status_to_string(gnutls_certificate_type_t type, unsigned int status) {
        gnutls_datum_t out;
        gtls_chk(
                gnutls_certificate_verification_status_print(status, type, &out,
                        0));
        sstring s(reinterpret_cast<const char *>(out.data), out.size);
        gnutls_free(out.data);
        return s;
    }

    future<> send_alert(gnutls_alert_level_t level, gnutls_alert_description_t desc) {
        return repeat([this, level, desc]() {
            auto res = gnutls_alert_send(*this, level, desc);
            switch(res) {
            case GNUTLS_E_SUCCESS:
                return wait_for_output().then([] {
                    return make_ready_future<stop_iteration>(stop_iteration::yes);
                });
            case GNUTLS_E_AGAIN:
            case GNUTLS_E_INTERRUPTED:
                return wait_for_output().then([] {
                    return make_ready_future<stop_iteration>(stop_iteration::no);
                });
            default:
                return handle_output_error(res).then([] {
                    return make_ready_future<stop_iteration>(stop_iteration::yes);
                });
            }
        });
    }

    future<> do_handshake() {
        if (_connected) {
            return make_ready_future<>();
        }
        if (_type == type::CLIENT && !_hostname.empty()) {
            gnutls_server_name_set(*this, GNUTLS_NAME_DNS, _hostname.data(), _hostname.size());
        }
        try {
            auto res = gnutls_handshake(*this);
            if (res < 0) {
                switch (res) {
                case GNUTLS_E_AGAIN:
                    // #453 always wait for output first.
                    // If none is pending, it should be a no-op
                {
                    int dir = gnutls_record_get_direction(*this);
                    return wait_for_output().then([this, dir] {
                        // we actually E_AGAIN:ed in a write. Don't
                        // wait for input.
                        if (dir == 1) {
                            return do_handshake();
                        }
                        return wait_for_input().then([this] {
                            return do_handshake();
                        });
                    });
                }
                case GNUTLS_E_NO_CERTIFICATE_FOUND:
                    return make_exception_future<>(verification_error("No certificate was found"));
#if GNUTLS_VERSION_NUMBER >= 0x030406
                case GNUTLS_E_CERTIFICATE_ERROR:
                    verify(); // should throw. otherwise, fallthrough
#endif
                default:
                    // Send the handshake error returned by gnutls_handshake()
                    // to the client, as an alert. For example, if the protocol
                    // version requested by the client is not supported, the
                    // "protocol_version" alert is sent.
                    auto alert = gnutls_alert_description_t(gnutls_error_to_alert(res, NULL));
                    return send_alert(GNUTLS_AL_FATAL, alert).then_wrapped([res] (future<> f) {
                        // Return to the caller the original handshake error.
                        // If send_alert() *also* failed, ignore that.
                        f.ignore_ready_future();
                        return make_exception_future<>(std::system_error(res, glts_errorc));
                    });
                }
            }
            if (_type == type::CLIENT || _creds->get_client_auth() != client_auth::NONE) {
                verify();
            }
            _connected = true;
            // make sure we reset output_pending
            return wait_for_output();
        } catch (...) {
            return make_exception_future<>(std::current_exception());
        }
    }
    future<> handshake() {
        // maybe load system certificates before handshake, in case we
        // have not done so yet...
        if (_creds->need_load_system_trust()) {
            return _creds->maybe_load_system_trust().then([this] {
               return handshake();
            });
        }
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

    size_t in_avail() const {
        return _input.size();
    }
    bool eof() const {
        return _eof;
    }
    future<> wait_for_input() {
        if (!_input.empty()) {
            return make_ready_future<>();
        }
        return _in.get().then([this](buf_type buf) {
            _eof |= buf.empty();
           _input = std::move(buf);
        }).handle_exception([this](auto ep) {
           _error = ep;
           return make_exception_future(ep);
        });
    }
    future<> wait_for_output() {
        return std::exchange(_output_pending, make_ready_future()).handle_exception([this](auto ep) {
           _error = ep;
           return make_exception_future(ep);
        });
    }

    static session * from_transport_ptr(gnutls_transport_ptr_t ptr) {
        return static_cast<session *>(ptr);
    }
#if GNUTLS_VERSION_NUMBER >= 0x030406
    static int verify_wrapper(gnutls_session_t gs) {
        try {
            from_transport_ptr(gnutls_transport_get_ptr(gs))->verify();
            return 0;
        } catch (...) {
            return GNUTLS_E_CERTIFICATE_ERROR;
        }
    }
#endif
    static ssize_t vec_push_wrapper(gnutls_transport_ptr_t ptr, const giovec_t * iov, int iovcnt) {
        return from_transport_ptr(ptr)->vec_push(iov, iovcnt);
    }
    static ssize_t pull_wrapper(gnutls_transport_ptr_t ptr, void* dst, size_t len) {
        return from_transport_ptr(ptr)->pull(dst, len);
    }

    void verify() {
        bool fetch_dn = static_cast<bool>(_session_dn);
        unsigned int status;
        auto res = gnutls_certificate_verify_peers3(*this, _type != type::CLIENT || _hostname.empty()
                        ? nullptr : _hostname.c_str(), &status);
        if (res == GNUTLS_E_NO_CERTIFICATE_FOUND && _type != type::CLIENT && _creds->get_client_auth() != client_auth::REQUIRE) {
            if (fetch_dn) {
                _session_dn->set_value(std::nullopt);
            }
            return;
        }
        if (res < 0) {
            if (fetch_dn) {
                _session_dn->set_value(std::nullopt);
            }
            throw std::system_error(res, glts_errorc);
        }
        if (status & GNUTLS_CERT_INVALID) {
            if (fetch_dn) {
                _session_dn->set_value(std::nullopt);
            }
            throw verification_error(
                    cert_status_to_string(gnutls_certificate_type_get(*this),
                            status));
        }
        if (fetch_dn || _creds->_dn_callback) {
            // if the user registered a DN (Distinguished Name) callback
            // then extract subject and issuer from the (leaf) peer certificate and invoke the callback

            unsigned int list_size;
            const gnutls_datum_t* client_cert_list = gnutls_certificate_get_peers(*this, &list_size);
            assert(list_size > 0); // otherwise we couldn't have gotten here

            gnutls_x509_crt_t peer_leaf_cert;
            gtls_chk(gnutls_x509_crt_init(&peer_leaf_cert));
            gtls_chk(gnutls_x509_crt_import(peer_leaf_cert, &(client_cert_list[0]), GNUTLS_X509_FMT_DER));

            // we need get_string to be noexcept because we need to manually de-init peer_leaf_cert afterwards
            auto [ec, subject] = get_gtls_string(gnutls_x509_crt_get_dn, peer_leaf_cert);
            auto [ec2, issuer] = get_gtls_string(gnutls_x509_crt_get_issuer_dn, peer_leaf_cert);

            gnutls_x509_crt_deinit(peer_leaf_cert);

            if (ec || ec2) {
                if (fetch_dn) {
                    _session_dn->set_value(std::nullopt);
                }
                throw std::runtime_error("error while extracting certificate DN strings");
            }

            // a switch here might look overelaborate, however,
            // the compiler will warn us if someone alters the definition of type
            session_type t;
            switch (_type) {
            case type::CLIENT:
                t = session_type::CLIENT;
                break;
            case type::SERVER:
                t = session_type::SERVER;
                break;
            }

            if (_creds->_dn_callback) {
                _creds->_dn_callback(t, subject, issuer);
            }
            if (fetch_dn) {
                _session_dn->set_value(session_dn{.subject=std::move(subject), .issuer=std::move(issuer)});
            }
        }
    }

    future<temporary_buffer<char>> get() {
        if (_error) {
            return make_exception_future<temporary_buffer<char>>(_error);
        }
        if (_shutdown || eof()) {
            return make_ready_future<temporary_buffer<char>>();
        }
        if (!_connected) {
            return handshake().then(std::bind(&session::get, this));
        }
        return with_semaphore(_in_sem, 1, std::bind(&session::do_get, this)).then([this](temporary_buffer<char> buf) {
            if (buf.empty() && !eof()) {
                // this must mean we got a re-handshake request.
                // see do_get.
                // We there clear connected flag and return empty in case
                // other side requests re-handshake. Now, someone else could have already dealt with it by the
                // time we are here (continuation reordering). In fact, someone could have dealt with
                // it and set the eof flag also, but in that case we're still eof...
                return handshake().then(std::bind(&session::get, this));
            }
            return make_ready_future<temporary_buffer<char>>(std::move(buf));
        });
    }

    future<temporary_buffer<char>> do_get() {
        // gnutls might have stuff in its buffers.
        auto avail = gnutls_record_check_pending(*this);
        if (avail == 0) {
            // or we might...
            avail = in_avail();
        }
        if (avail != 0) {
            // typically, unencrypted data can get smaller (padding),
            // but not larger.
            temporary_buffer<char> buf(avail);
            auto n = gnutls_record_recv(*this, buf.get_write(), buf.size());
            if (n < 0) {
                switch (n) {
                case GNUTLS_E_AGAIN:
                    // Assume we got this because we read to little underlying
                    // data to finish a tls packet
                    // Our input buffer should be empty now, so just go again
                    return do_get();
                case GNUTLS_E_REHANDSHAKE:
                    // server requests new HS. must release semaphore, so set new state
                    // and return nada.
                    _connected = false;
                    return make_ready_future<temporary_buffer<char>>();
                default:
                    _error = std::make_exception_ptr(std::system_error(n, glts_errorc));
                    return make_exception_future<temporary_buffer<char>>(_error);
                }
            }
            buf.trim(n);
            if (n == 0) {
                _eof = true;
            }
            return make_ready_future<temporary_buffer<char>>(std::move(buf));
        }
        if (eof()) {
            return make_ready_future<temporary_buffer<char>>();
        }
        // No input? wait for out buffers to fill...
        return wait_for_input().then([this] {
            return do_get();
        });
    }

    typedef net::fragment* frag_iter;

    future<> do_put(frag_iter i, frag_iter e) {
        assert(_output_pending.available());
        return do_for_each(i, e, [this](net::fragment& f) {
            auto ptr = f.base;
            auto size = f.size;
            size_t off = 0; // here to appease eclipse cdt
            return repeat([this, ptr, size, off]() mutable {
                if (off == size) {
                    return make_ready_future<stop_iteration>(stop_iteration::yes);
                }
                auto res = gnutls_record_send(*this, ptr + off, size - off);
                if (res > 0) { // don't really need to check, but...
                    off += res;
                }
                // what will we wait for? error or results...
                auto f = res < 0 ? handle_output_error(res) : wait_for_output();
                return f.then([] {
                    return make_ready_future<stop_iteration>(stop_iteration::no);
                });
            });
        });
    }
    future<> put(net::packet p) {
        if (_error) {
            return make_exception_future<>(_error);
        }
        if (_shutdown) {
            return make_exception_future<>(std::system_error(ENOTCONN, std::system_category()));
        }
        if (!_connected) {
            return handshake().then([this, p = std::move(p)]() mutable {
               return put(std::move(p));
            });
        }
        auto i = p.fragments().begin();
        auto e = p.fragments().end();
        return with_semaphore(_out_sem, 1, std::bind(&session::do_put, this, i, e)).finally([p = std::move(p)] {});
    }

    ssize_t pull(void* dst, size_t len) {
        if (eof()) {
            return 0;
        }
        // If we have data in buffers, we can complete.
        // Otherwise, we must be conservative.
        if (_input.empty()) {
            gnutls_transport_set_errno(*this, EAGAIN);
            return -1;
        }
        auto n = std::min(len, _input.size());
        memcpy(dst, _input.get(), n);
        _input.trim_front(n);
        return n;
    }
    ssize_t vec_push(const giovec_t * iov, int iovcnt) {
        if (!_output_pending.available()) {
            gnutls_transport_set_errno(*this, EAGAIN);
            return -1;
        }
        try {
            scattered_message<char> msg;
            for (int i = 0; i < iovcnt; ++i) {
                msg.append(std::string_view(reinterpret_cast<const char *>(iov[i].iov_base), iov[i].iov_len));
            }
            auto n = msg.size();
            _output_pending = _out.put(std::move(msg).release());
            return n;
        } catch (...) {
            gnutls_transport_set_errno(*this, EIO);
            _output_pending = make_exception_future<>(std::current_exception());
        }
        return -1;
    }

    operator gnutls_session_t() const {
        return _session.get();
    }

    future<>
    handle_error(int res) {
        _error = std::make_exception_ptr(std::system_error(res, glts_errorc));
        return make_exception_future(_error);
    }
    future<>
    handle_output_error(int res) {
        _error = std::make_exception_ptr(std::system_error(res, glts_errorc));
        // #453
        // defensively wait for output before generating the error.
        // if we have both error code and an exception in output
        // future, throw both.
        return wait_for_output().then_wrapped([this, res](auto f) {
            try {
                f.get();
                // output was ok/done, just generate error code exception
                return make_exception_future(_error);
            } catch (...) {
                std::throw_with_nested(std::system_error(res, glts_errorc));
            }
        });
    }
    future<> do_shutdown() {
        if (_error || !_connected) {
            return make_ready_future();
        }
        auto res = gnutls_bye(*this, GNUTLS_SHUT_WR);
        if (res < 0) {
            switch (res) {
            case GNUTLS_E_AGAIN:
                // We only send "bye" alert, letting a "normal" (either pending, or subsequent)
                // read deal with reading the expected EOF alert.
                assert(gnutls_record_get_direction(*this) == 1);
                return wait_for_output().then([this] {
                    return do_shutdown();
                });
            default:
                return handle_output_error(res);
            }
        }
        return wait_for_output();
    }
    future<> wait_for_eof() {
        // read records until we get an eof alert
        // since this call could time out, we must not ac
        return with_semaphore(_in_sem, 1, [this] {
            if (_error || !_connected) {
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
    void close() {
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
        if (_session_dn) {
            return _session_dn->get_future();
        }
        return make_ready_future<std::optional<session_dn>>(std::nullopt);
    }

private:
    type _type;

    std::unique_ptr<net::connected_socket_impl> _sock;
    shared_ptr<tls::certificate_credentials::impl> _creds;
    const sstring _hostname;
    data_source _in;
    data_sink _out;

    semaphore _in_sem, _out_sem;

    bool _eof = false;
    bool _shutdown = false;
    bool _connected = false;
    std::exception_ptr _error;

    future<> _output_pending;
    buf_type _input;

    // modify this to a unique_ptr to handle exceptions in our constructor.
    std::unique_ptr<std::remove_pointer_t<gnutls_session_t>, void(*)(gnutls_session_t)> _session;
    std::unique_ptr<promise<std::optional<session_dn>>> _session_dn;
};

}

}
