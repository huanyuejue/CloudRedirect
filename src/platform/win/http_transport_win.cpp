// WinHTTP transport adapter for CloudProviderBase.
// Implements IHttpTransport using WinHTTP session/connection/request handles.

#include "cloud_provider_base.h"
#include "http_util.h"
#include "sha256_hmac.h"
#include "log.h"

#include <Windows.h>
#include <winhttp.h>
#include <cctype>
#include <map>
#include <memory>
#include <string>

using HttpUtil::Widen;
using HttpUtil::HttpResp;

class WinHttpTransport : public IHttpTransport {
public:
    explicit WinHttpTransport(const char* logTag) : m_logTag(logTag) {}
    ~WinHttpTransport() override { Shutdown(); }

    bool Init() override {
        if (m_session) return true;
        // AUTOMATIC_PROXY 读取系统（IE/WinINet 层）代理设置；DEFAULT_PROXY 只看
        // netsh winhttp 级静态配置，用户开在系统层的代理对它不可见，会直连超时。
        m_session = WinHttpOpen(L"CloudRedirect/1.0",
                                 WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                 WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!m_session) {
            LOG("%s WinHttpOpen failed: %u", m_logTag, GetLastError());
            return false;
        }
        WinHttpSetTimeouts(m_session, 5000, 5000, 10000, 10000);
        return true;
    }

    // 请求体较大时放宽发送/接收超时，避免几 MB 的上传在慢链路上被默认 10 秒掐断；
    // 小请求仍用快速默认值。显式配置了 timeoutSec 时以配置为准。
    void ApplyRequestOptions(HINTERNET hReq, size_t bodyBytes) {
        if (m_opts.disableRedirects) {
            DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
            WinHttpSetOption(hReq, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy));
        }
        if (m_opts.timeoutSec > 0) {
            int sec = m_opts.timeoutSec > 300 ? 300 : m_opts.timeoutSec;
            WinHttpSetTimeouts(hReq, 5000, 5000, sec * 1000, sec * 1000);
            return;
        }
        if (bodyBytes <= 256 * 1024) return;
        int sendMs = 60000;
        int receiveMs = 30000;
        WinHttpSetTimeouts(hReq, 5000, 5000, sendMs, receiveMs);
    }

    // 预签名 URL 自带授权凭据，再补 Authorization 会让服务端改用 Bearer 校验。
    // SharePoint / OneDrive 的 downloadUrl 带 tempauth，一旦同时出现 Bearer，
    // 内容端点会认为 Bearer 优先，而它的 audience 是 graph.microsoft.com，
    // 与内容端点不匹配，直接 401。
    static bool HasUrlSignature(const std::string& url) {
        static const char* kParams[] = {
            "tempauth=", "tempauth2=", "temkb=", "authkey=",   // SharePoint / OneDrive
            "X-Amz-Signature=", "X-Goog-Signature=",           // S3 / GCS 预签名
        };
        for (const char* p : kParams) {
            if (url.find(p) != std::string::npos) return true;
        }
        return false;
    }

    // 调用方显式写了 Authorization（自定义 token 等）时以调用方为准，
    // 避免同一请求出现两个 Authorization 头把服务端搞糊涂。
    static bool HasAuthorizationHeader(const std::vector<std::string>& hdrs) {
        static const char kName[] = "authorization";
        const size_t nameLen = sizeof(kName) - 1;
        for (const auto& h : hdrs) {
            size_t i = 0;
            while (i < h.size() && (unsigned char)h[i] <= ' ') ++i;
            if (h.size() - i <= nameLen || h[i + nameLen] != ':') continue;
            bool match = true;
            for (size_t k = 0; k < nameLen; ++k) {
                if (tolower((unsigned char)h[i + k]) != kName[k]) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }

    // Basic/Bearer 由我预发送；Digest/NTLM/Negotiate 需要先拿 401 挑战，
    // 交给 SendRequestWithAuth 处理。
    // url 用于识别预签名链接：那类地址自带授权，绝不能补 Authorization。
    void AddAuthHeaders(std::vector<std::string>& hdrs, const std::string& url) const {
        if (m_opts.authScheme == ServerAuthScheme::None ||
            HasAuthorizationHeader(hdrs) ||
            HasUrlSignature(url)) return;
        if (m_opts.authScheme == ServerAuthScheme::Basic) {
            std::string creds = m_opts.username + ":" + m_opts.password;
            hdrs.push_back("Authorization: Basic " +
                crypto::Base64Encode(reinterpret_cast<const uint8_t*>(creds.data()), creds.size()));
        } else if (m_opts.authScheme == ServerAuthScheme::Bearer &&
                   !m_opts.bearerToken.empty()) {
            hdrs.push_back("Authorization: Bearer " + m_opts.bearerToken);
        }
    }

    bool IsNegotiatedAuth() const {
        switch (m_opts.authScheme) {
        case ServerAuthScheme::Negotiated:
        case ServerAuthScheme::Digest:
        case ServerAuthScheme::Ntlm:
        case ServerAuthScheme::Negotiate:
            return !m_opts.username.empty() || !m_opts.password.empty();
        default:
            return false;
        }
    }

    DWORD PickAuthScheme(DWORD supported) const {
        auto has = [&](DWORD s) { return (supported & s) != 0; };
        switch (m_opts.authScheme) {
        case ServerAuthScheme::Digest:
            return has(WINHTTP_AUTH_SCHEME_DIGEST) ? WINHTTP_AUTH_SCHEME_DIGEST : 0;
        case ServerAuthScheme::Ntlm:
            return has(WINHTTP_AUTH_SCHEME_NTLM) ? WINHTTP_AUTH_SCHEME_NTLM : 0;
        case ServerAuthScheme::Negotiate:
            return has(WINHTTP_AUTH_SCHEME_NEGOTIATE) ? WINHTTP_AUTH_SCHEME_NEGOTIATE : 0;
        default:
            if (has(WINHTTP_AUTH_SCHEME_NEGOTIATE)) return WINHTTP_AUTH_SCHEME_NEGOTIATE;
            if (has(WINHTTP_AUTH_SCHEME_NTLM))      return WINHTTP_AUTH_SCHEME_NTLM;
            if (has(WINHTTP_AUTH_SCHEME_DIGEST))    return WINHTTP_AUTH_SCHEME_DIGEST;
            if (has(WINHTTP_AUTH_SCHEME_BASIC))     return WINHTTP_AUTH_SCHEME_BASIC;
            return 0;
        }
    }

    bool QueryStatus(HINTERNET hReq, DWORD& status) const {
        DWORD code = 0, len = sizeof(code);
        if (!WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &code, &len, WINHTTP_NO_HEADER_INDEX))
            return false;
        status = code;
        return true;
    }

    bool SendOnce(HINTERNET hReq, const std::string& body) {
        BOOL ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            body.empty() ? nullptr : (void*)body.data(), (DWORD)body.size(),
            (DWORD)body.size(), 0);
        if (!ok) {
            LOG("%s WinHttpSendRequest failed: error %lu", m_logTag, GetLastError());
            return false;
        }
        ok = WinHttpReceiveResponse(hReq, nullptr);
        if (!ok) {
            LOG("%s WinHttpReceiveResponse failed: error %lu", m_logTag, GetLastError());
            return false;
        }
        return true;
    }

    // 发送请求；协商类认证会先收到 401，再查询服务端支持的方案并重放，
    // Negotiate/NTLM 通常需要多轮往返。
    bool SendRequestWithAuth(HINTERNET hReq, const std::string& body) {
        if (!SendOnce(hReq, body)) return false;
        if (!IsNegotiatedAuth()) return true;

        for (int attempt = 0; attempt < 4; ++attempt) {
            DWORD status = 0;
            if (!QueryStatus(hReq, status) || status != 401) break;
            DWORD supported = 0, first = 0, target = 0;
            if (!WinHttpQueryAuthSchemes(hReq, &supported, &first, &target)) {
                LOG("%s WinHttpQueryAuthSchemes failed: %lu", m_logTag, GetLastError());
                break;
            }
            DWORD scheme = PickAuthScheme(supported);
            if (!scheme) {
                LOG("%s server offered no usable auth scheme (0x%lX)", m_logTag, supported);
                break;
            }
            auto wUser = HttpUtil::Widen(m_opts.username);
            auto wPass = HttpUtil::Widen(m_opts.password);
            if (!WinHttpSetCredentials(hReq, target, scheme,
                    wUser.c_str(), wPass.c_str(), nullptr)) {
                LOG("%s WinHttpSetCredentials failed: %lu", m_logTag, GetLastError());
                break;
            }
            if (!SendOnce(hReq, body)) return false;
        }
        return true;
    }

    void Shutdown() override {
        if (m_session) {
            WinHttpCloseHandle(m_session);
            m_session = nullptr;
        }
    }

    bool IsReady() const override { return m_session != nullptr; }
    void SetOptions(const TransportOptions& opts) override { m_opts = opts; }

    HttpResp Request(const char* method, const char* host,
                     const std::string& path,
                     const std::string& body,
                     const std::vector<std::string>& hdrs) override {
        HttpResp resp;
        if (!m_session) return resp;

        auto wHost = Widen(host);
        HINTERNET hConn = WinHttpConnect(m_session, wHost.c_str(),
                                          INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConn) return resp;

        auto wMethod = Widen(method);
        auto wPath = Widen(path);
        HINTERNET hReq = WinHttpOpenRequest(hConn, wMethod.c_str(), wPath.c_str(),
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE | WINHTTP_FLAG_ESCAPE_DISABLE);
        if (!hReq) { WinHttpCloseHandle(hConn); return resp; }

        std::vector<std::string> allHdrs = hdrs;
        // Request 走的是 API 域名，正常不会是预签名链接；仍传完整 URL 以防万一
        AddAuthHeaders(allHdrs, std::string("https://") + host + path);
        for (auto& h : allHdrs) {
            auto wh = Widen(h);
            WinHttpAddRequestHeaders(hReq, wh.c_str(), (DWORD)wh.size(),
                                      WINHTTP_ADDREQ_FLAG_ADD);
        }

        ApplyRequestOptions(hReq, body.size());
        BOOL ok = SendRequestWithAuth(hReq, body);

        if (ok) {
            DWORD code = 0, codeLen = sizeof(code);
            WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &code, &codeLen, WINHTTP_NO_HEADER_INDEX);
            resp.status = (int)code;
            ReadBody(hReq, resp.body);
            ReadLocationHeader(hReq, resp.location);
            ReadAllHeaders(hReq, resp.headers);
        }

        WinHttpCloseHandle(hReq);
        WinHttpCloseHandle(hConn);
        return resp;
    }

    HttpResp RequestUrl(const char* method, const std::string& fullUrl,
                        const std::string& body,
                        const std::vector<std::string>& hdrs) override {
        size_t schemeEnd = fullUrl.find("://");
        if (schemeEnd == std::string::npos) return {};
        size_t hostStart = schemeEnd + 3;
        size_t pathStart = fullUrl.find('/', hostStart);
        std::string host = (pathStart != std::string::npos)
            ? fullUrl.substr(hostStart, pathStart - hostStart)
            : fullUrl.substr(hostStart);
        std::string path = (pathStart != std::string::npos)
            ? fullUrl.substr(pathStart)
            : "/";

        bool isHttps = fullUrl.substr(0, schemeEnd) == "https";
        if (!isHttps && !(m_opts.allowInsecureHttp && fullUrl.substr(0, schemeEnd) == "http")) {
            LOG("%s BLOCKED non-HTTPS request to %s", m_logTag, fullUrl.c_str());
            return {};
        }
        if (!m_session) return {};

        INTERNET_PORT port = isHttps ? INTERNET_DEFAULT_HTTPS_PORT
                                     : INTERNET_DEFAULT_HTTP_PORT;
        // IPv6 字面量形如 [::1]:8080，先剥掉方括号再取端口；
        // 否则按第一个 ':' 切分会把主机名截成 '['。
        if (!host.empty() && host.front() == '[') {
            size_t close = host.find(']');
            if (close != std::string::npos) {
                if (close + 1 < host.size() && host[close + 1] == ':')
                    port = (INTERNET_PORT)atoi(host.substr(close + 2).c_str());
                host = host.substr(1, close - 1);
            }
        } else {
            size_t colonPos = host.find(':');
            if (colonPos != std::string::npos) {
                port = (INTERNET_PORT)atoi(host.substr(colonPos + 1).c_str());
                host = host.substr(0, colonPos);
            }
        }

        auto wHost = Widen(host);
        HINTERNET hConn = WinHttpConnect(m_session, wHost.c_str(), port, 0);
        if (!hConn) return {};

        DWORD openFlags = WINHTTP_FLAG_ESCAPE_DISABLE;
        if (isHttps) openFlags |= WINHTTP_FLAG_SECURE;
        auto wMethod = Widen(method);
        auto wPath = Widen(path);
        HINTERNET hReq = WinHttpOpenRequest(hConn, wMethod.c_str(), wPath.c_str(),
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, openFlags);
        if (!hReq) { WinHttpCloseHandle(hConn); return {}; }

        if (isHttps && m_opts.allowInsecureTls) {
            DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                           | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                           | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                           | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
            WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS,
                             &secFlags, sizeof(secFlags));
        }

        std::vector<std::string> allHdrs = hdrs;
        AddAuthHeaders(allHdrs, fullUrl);
        for (auto& h : allHdrs) {
            auto wh = Widen(h);
            WinHttpAddRequestHeaders(hReq, wh.c_str(), (DWORD)wh.size(),
                                      WINHTTP_ADDREQ_FLAG_ADD);
        }

        HttpResp resp;
        ApplyRequestOptions(hReq, body.size());
        BOOL ok = SendRequestWithAuth(hReq, body);

        if (ok) {
            DWORD code = 0, codeLen = sizeof(code);
            WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &code, &codeLen, WINHTTP_NO_HEADER_INDEX);
            resp.status = (int)code;
            ReadBody(hReq, resp.body);
            ReadLocationHeader(hReq, resp.location);
            ReadAllHeaders(hReq, resp.headers);
        }

        WinHttpCloseHandle(hReq);
        WinHttpCloseHandle(hConn);
        return resp;
    }

    HttpResp AuthenticatedGetWithRedirect(const std::string& host,
                                           const std::string& path,
                                           const std::string& authHeader) override {
        if (!m_session) return {};

        auto wHost = Widen(host);
        HINTERNET hConn = WinHttpConnect(m_session, wHost.c_str(),
                                          INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConn) return {};

        auto wPath = Widen(path);
        HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", wPath.c_str(),
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE | WINHTTP_FLAG_ESCAPE_DISABLE);
        if (!hReq) { WinHttpCloseHandle(hConn); return {}; }

        // Disable auto-redirect so we can strip auth before following
        DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        WinHttpSetOption(hReq, WINHTTP_OPTION_REDIRECT_POLICY,
                         &redirectPolicy, sizeof(redirectPolicy));

        auto wAuth = Widen(authHeader);
        WinHttpAddRequestHeaders(hReq, wAuth.c_str(), (DWORD)wAuth.size(),
                                  WINHTTP_ADDREQ_FLAG_ADD);

        BOOL ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0);
        if (ok) ok = WinHttpReceiveResponse(hReq, nullptr);

        HttpResp resp;
        if (!ok) {
            WinHttpCloseHandle(hReq);
            WinHttpCloseHandle(hConn);
            return resp;
        }

        DWORD statusCode = 0, codeLen = sizeof(statusCode);
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &codeLen, WINHTTP_NO_HEADER_INDEX);
        resp.status = (int)statusCode;

        if (statusCode == 200) {
            ReadBody(hReq, resp.body);
            WinHttpCloseHandle(hReq);
            WinHttpCloseHandle(hConn);
            return resp;
        }

        if (statusCode == 302) {
            DWORD locLen = 0;
            WinHttpQueryHeaders(hReq, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
                WINHTTP_NO_OUTPUT_BUFFER, &locLen, WINHTTP_NO_HEADER_INDEX);
            std::wstring wLoc(locLen / sizeof(wchar_t), 0);
            WinHttpQueryHeaders(hReq, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
                wLoc.data(), &locLen, WINHTTP_NO_HEADER_INDEX);
            while (!wLoc.empty() && wLoc.back() == 0) wLoc.pop_back();

            WinHttpCloseHandle(hReq);
            WinHttpCloseHandle(hConn);

            if (wLoc.empty()) { resp.status = 0; return resp; }

            int n = WideCharToMultiByte(CP_UTF8, 0, wLoc.c_str(), (int)wLoc.size(),
                                         nullptr, 0, nullptr, nullptr);
            std::string location(n, 0);
            WideCharToMultiByte(CP_UTF8, 0, wLoc.c_str(), (int)wLoc.size(),
                                 location.data(), n, nullptr, nullptr);

            // 去掉认证头再跟跳转：预签名链接自带授权，带上 Bearer 会被判 401。
            // RequestUrl 内部的 AddAuthHeaders 也会识别签名 URL 跳过，这里是双保险。
            LOG("%s Redirect to pre-signed URL, dropping Authorization", m_logTag);
            return RequestUrl("GET", location, {}, {});
        }

        WinHttpCloseHandle(hReq);
        WinHttpCloseHandle(hConn);
        return resp;
    }

private:
    void ReadLocationHeader(HINTERNET hReq, std::string& location) {
        DWORD size = 0;
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
            WINHTTP_NO_OUTPUT_BUFFER, &size, WINHTTP_NO_HEADER_INDEX);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0) return;
        std::wstring wLoc(size / sizeof(wchar_t), 0);
        if (!WinHttpQueryHeaders(hReq, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
                wLoc.data(), &size, WINHTTP_NO_HEADER_INDEX)) return;
        while (!wLoc.empty() && wLoc.back() == 0) wLoc.pop_back();
        if (wLoc.empty()) return;
        int n = WideCharToMultiByte(CP_UTF8, 0, wLoc.c_str(), (int)wLoc.size(),
                                     nullptr, 0, nullptr, nullptr);
        if (n <= 0) return;
        location.resize(n);
        WideCharToMultiByte(CP_UTF8, 0, wLoc.c_str(), (int)wLoc.size(),
                             location.data(), n, nullptr, nullptr);
    }

    // Query the full raw header block and fold it into a lower-cased map so
    // callers can read S3 response headers (x-amz-version-id, etag, ...).
    void ReadAllHeaders(HINTERNET hReq, std::map<std::string, std::string>& out) {
        DWORD size = 0;
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_RAW_HEADERS_CRLF,
            WINHTTP_HEADER_NAME_BY_INDEX, WINHTTP_NO_OUTPUT_BUFFER, &size,
            WINHTTP_NO_HEADER_INDEX);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0) return;
        std::wstring wRaw(size / sizeof(wchar_t), 0);
        if (!WinHttpQueryHeaders(hReq, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                WINHTTP_HEADER_NAME_BY_INDEX, wRaw.data(), &size,
                WINHTTP_NO_HEADER_INDEX)) return;
        int n = WideCharToMultiByte(CP_UTF8, 0, wRaw.c_str(), (int)wRaw.size(),
                                     nullptr, 0, nullptr, nullptr);
        if (n <= 0) return;
        std::string raw(n, 0);
        WideCharToMultiByte(CP_UTF8, 0, wRaw.c_str(), (int)wRaw.size(),
                             raw.data(), n, nullptr, nullptr);

        size_t pos = 0;
        while (pos < raw.size()) {
            size_t eol = raw.find("\r\n", pos);
            std::string line = raw.substr(pos, (eol == std::string::npos ? raw.size() : eol) - pos);
            pos = (eol == std::string::npos) ? raw.size() : eol + 2;
            size_t colon = line.find(':');
            if (colon == std::string::npos) continue;  // status line or blank
            std::string name = line.substr(0, colon);
            for (char& c : name) c = (char)tolower((unsigned char)c);
            size_t vs = colon + 1;
            while (vs < line.size() && (line[vs] == ' ' || line[vs] == '\t')) vs++;
            out[name] = line.substr(vs);
        }
    }

    void ReadBody(HINTERNET hReq, std::string& body) {
        DWORD avail, got;
        while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
            if (body.size() + avail > 1024ULL * 1024 * 1024) {
                LOG("%s Response body exceeded 1GB cap, aborting read", m_logTag);
                break;
            }
            size_t off = body.size();
            body.resize(off + avail);
            got = 0;
            if (!WinHttpReadData(hReq, &body[off], avail, &got))
                got = 0;
            body.resize(off + got);
        }
    }

    const char* m_logTag;
    HINTERNET m_session = nullptr;
    TransportOptions m_opts;
};

// Factory function
std::unique_ptr<IHttpTransport> CreateHttpTransport(const char* logTag) {
    return std::make_unique<WinHttpTransport>(logTag);
}
