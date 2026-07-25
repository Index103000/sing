package http

import (
	std_bufio "bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

func HandleConnectionEx(
	ctx context.Context,
	conn net.Conn,
	reader *std_bufio.Reader,
	authenticator *auth.Authenticator,
	handler N.TCPConnectionHandlerEx,
	source M.Socksaddr,
	onClose N.CloseHandlerFunc,
) error {
	for {
		request, err := ReadRequest(reader)
		if err != nil {
			return E.Cause(err, "read http request")
		}
		if authenticator != nil {
			username, password, authOk := ParseBasicAuth(request.Header.Get("Proxy-Authorization"))
			authOk = authOk && authenticator.Verify(username, password)
			if authOk {
				ctx = auth.ContextWithUser(ctx, username)
			} else {
				keepAlive := !(request.ProtoMajor == 1 && request.ProtoMinor == 0) && strings.TrimSpace(strings.ToLower(request.Header.Get("Proxy-Connection"))) == "keep-alive" && request.ContentLength == 0
				// Since no one else is using the library, use a fixed realm until rewritten
				headers := []string{"Proxy-Authenticate", `Basic realm="sing-box" charset="UTF-8"`}
				if !keepAlive {
					headers = append(headers, "Connection", "close")
				}

				// 构造 HTTP 407 Proxy Authentication Required 响应。
				//
				// 这里不能只返回状态码，还必须包含 Proxy-Authenticate 响应头，
				// 客户端（例如 FFmpeg）收到该响应后，才知道代理服务器要求
				// 使用 Basic 认证，并会重新发送携带 Proxy-Authorization 的 CONNECT 请求。
				proxyAuthRequiredResponse := responseWith(
					request,
					http.StatusProxyAuthRequired,
					headers...,
				)

				// 不再直接调用 proxyAuthRequiredResponse.Write(conn)。
				//
				// http.Response.Write 会分步骤将状态行、响应头和响应体写入 conn。
				// 对普通 TCP 连接而言，一次 Write 调用不保证写完全部数据；
				// 如果连接随后被关闭，客户端可能只收到：
				//
				//     HTTP/1.1 407 Proxy Authentication Required
				//     Connection: close
				//
				// 却没有收到关键的：
				//
				//     Proxy-Authenticate: Basic realm="sing-box" charset="UTF-8"
				//
				// FFmpeg 在这种情况下无法识别认证方式，最终会报告 EOF。
				//
				// 因此这里先把完整 HTTP 响应序列化到内存，再统一写入底层连接，
				// 同时检查是否发生短写。
				err = writeResponseBuffered(conn, proxyAuthRequiredResponse)
				if err != nil {
					// 补充错误上下文，便于从日志中判断失败发生在
					// “写出 407 代理认证响应”这一阶段，而不是读取请求或校验密码阶段。
					return E.Cause(err, "write proxy authentication required response")
				}

				if keepAlive {
					continue
				}
				authorization := request.Header.Get("Proxy-Authorization")
				switch {
				case username != "":
					return E.New("http: authentication failed, username=", username, ", password=", password)
				case authorization != "":
					return E.New("http: authentication failed, Proxy-Authorization=", authorization)
				default:
					return E.New("http: authentication failed, no Proxy-Authorization header")
				}
			}
		}

		if sourceAddress := SourceAddress(request); sourceAddress.IsValid() {
			source = sourceAddress
		}

		if request.Method == "CONNECT" {
			destination := M.ParseSocksaddrHostPortStr(request.URL.Hostname(), request.URL.Port()).Unwrap()
			if destination.Port == 0 {
				switch request.URL.Scheme {
				case "https", "wss":
					destination.Port = 443
				default:
					destination.Port = 80
				}
			}
			_, err = conn.Write([]byte(F.ToString("HTTP/", request.ProtoMajor, ".", request.ProtoMinor, " 200 Connection established\r\n\r\n")))
			if err != nil {
				return E.Cause(err, "write http response")
			}
			var requestConn net.Conn
			if reader.Buffered() > 0 {
				buffer := buf.NewSize(reader.Buffered())
				_, err = buffer.ReadFullFrom(reader, reader.Buffered())
				if err != nil {
					return err
				}
				requestConn = bufio.NewCachedConn(conn, buffer)
			} else {
				requestConn = conn
			}
			handler.NewConnectionEx(ctx, requestConn, source, destination, onClose)
			return nil
		} else if strings.ToLower(request.Header.Get("Connection")) == "upgrade" {
			destination := M.ParseSocksaddrHostPortStr(request.URL.Hostname(), request.URL.Port()).Unwrap()
			if destination.Port == 0 {
				switch request.URL.Scheme {
				case "https", "wss":
					destination.Port = 443
				default:
					destination.Port = 80
				}
			}
			serverConn, clientConn := pipe.Pipe()
			go func() {
				handler.NewConnectionEx(ctx, clientConn, source, destination, func(it error) {
					if it != nil {
						common.Close(serverConn, clientConn)
					}
				})
			}()
			err = request.Write(serverConn)
			if err != nil {
				return E.Cause(err, "http: write upgrade request")
			}
			if reader.Buffered() > 0 {
				_, err = io.CopyN(serverConn, reader, int64(reader.Buffered()))
				if err != nil {
					return err
				}
			}
			return bufio.CopyConn(ctx, conn, serverConn)
		} else {
			err = handleHTTPConnection(ctx, handler, conn, request, source)
			if err != nil {
				return err
			}
		}
	}
}

func handleHTTPConnection(
	ctx context.Context,
	handler N.TCPConnectionHandlerEx,
	conn net.Conn,
	request *http.Request, source M.Socksaddr,
) error {
	keepAlive := !(request.ProtoMajor == 1 && request.ProtoMinor == 0) && strings.TrimSpace(strings.ToLower(request.Header.Get("Proxy-Connection"))) == "keep-alive"
	request.RequestURI = ""

	removeHopByHopHeaders(request.Header)
	removeExtraHTTPHostPort(request)

	if hostStr := request.Header.Get("Host"); hostStr != "" {
		if hostStr != request.URL.Host {
			request.Host = hostStr
		}
	}

	if request.URL.Scheme == "" || request.URL.Host == "" {
		return responseWith(request, http.StatusBadRequest).Write(conn)
	}

	var innerErr common.TypedValue[error]
	httpClient := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				input, output := pipe.Pipe()
				go handler.NewConnectionEx(ctx, output, source, M.ParseSocksaddr(address).Unwrap(), func(it error) {
					innerErr.Store(it)
					common.Close(input, output)
				})
				return input, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer httpClient.CloseIdleConnections()

	requestCtx, cancel := context.WithCancel(ctx)
	response, err := httpClient.Do(request.WithContext(requestCtx))
	if err != nil {
		cancel()
		return E.Errors(innerErr.Load(), err, responseWith(request, http.StatusBadGateway).Write(conn))
	}

	removeHopByHopHeaders(response.Header)

	if keepAlive {
		response.Header.Set("Proxy-Connection", "keep-alive")
		response.Header.Set("Connection", "keep-alive")
		response.Header.Set("Keep-Alive", "timeout=4")
	}

	response.Close = !keepAlive

	err = response.Write(conn)
	if err != nil {
		cancel()
		return E.Errors(innerErr.Load(), err)
	}

	cancel()
	if !keepAlive {
		return conn.Close()
	}
	return nil
}

func removeHopByHopHeaders(header http.Header) {
	// Strip hop-by-hop header based on RFC:
	// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html#sec13.5.1
	// https://www.mnot.net/blog/2011/07/11/what_proxies_must_do

	header.Del("Proxy-Connection")
	header.Del("Proxy-Authenticate")
	header.Del("Proxy-Authorization")
	header.Del("TE")
	header.Del("Trailers")
	header.Del("Transfer-Encoding")
	header.Del("Upgrade")

	connections := header.Get("Connection")
	header.Del("Connection")
	if len(connections) == 0 {
		return
	}
	for h := range strings.SplitSeq(connections, ",") {
		header.Del(strings.TrimSpace(h))
	}
}

func removeExtraHTTPHostPort(req *http.Request) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	if pHost, port, err := net.SplitHostPort(host); err == nil && port == "80" {
		if M.ParseAddr(pHost).Is6() {
			pHost = "[" + pHost + "]"
		}
		host = pHost
	}

	req.Host = host
	req.URL.Host = host
}

// writeResponseBuffered 将一个完整的 HTTP 响应先序列化到内存缓冲区，
// 再写入底层网络连接。
//
// 该函数主要用于 HTTP 407 Proxy Authentication Required 响应。
//
// 背景：
//
//	http.Response.Write(conn) 内部可能执行多次底层写入，例如分别写入：
//	1. HTTP 状态行；
//	2. HTTP 响应头；
//	3. 空行；
//	4. 响应体。
//
//	TCP 的 Write 语义并不保证一次写入请求中的所有字节都会成功写出。
//	在连接关闭、客户端并发建立连接或网络状态异常时，可能发生短写。
//	如果 407 响应只写出一部分，客户端可能收不到 Proxy-Authenticate，
//	从而不知道应该使用 Basic 代理认证。
//
// 处理方式：
//  1. 先将整个 HTTP 响应写入 bytes.Buffer；
//  2. 得到完整、连续的字节序列；
//  3. 将该字节序列写入网络连接；
//  4. 检查实际写入长度是否等于响应总长度。
//
// 参数：
//
//	conn:
//	  当前客户端与 HTTP 代理服务器之间的 TCP 连接。
//
//	response:
//	  需要发送给客户端的完整 HTTP 响应。
//
// 返回值：
//
//	nil:
//	  HTTP 响应已经完整写入连接。
//
//	error:
//	  响应序列化失败、网络写入失败，或者发生短写。
func writeResponseBuffered(conn net.Conn, response *http.Response) error {
	// 在内存中保存完整序列化后的 HTTP 响应。
	var responseBuffer bytes.Buffer

	// 先让标准库把状态行、响应头、空行以及响应体完整写入缓冲区。
	//
	// 此时不会直接操作网络连接，因此不会出现客户端只收到半个响应的情况。
	if err := response.Write(&responseBuffer); err != nil {
		return err
	}

	// 将已经完整序列化的 HTTP 响应写入 TCP 连接。
	//
	// 注意：即使传入完整字节切片，net.Conn.Write 仍有可能出现：
	//   n < len(data)
	//
	// 因此不能只检查 err，还必须检查实际写入的字节数。
	n, err := conn.Write(responseBuffer.Bytes())
	if err != nil {
		return err
	}

	// 如果实际写入字节数少于响应总长度，说明发生了短写。
	//
	// 返回 io.ErrShortWrite 可以明确表示：
	// 网络层没有完整发送本次 HTTP 407 响应。
	if n != responseBuffer.Len() {
		return io.ErrShortWrite
	}

	return nil
}

func responseWith(request *http.Request, statusCode int, headers ...string) *http.Response {
	var header http.Header
	if len(headers) > 0 {
		header = make(http.Header)
		for i := 0; i < len(headers); i += 2 {
			header.Add(headers[i], headers[i+1])
		}
	}
	return &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Proto:      request.Proto,
		ProtoMajor: request.ProtoMajor,
		ProtoMinor: request.ProtoMinor,
		Header:     header,
	}
}
