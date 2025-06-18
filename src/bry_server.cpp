#include "bry_challenge/core.h"
#include <Poco/JSON/Object.h>
#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPRequestHandlerFactory.h>
#include <Poco/Net/HTTPServerParams.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Net/HTMLForm.h>
#include <Poco/Net/MessageHeader.h>
#include <Poco/Net/NameValueCollection.h>
#include <Poco/Net/PartHandler.h>
#include <Poco/Util/ServerApplication.h>
#include <Poco/Util/Application.h>
#include <Poco/Base64Encoder.h>
#include <Poco/StreamCopier.h>
#include <Poco/Exception.h>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>

using namespace Poco::Net;
using namespace Poco::Util;
using namespace Poco;

namespace {

constexpr const uint16_t PORT = 8080;

std::string getPartValue(const MessageHeader& header) {
    std::string disp;
    NameValueCollection params;
    MessageHeader::splitParameters(header["Content-Disposition"], disp, params);
    return params.get("name", "");
}

std::string toISO8601(const std::tm& tm) {
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

}

class VerifyPartHandler : public PartHandler {
public:
    void handlePart(const MessageHeader& header, std::istream& stream) override {
        if (!header.has("Content-Disposition")) {
            return;
        }

        auto name = ::getPartValue(header);
        if (name == "signed_data") {
            signedData = std::vector<char>(std::istream_iterator<char>(stream), std::istream_iterator<char>());
        }
    }

    std::vector<char> signedData;
};

class SignPartHandler : public PartHandler {
public:
    void handlePart(const MessageHeader& header, std::istream& stream) override {
        if (!header.has("Content-Disposition")) {
            return;
        }
        auto name = ::getPartValue(header);
        if (name == "pkcs12_passwd") {
            pkcs12Passwd = std::string(std::istream_iterator<char>(stream), std::istream_iterator<char>());
        } else if (name == "pkcs12") {
            pkcs12 = std::vector<char>(std::istream_iterator<char>(stream), std::istream_iterator<char>());
        } else if (name == "data") {
            data = std::vector<char>(std::istream_iterator<char>(stream), std::istream_iterator<char>());
        }
    }

    std::vector<char> pkcs12;
    std::vector<char> data;
    std::string pkcs12Passwd;
};

class VerifyHandler : public HTTPRequestHandler {
public:
    void handleRequest(HTTPServerRequest &request, HTTPServerResponse &response) override {
        response.setContentType("application/json");
        std::ostream& ostr = response.send();

        if (request.getMethod() != HTTPRequest::HTTP_POST) {
            response.setStatus(HTTPResponse::HTTP_METHOD_NOT_ALLOWED);
            ostr << R"({"error":"Only POST allowed"})";
            return;
        }

        try {
            VerifyPartHandler partHandler;
            HTMLForm form(request, request.stream(), partHandler);

            if (partHandler.signedData.empty()) {
                response.setStatus(HTTPResponse::HTTP_BAD_REQUEST);
                ostr << "Missing parameter signed_data";
                return;
            }

            bry_challenge::SignInfo signInfo;
            bool validSignature = bry_challenge::cmsVerify(
                partHandler.signedData.data(),
                partHandler.signedData.size(),
                signInfo
            );

            JSON::Object info, root;
            info.set("common_name", signInfo.commonName);
            info.set("signing_time", ::toISO8601(signInfo.signingTime));
            info.set("digest_algorithm", signInfo.digestAlgorithm);
            info.set("encap_content_info", signInfo.encapContentInfoHex);
            root.set("valid", validSignature ? "VALIDO" : "INVALIDO");
            root.set("info", info);

            response.setStatus(HTTPResponse::HTTP_OK);
            root.stringify(ostr);

        } catch (Exception& exc) {
            JSON::Object err;
            err.set("error", exc.displayText());
            response.setStatus(HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
            err.stringify(ostr);
            return;
        } catch (const bry_challenge::PKCS7Error& exc) {
            JSON::Object err;
            err.set("error", "Invalid PKCS7 file");
            response.setStatus(HTTPResponse::HTTP_BAD_REQUEST);
            err.stringify(ostr);
            return;
        } catch (const std::exception& exc) {
            response.setStatus(HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }
};

class SignHandler : public HTTPRequestHandler {
public:
    void handleRequest(HTTPServerRequest &request, HTTPServerResponse &response) override {
        response.setContentType("text/plain");
        std::ostream &ostr = response.send();

        if (request.getMethod() != HTTPRequest::HTTP_POST) {
            response.setStatus(HTTPResponse::HTTP_METHOD_NOT_ALLOWED);
            ostr << "Only POST allowed";
            return;
        }

        try {
            SignPartHandler partHandler;
            HTMLForm form(request, request.stream(), partHandler);

            if (partHandler.pkcs12.empty() || partHandler.data.empty() || partHandler.pkcs12Passwd.empty()) {
                response.setStatus(HTTPResponse::HTTP_BAD_REQUEST);
                ostr << "Missing parameters";
                return;
            }

            char *out = nullptr;
            std::size_t outLen = 0;
            bry_challenge::cmsSign(
                reinterpret_cast<unsigned char*>(partHandler.pkcs12.data()),
                partHandler.pkcs12.size(),
                partHandler.pkcs12Passwd.c_str(),
                partHandler.data.data(),
                partHandler.data.size(),
                &out,
                &outLen
            );

            std::ostringstream base64Stream;
            Base64Encoder encoder(base64Stream);
            encoder.write(out, outLen);
            encoder.close();

            response.setStatus(HTTPResponse::HTTP_OK);
            ostr << base64Stream.str();
        } catch (Exception& err) {
            response.setStatus(HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
            ostr << "Error: " << err.displayText() << "\n";
            return;
        } catch (const bry_challenge::PKCS12Error& err) {
            response.setStatus(HTTPResponse::HTTP_BAD_REQUEST);
            ostr << "Invalid PKCS12 file, or wrong password";
            return;
        } catch (const std::exception& err) {
            response.setStatus(HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }
};

class RequestHandlerFactory : public HTTPRequestHandlerFactory {
public:
    HTTPRequestHandler* createRequestHandler(const HTTPServerRequest& request) override {
        if (request.getURI() == "/signature/") {
            return new SignHandler{};
        } else if (request.getURI() == "/verify/") {
            return new VerifyHandler{};
        } else {
            return nullptr;  // 404
        }
    }
};

class RESTServerApp : public ServerApplication {
protected:
    int main(const std::vector<std::string>&) override {
        HTTPServer server(new RequestHandlerFactory(),
                          PORT,
                          new HTTPServerParams);

        server.start();
        std::cout << "Server started on port " << PORT << std::endl;

        waitForTerminationRequest(); // CTRL-C or kill
        server.stop();
        std::cout << "Server stopped" << std::endl;

        return Application::EXIT_OK;
    }
};

int main(int argc, char** argv) {
    RESTServerApp app;
    return app.run(argc, argv);
}

