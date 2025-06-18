#include "bry_challenge/core.h"
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
#include <iostream>
#include <iterator>
#include <sstream>

using namespace Poco::Net;
using namespace Poco::Util;
using namespace Poco;

namespace {

constexpr const uint16_t PORT = 8080;

}

class SignPartHandler : public PartHandler {
public:
    void handlePart(const MessageHeader& header, std::istream& stream) override {
        if (!header.has("Content-Disposition")) {
            return;
        }

        std::string disp;
        NameValueCollection params;
        MessageHeader::splitParameters(header["Content-Disposition"], disp, params);

        if (params.has("pkcs12Passwd")) {
            pkcs12Passwd = std::string(std::istream_iterator<char>(stream), std::istream_iterator<char>());
        } else if (params.has("pkcs12")) {
            pkcs12 = std::vector<char>(std::istream_iterator<char>(stream), std::istream_iterator<char>());
        } else if (params.has("data")) {
            data = std::vector<char>(std::istream_iterator<char>(stream), std::istream_iterator<char>());
        }
    }

    std::vector<char> pkcs12;
    std::vector<char> data;
    std::string pkcs12Passwd;
};

class SignHandler : public HTTPRequestHandler
{
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
            try {
                bry_challenge::cmsSign(
                    reinterpret_cast<unsigned char*>(partHandler.pkcs12.data()),
                    partHandler.pkcs12.size(),
                    partHandler.pkcs12Passwd.c_str(),
                    partHandler.data.data(),
                    partHandler.data.size(),
                    &out,
                    &outLen
                );
            } catch (const bry_challenge::InvalidPKCS12& err) {
                response.setStatus(HTTPResponse::HTTP_BAD_REQUEST);
                ostr << "Invalid PKCS12 file, or wrong password";
                return;
            } catch (const std::exception& err) {
                response.setStatus(HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            std::ostringstream base64Stream;
            Base64Encoder encoder(base64Stream);
            encoder.write(out, outLen);
            encoder.close();

            response.setStatus(HTTPResponse::HTTP_OK);
            ostr << base64Stream.str();
        } catch (Exception& ex) {
            response.setStatus(HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
            ostr << "Error: " << ex.displayText() << "\n";
        }
    }
};

class RequestHandlerFactory : public HTTPRequestHandlerFactory {
public:
    HTTPRequestHandler* createRequestHandler(const HTTPServerRequest& request) override {
        if (request.getURI() == "/signature/") {
            return new SignHandler{};
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

