#include "bry_challenge/core.h"
#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPRequestHandlerFactory.h>
#include <Poco/Net/HTTPServerParams.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Util/ServerApplication.h>
#include <Poco/Util/Application.h>
#include <Poco/StreamCopier.h>
#include <Poco/Exception.h>
#include <iostream>
#include <sstream>

using namespace Poco::Net;
using namespace Poco::Util;
using namespace Poco;

class HelloRequestHandler : public HTTPRequestHandler {
public:
    void handleRequest(HTTPServerRequest& request, HTTPServerResponse& response) override {
        response.setStatus(HTTPResponse::HTTP_OK);
        response.setContentType("application/json");

        std::ostream& ostr = response.send();
        ostr << R"({"message": "Hello, REST world!"})";
    }
};

class RequestHandlerFactory : public HTTPRequestHandlerFactory {
public:
    HTTPRequestHandler* createRequestHandler(const HTTPServerRequest& request) override {
        if (request.getURI() == "/api/hello")
            return new HelloRequestHandler;
        else
            return nullptr;  // 404
    }
};

class RESTServerApp : public ServerApplication {
protected:
    int main(const std::vector<std::string>&) override {
        HTTPServer server(new RequestHandlerFactory(),
                          ServerSocket(8080),
                          new HTTPServerParams);

        server.start();
        std::cout << "Server started on port 8080" << std::endl;

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

