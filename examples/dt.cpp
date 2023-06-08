#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <thread>

#include "client/hdfs.h"

int main(int argc, char **argv) try {
    hdfsFS fs = nullptr;

    // Parse args
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " host port princ" << std::endl;
        return 1;
    }
    std::string nn_host = argv[1];
    int nn_port = std::atoi(argv[2]);
    std::string principal = argv[3];

    // Banner
    std::cerr
        << "Please REMOVE /tmp/krb5cc_$UID to verify that token is work."
        << std::endl
        << "Delegation token can be found in java UGI: "
           "`org.apache.hadoop.security.UserGroupInformation.getCurrentUser."
           "getTokens.forEach(t => println(t.getService, t.encodeToUrlString))`"
        << std::endl;

    // Set default user
    hdfsSetDefautUserName(principal.c_str());

    while (true) {
        std::cout << "\033[1;34mAdd token: \033[0m";
        std::string token;
        if (!std::getline(std::cin, token)) {
            std::cout << "Bye" << std::endl;
            break;
        }

        if (!token.empty()) {
            if (hdfsSetTokenForDefaultUser(token.c_str()) != 0) {
                std::cerr << hdfsGetLastError() << std::endl;
                continue;
            }
        }

        if (!fs) {
            std::cerr << "Connect hdfs..." << std::endl;
            auto *bld = hdfsNewBuilder();
            hdfsBuilderSetNameNode(bld, nn_host.c_str());
            hdfsBuilderSetNameNodePort(bld, nn_port);
            fs = hdfsBuilderConnect(bld);
            hdfsFreeBuilder(bld);

            if (!fs) {
                std::cerr << hdfsGetLastError() << std::endl;
                continue;
            }
        }

        int cnt = -1;
        auto *info = hdfsListDirectory(fs, "/", &cnt);

        if (info) {
            std::cerr << "Count children: " << cnt << std::endl;
            hdfsFreeFileInfo(info, cnt);
        } else {
            std::cerr << hdfsGetLastError() << std::endl;
        }
    }

    // Delegation Token can be issued only with kerberos or web authentication
    // hdfsGetDelegationToken(fs, "hdfs");
    // std::cerr << hdfsGetLastError() << std::endl;

    return 0;
} catch (std::exception &e) {
    std::cerr << "Exception: " << e.what() << std::endl;
    return 1;
}