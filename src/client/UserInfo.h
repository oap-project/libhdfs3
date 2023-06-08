/********************************************************************
 * Copyright (c) 2013 - 2014, Pivotal Inc.
 * All rights reserved.
 *
 * Author: Zhanwei Wang
 ********************************************************************/
/********************************************************************
 * 2014 -
 * open source under Apache License Version 2.0
 ********************************************************************/
/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef _HDFS_LIBHDFS3_CLIENT_USERINFO_H_
#define _HDFS_LIBHDFS3_CLIENT_USERINFO_H_

#include <map>
#include <mutex>
#include <string>

#include "Hash.h"
#include "KerberosName.h"
#include "Token.h"

#include "Logger.h"

namespace Hdfs {
namespace Internal {
class AuthTokens {
  public:
    AuthTokens() {}
    AuthTokens(const AuthTokens &other) { tokens = other.tokens; }
    AuthTokens &operator=(const AuthTokens &other) {
        tokens = other.tokens;
        return *this;
    }
    AuthTokens(AuthTokens &&other) { tokens = std::move(other.tokens); }
    AuthTokens &operator=(AuthTokens &&other) {
        tokens = std::move(other.tokens);
        return *this;
    }

    void addToken(const Token &token);
    const Token *selectToken(const std::string &kind,
                             const std::string &service) const;

  private:
    std::map<std::pair<std::string, std::string>, Token> tokens;
    mutable std::mutex mtx;
};

class UserInfo {
public:
    UserInfo() {
    }

    explicit UserInfo(const std::string & u) :
        effectiveUser(u) {
    }

    const std::string & getRealUser() const {
        return realUser;
    }

    void setRealUser(const std::string & user) {
        this->realUser = user;
    }

    const std::string & getEffectiveUser() const {
        return effectiveUser.getName();
    }

    void setEffectiveUser(const std::string & effectiveUser) {
        this->effectiveUser = KerberosName(effectiveUser);
    }

    std::string getPrincipal() const {
        return effectiveUser.getPrincipal();
    }

    bool operator ==(const UserInfo & other) const {
        return realUser == other.realUser
               && effectiveUser == other.effectiveUser;
    }

    void addToken(const Token &token) { tokens.addToken(token); }

    const Token * selectToken(const std::string & kind, const std::string & service) const {
        auto private_token = tokens.selectToken(kind, service);

        // HACK: Share tokens in default user instance
        if (!private_token && effectiveUser == default_user.effectiveUser)
            return default_user.tokens.selectToken(kind, service);

        return private_token;
    }

    size_t hash_value() const;

public:
    static UserInfo LocalUser();
    static UserInfo &DefaultUser() { return default_user; };

  private:
    KerberosName effectiveUser;
    AuthTokens tokens;
    std::string realUser;

    static UserInfo default_user;
};

}
}

HDFS_HASH_DEFINE(::Hdfs::Internal::UserInfo);

#endif /* _HDFS_LIBHDFS3_CLIENT_USERINFO_H_ */
