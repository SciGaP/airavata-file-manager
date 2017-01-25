/*
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
*/
package org.apache.airavata.filemgr;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class AuthenticationMgr {
    private final static Logger logger = LoggerFactory.getLogger(AuthenticationMgr.class);

    private Connection connect = null;
    private PreparedStatement preparedStatement = null;
    private ResultSet resultSet = null;

    public boolean authenticate(String username,String password) throws AuthenticationException {
        try {
            Class.forName("com.mysql.jdbc.Driver");
            connect = DriverManager.getConnection(AiravataFileMgrProperties.getInstance().getGrichemMySQLUrl());
            preparedStatement = connect.prepareStatement("select password from Users where userName=?");
            preparedStatement.setString(1, username);
            resultSet = preparedStatement.getResultSet();
            if (resultSet.next()) {
                String storedPassword = resultSet.getString("password");
                return SHA1.encrypt(password).equals(storedPassword);
            }else{
                return false;
            }
        }catch (Exception ex){
            throw new AuthenticationException(ex);
        }
    }
}