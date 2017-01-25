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

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class AiravataFileMgrProperties {
    private final static Logger logger = LoggerFactory.getLogger(AiravataFileMgrProperties.class);
    private static AiravataFileMgrProperties instance;

    private Properties properties = new Properties();
    private static final String PROPERTY_FILE_NAME = "/filemgr.properties";

    private AiravataFileMgrProperties(){
        InputStream inputStream = AiravataFileMgr.class.getResourceAsStream(PROPERTY_FILE_NAME);
        try {
            properties.load(inputStream);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static AiravataFileMgrProperties getInstance(){
        if(instance==null){
            instance = new AiravataFileMgrProperties();
        }
        return instance;
    }

    public String getIdpUrl() {
        return properties.getProperty(AiravataFileMgrConfig.IDP_URL);
    }

    public String[] getAuthorisedUserRoles() {
        return properties.getProperty(AiravataFileMgrConfig.IDP_AUTHORISED_ROLES).split(",");
    }

    public String getDataRoot() {
        return properties.getProperty(AiravataFileMgrConfig.USER_DATA_ROOT);
    }

    public int getServerPort() {
        return Integer.parseInt(properties.getProperty(AiravataFileMgrConfig.SFTP_PORT));
    }

    public String getGrichemMySQLUrl() {
        return properties.getProperty(AiravataFileMgrConfig.GRIDCHEM_MYSQL_URL);
    }
}