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

public class AiravataFileMgrConfig {
    private final static Logger logger = LoggerFactory.getLogger(AiravataFileMgrConfig.class);

    public static final String SFTP_PORT = "sftp.port";
    public static final String IDP_URL = "idp.url";
    public static final String IDP_AUTHORISED_ROLES = "idp.authorised.roles";
    public static final String USER_DATA_ROOT = "user.data.root";
    public static final java.lang.String GRIDCHEM_MYSQL_URL = "gridchem.mysql.url";
}