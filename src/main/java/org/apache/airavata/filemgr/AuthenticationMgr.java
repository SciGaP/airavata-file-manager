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

import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthBearerClientRequest;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthResourceResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.codehaus.jackson.map.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

public class AuthenticationMgr {
    private final static Logger logger = LoggerFactory.getLogger(AuthenticationMgr.class);

    String hostName = AiravataFileMgrProperties.getInstance().getIdpUrl();

    public boolean authenticate(String username,String accessToken) throws AuthenticationException {
        try {
            if(accessToken != null && !accessToken.isEmpty()){
                OAuthClientRequest request = new OAuthBearerClientRequest(hostName + "/auth/realms/iu-geology-survey/protocol/openid-connect/userinfo").
                        buildQueryMessage();
                URLConnectionClient ucc = new URLConnectionClient();
                request.setHeader("Authorization","Bearer "+accessToken);
                org.apache.oltu.oauth2.client.OAuthClient oAuthClient = new org.apache.oltu.oauth2.client.OAuthClient(ucc);
                OAuthResourceResponse resp = oAuthClient.resource(request, OAuth.HttpMethod.GET,
                        OAuthResourceResponse.class);
                ObjectMapper mapper = new ObjectMapper();
                Map<String,String> profile = mapper.readValue(resp.getBody(), Map.class);
                if(profile.containsKey("preferred_username") && profile.get("preferred_username").equalsIgnoreCase(username)){
                    return true;
                }
            }
        }catch (Exception ex){
            ex.printStackTrace();
        }
        return false;
    }
}
