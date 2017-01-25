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

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.root.RootedFileSystemProvider;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.command.ScpCommandFactory;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.subsystem.sftp.SftpSubsystemFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystem;
import java.security.PublicKey;
import java.util.Collections;

public class AiravataFileMgr {

    private final static Logger logger = LoggerFactory.getLogger(AiravataFileMgr.class);

    public void setupSftpServer() throws IOException {
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(AiravataFileMgrProperties.getInstance().getServerPort());

        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(new File(this.getClass().getResource("/hostkey.ser").getPath())));

        sshd.setPasswordAuthenticator(new PasswordAuthenticator() {
            public boolean authenticate(String username, String accessToken, ServerSession serverSession) {
                AuthenticationMgr authenticationMgr = new AuthenticationMgr();
                try {
                    return authenticationMgr.authenticate(username, accessToken);
                } catch (AuthenticationException e) {
                    e.printStackTrace();
                }
                return false;
            }
        });

        sshd.setPublickeyAuthenticator(new PublickeyAuthenticator() {
            public boolean authenticate(String s, PublicKey publicKey, ServerSession serverSession) {
                return false;
            }
        });

        sshd.setSubsystemFactories(Collections.<NamedFactory<Command>>singletonList(new SftpSubsystemFactory()));
        sshd.setCommandFactory(new ScpCommandFactory());
        FileSystemFactory fileSystemFactory = new FileSystemFactory() {
            public FileSystem createFileSystem(Session session) throws IOException {
                String userName = session.getUsername();

                String homeDirStr = AiravataFileMgrProperties.getInstance().getDataRoot() + File.separator + userName;
                File homeDir = new File(homeDirStr);

                if ((!homeDir.exists()) && (!homeDir.mkdirs())) {
                    logger.error("Cannot create user home :: " + homeDirStr);
                }

                FileSystem rootFileSystem = new RootedFileSystemProvider().newFileSystem((new File(homeDirStr).toPath()),
                        Collections.<String, Object>emptyMap());
                return rootFileSystem;
            }
        };
        sshd.setFileSystemFactory(fileSystemFactory);

        try {
            sshd.start();
            Thread.sleep(Long.MAX_VALUE);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws IOException {
        AiravataFileMgr airavataFileManager = new AiravataFileMgr();
        airavataFileManager.setupSftpServer();
    }

}