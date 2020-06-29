/*
 * Copyright 2010-2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 *
 */
package com.amazon.example.service;

import com.amazon.example.pojo.User;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import org.apache.commons.codec.binary.Base64;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptResponse;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.List;
import java.util.stream.Collectors;

@ApplicationScoped
public class UserService extends AbstractService {

    @Inject
    DynamoDbClient dynamoDB;
    @Inject
    KmsClient kms;
    String keyArn = "alias/sasha-quarkus-demo";

    public List<User> findAll() {
        return dynamoDB.scanPaginator(scanRequest()).items().stream()
                .map(User::from)
                .map(u -> {
                    u.setSecret(decrypt(u.getSecret()));
                    return u;
                })
                .collect(Collectors.toList());
    }

    public String add(User user) {
        user.setSecret(encrypt(user.getFirstName() + user.getLastName()));
        dynamoDB.putItem(putRequest(user));

        return user.getUserId();
    }

    public User get(String userId) {
        User user = User.from(dynamoDB.getItem(getRequest(userId)).item());
        user.setSecret(decrypt(user.getSecret()));
        return user;
    }

    public String delete(String userId) {
        dynamoDB.deleteItem(deleteRequest(userId));

        return userId;
    }

    private String encrypt(String data) {
        SdkBytes encryptedBytes = kms.encrypt(req -> req.keyId(keyArn).plaintext(SdkBytes.fromUtf8String(data))).ciphertextBlob();
        return Base64.encodeBase64String(encryptedBytes.asByteArray());
    }

    private String decrypt(String data) {
        SdkBytes encryptedData = SdkBytes.fromByteArray(Base64.decodeBase64(data.getBytes()));
        DecryptResponse decrypted = kms.decrypt(req -> req.keyId(keyArn).ciphertextBlob(encryptedData));
        return decrypted.plaintext().asUtf8String();
    }
}
