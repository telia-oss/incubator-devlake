/*
Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements.  See the NOTICE file distributed with
this work for additional information regarding copyright ownership.
The ASF licenses this file to You under the Apache License, Version 2.0
(the "License"); you may not use this file except in compliance with
the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package models

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/apache/incubator-devlake/core/errors"
	helper "github.com/apache/incubator-devlake/helpers/pluginhelper/api"
	"github.com/apache/incubator-devlake/helpers/pluginhelper/api/apihelperabstract"
	"github.com/golang-jwt/jwt/v5"
)

// GithubAccessToken supports fetching data with multiple tokens
type GithubAccessToken struct {
	Token      string   `mapstructure:"token" json:"token" gorm:"serializer:encdec"`
	tokens     []string `gorm:"-" json:"-" mapstructure:"-"`
	tokenIndex int      `gorm:"-" json:"-" mapstructure:"-"`
}

type GithubAppInfo struct {
	AppId     string `gorm:"serializer:encdec" json:"appId" mapstructure:"appId"`
	SecretKey string `gorm:"serializer:encdec" json:"secretKey" mapstructure:"secretKey"`
}

// GithubConn holds the essential information to connect to the Github API
type GithubConn struct {
	AuthMethod            string `mapstructure:"authMethod" json:"authMethod"`
	helper.RestConnection `mapstructure:",squash"`
	GithubAccessToken     `mapstructure:",squash"`
	GithubAppInfo         `mapstructure:",squash"`
}

// PrepareApiClient splits Token to tokens for SetupAuthentication to utilize
func (conn *GithubConn) PrepareApiClient(apiClient apihelperabstract.ApiClientAbstract) errors.Error {
	conn.tokens = strings.Split(conn.Token, ",")
	return nil
}

// SetupAuthentication sets up the HTTP Request Authentication
func (conn *GithubConn) SetupAuthentication(req *http.Request) errors.Error {
	if conn.AuthMethod == "githubapp" {
		// Generate an app token
		token := jwt.New(jwt.SigningMethodRS256)

		//current time
		t := time.Now().Unix()

		token.Claims = jwt.MapClaims{
			"iat": t,
			"exp": t + (10 * 60),
			"iss": conn.GithubAppInfo.AppId,
		}

		privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(conn.GithubAppInfo.SecretKey))
		if err != nil {
			return errors.AsLakeErrorType(err)
		}

		tokenString, err := token.SignedString(privateKey)
		if err != nil {
			return errors.AsLakeErrorType(err)
		}

		req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", tokenString))
	} else {
		// Rotates token on each request.
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", conn.tokens[conn.tokenIndex]))
		// Set next token index
		conn.tokenIndex = (conn.tokenIndex + 1) % len(conn.tokens)
	}
	return nil
}

// GetTokensCount returns total number of tokens
func (gat *GithubAccessToken) GetTokensCount() int {
	return len(gat.tokens)
}

// GithubConnection holds GithubConn plus ID/Name for database storage
type GithubConnection struct {
	helper.BaseConnection `mapstructure:",squash"`
	GithubConn            `mapstructure:",squash"`
	EnableGraphql         bool `mapstructure:"enableGraphql" json:"enableGraphql"`
}

func (GithubConnection) TableName() string {
	return "_tool_github_connections"
}

func (c *GithubConnection) UseAppInstallationTokenForRepo(repo string, apiClient apihelperabstract.ApiClientAbstract) (*GithubConnection, errors.Error) {
	if c.AuthMethod != "githubapp" {
		return nil, errors.AsLakeErrorType(fmt.Errorf("AuthMethod is not githubapp"))
	}

	installationRes, err := getAppInstallation(repo, apiClient)
	if err != nil {
		return nil, err
	}

	return c.UseAppInstallationToken(installationRes.Id, apiClient)
}

func (c *GithubConnection) UseAppInstallationToken(installationId int32, apiClient apihelperabstract.ApiClientAbstract) (*GithubConnection, errors.Error) {
	if c.AuthMethod != "githubapp" {
		return nil, errors.AsLakeErrorType(fmt.Errorf("AuthMethod is not githubapp"))
	}

	tokenRes, err := getAppInstallationAccessToken(apiClient, installationId)
	if err != nil {
		return nil, err
	}

	newConn := *c

	newConn.AuthMethod = "token"
	newConn.Token = tokenRes.Token
	return &newConn, nil
}

// Using GithubUserOfToken because it requires authentication, and it is public information anyway.
type GithubUserOfToken struct {
	Login string `json:"login"`
}

type InstallationToken struct {
	Token string `json:"token"`
}

type GithubApp struct {
	ID   int32  `json:"id"`
	Slug string `json:"slug"`
}

type GithubAppInstallation struct {
	Id int32 `json:"id"`
}

func getAppInstallation(
	repo string,
	apiClient apihelperabstract.ApiClientAbstract,
) (*GithubAppInstallation, errors.Error) {
	installationRes := &GithubAppInstallation{}

	res, err := apiClient.Get(fmt.Sprintf("repos/%s/installation", repo), nil, nil)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, errors.HttpStatus(res.StatusCode).New(fmt.Sprintf("unexpected status code when requesting repo installation from %s", res.Request.URL.String()))
	}
	body, err := errors.Convert01(io.ReadAll(res.Body))
	if err != nil {
		return nil, err
	}
	err = errors.Convert(json.Unmarshal(body, installationRes))
	if err != nil {
		return nil, err
	}
	return installationRes, nil
}

func getAppInstallationAccessToken(
	apiClient apihelperabstract.ApiClientAbstract,
	installationID int32,
) (*InstallationToken, errors.Error) {

	resp, err := apiClient.Post(fmt.Sprintf("/app/installations/%d/access_tokens", installationID), nil, nil, nil)
	if err != nil {
		return nil, err
	}

	body, err := errors.Convert01(io.ReadAll(resp.Body))
	if err != nil {
		return nil, err
	}

	var installationToken InstallationToken
	err = errors.Convert(json.Unmarshal(body, &installationToken))
	if err != nil {
		return nil, err
	}

	return &installationToken, nil
}
