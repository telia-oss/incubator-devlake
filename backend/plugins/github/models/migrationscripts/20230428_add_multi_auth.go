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

package migrationscripts

import (
	"github.com/apache/incubator-devlake/core/context"
	"github.com/apache/incubator-devlake/core/dal"
	"github.com/apache/incubator-devlake/core/errors"
)

type githubMultiAuth20230428 struct {
	AppId      string
	SecretKey  string
	AuthMethod string
}

func (githubMultiAuth20230428) TableName() string {
	return "_tool_github_connections"
}

type addGithubMultiAuth struct{}

func (*addGithubMultiAuth) Up(res context.BasicRes) errors.Error {
	db := res.GetDal()
	err := db.AutoMigrate(&githubMultiAuth20230428{})
	if err != nil {
		return err
	}
	err = db.UpdateColumn(
		&GithubConnection20221111{},
		`auth_method`,
		"AccessToken",
		dal.Where(`token IS NOT NULL`),
	)
	if err != nil {
		return err
	}
	return err
}

func (*addGithubMultiAuth) Version() uint64 {
	return 20230428000010
}

func (*addGithubMultiAuth) Name() string {
	return "UpdateSchemas for addGithubMultiAuth"
}
