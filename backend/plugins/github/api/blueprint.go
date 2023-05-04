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

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/apache/incubator-devlake/core/errors"

	"github.com/apache/incubator-devlake/core/models/domainlayer/didgen"
	"github.com/apache/incubator-devlake/core/plugin"
	"github.com/apache/incubator-devlake/core/utils"
	"github.com/apache/incubator-devlake/helpers/pluginhelper/api"
	helper "github.com/apache/incubator-devlake/helpers/pluginhelper/api"
	aha "github.com/apache/incubator-devlake/helpers/pluginhelper/api/apihelperabstract"
	"github.com/apache/incubator-devlake/plugins/github/models"
	"github.com/apache/incubator-devlake/plugins/github/tasks"
)

func MakePipelinePlan(
	subtaskMetas []plugin.SubTaskMeta,
	connectionId uint64,
	scope []*plugin.BlueprintScopeV100,
) (plugin.PipelinePlan, errors.Error) {
	var err errors.Error
	connection := new(models.GithubConnection)
	err = connectionHelper.FirstById(connection, connectionId)
	if err != nil {
		return nil, err
	}
	apiClient, err := helper.NewApiClientFromConnection(context.TODO(), basicRes, connection)
	if err != nil {
		return nil, err
	}
	plan, err := makePipelinePlan(subtaskMetas, scope, apiClient, connection)
	if err != nil {
		return nil, err
	}
	return plan, nil
}

func makePipelinePlan(
	subtaskMetas []plugin.SubTaskMeta,
	scopeV100s []*plugin.BlueprintScopeV100,
	apiClient aha.ApiClientAbstract,
	connection *models.GithubConnection,
) (plugin.PipelinePlan, errors.Error) {
	var err errors.Error
	var repo *tasks.GithubApiRepo
	plan := make(plugin.PipelinePlan, len(scopeV100s))
	for i, scopeElem := range scopeV100s {
		// handle taskOptions and transformationRules, by dumping them to taskOptions
		transformationRules := make(map[string]interface{})
		if len(scopeElem.Transformation) > 0 {
			err = errors.Convert(json.Unmarshal(scopeElem.Transformation, &transformationRules))
			if err != nil {
				return nil, err
			}
		}
		// construct task options for github
		options := make(map[string]interface{})
		err = errors.Convert(json.Unmarshal(scopeElem.Options, &options))
		if err != nil {
			return nil, err
		}
		options["connectionId"] = connection.ID
		options["transformationRules"] = transformationRules
		// make sure task options is valid
		op, err := tasks.DecodeAndValidateTaskOptions(options)
		if err != nil {
			return nil, err
		}

		// refdiff
		if refdiffRules, ok := transformationRules["refdiff"]; ok && refdiffRules != nil {
			// add a new task to next stage
			j := i + 1
			if j == len(plan) {
				plan = append(plan, nil)
			}
			repo, err = MemorizedGetApiRepo(repo, op, apiClient)
			if err != nil {
				return nil, err
			}
			ops := refdiffRules.(map[string]interface{})
			ops["repoId"] = didgen.NewDomainIdGenerator(&models.GithubRepo{}).Generate(connection.ID, repo.GithubId)
			plan[j] = plugin.PipelineStage{{
				Plugin:  "refdiff",
				Options: ops,
			},
			}
			// remove it from github transformationRules
			delete(transformationRules, "refdiff")
		}

		stage := plan[i]
		if stage == nil {
			stage = plugin.PipelineStage{}
		}
		stage, err = addGithub(subtaskMetas, connection, scopeElem.Entities, stage, options)
		if err != nil {
			return nil, err
		}
		// collect git data by gitextractor if CODE was requested
		repo, err = MemorizedGetApiRepo(repo, op, apiClient)
		if err != nil {
			return nil, err
		}
		stage, err = addGitex(scopeElem.Entities, connection, repo, stage)
		if err != nil {
			return nil, err
		}
		// This is just to add a dora subtask, then we can add another two subtasks at the end of plans
		// The only purpose is to adapt old blueprints
		// DEPRECATED, will be removed in v0.17
		// dora
		if productionPattern, ok := transformationRules["productionPattern"]; ok && productionPattern != nil {
			j := i + 1
			if j == len(plan) {
				plan = append(plan, nil)
			}
			// add a new task to next stage
			if plan[j] != nil {
				j++
			}
			if j == len(plan) {
				plan = append(plan, nil)
			}
			plan[j] = plugin.PipelineStage{
				{
					Plugin:   "dora",
					Subtasks: []string{"EnrichTaskEnv"},
					Options:  map[string]interface{}{},
				},
			}
		}
		plan[i] = stage
		repo = nil
	}
	return plan, nil
}

func addGitex(entities []string,
	connection *models.GithubConnection,
	repo *tasks.GithubApiRepo,
	stage plugin.PipelineStage,
) (plugin.PipelineStage, errors.Error) {
	if utils.StringsContains(entities, plugin.DOMAIN_TYPE_CODE) {
		// here is the tricky part, we have to obtain the repo id beforehand

		var token string
		if connection.AuthMethod == "githubapp" {
			apiClient, err := api.NewApiClientFromConnection(context.TODO(), basicRes, connection)
			if err != nil {
				return nil, err
			}

			newConnection, err := connection.UseAppInstallationTokenForRepo(repo.Name, apiClient)
			if err != nil {
				return nil, err
			}

			token = strings.Split(newConnection.Token, ",")[0]
		} else {
			token = strings.Split(connection.Token, ",")[0]
		}

		cloneUrl, err := errors.Convert01(url.Parse(repo.CloneUrl))
		if err != nil {
			return nil, err
		}
		cloneUrl.User = url.UserPassword("git", token)
		stage = append(stage, &plugin.PipelineTask{
			Plugin: "gitextractor",
			Options: map[string]interface{}{
				"url":    cloneUrl.String(),
				"repoId": didgen.NewDomainIdGenerator(&models.GithubRepo{}).Generate(connection.ID, repo.GithubId),
				"proxy":  connection.Proxy,
			},
		})
	}
	return stage, nil
}

func addGithub(subtaskMetas []plugin.SubTaskMeta, connection *models.GithubConnection, entities []string, stage plugin.PipelineStage, options map[string]interface{}) (plugin.PipelineStage, errors.Error) {
	// construct github(graphql) task
	if connection.EnableGraphql {
		// FIXME this need fix when 2 plugins merged
		p, err := plugin.GetPlugin(`github_graphql`)
		if err != nil {
			return nil, err
		}
		if pluginGq, ok := p.(plugin.PluginTask); ok {
			subtasks, err := helper.MakePipelinePlanSubtasks(pluginGq.SubTaskMetas(), entities)
			if err != nil {
				return nil, err
			}
			stage = append(stage, &plugin.PipelineTask{
				Plugin:   "github_graphql",
				Subtasks: subtasks,
				Options:  options,
			})
		} else {
			return nil, errors.BadInput.New("plugin github_graphql does not support SubTaskMetas")
		}
	} else {
		subtasks, err := helper.MakePipelinePlanSubtasks(subtaskMetas, entities)
		if err != nil {
			return nil, err
		}
		stage = append(stage, &plugin.PipelineTask{
			Plugin:   "github",
			Subtasks: subtasks,
			Options:  options,
		})
	}
	return stage, nil
}

func getApiRepo(
	op *tasks.GithubOptions,
	apiClient aha.ApiClientAbstract,
) (*tasks.GithubApiRepo, errors.Error) {
	repoRes := &tasks.GithubApiRepo{}
	res, err := apiClient.Get(fmt.Sprintf("repos/%s", op.Name), nil, nil)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, errors.HttpStatus(res.StatusCode).New(fmt.Sprintf("unexpected status code when requesting repo detail from %s", res.Request.URL.String()))
	}
	body, err := errors.Convert01(io.ReadAll(res.Body))
	if err != nil {
		return nil, err
	}
	err = errors.Convert(json.Unmarshal(body, repoRes))
	if err != nil {
		return nil, err
	}
	return repoRes, nil
}

func MemorizedGetApiRepo(
	repo *tasks.GithubApiRepo,
	op *tasks.GithubOptions, apiClient aha.ApiClientAbstract,
) (*tasks.GithubApiRepo, errors.Error) {
	if repo == nil {
		var err errors.Error
		repo, err = getApiRepo(op, apiClient)
		if err != nil {
			return nil, err
		}
	}
	return repo, nil
}
