/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

import { request } from '@/utils';

type PaginationParams = {
  page: number;
  per_page: number;
};

export const getUser = (prefix: string) => request(`${prefix}/user`);

export const getAppInstallations = (prefix: string) => request(`${prefix}/app/installations`);

export const getInstallationRepos = (connectionId: string | number, installationId: string, params: PaginationParams) =>
  request(`/plugins/github/connections/${connectionId}/installations/${installationId}/proxy/rest/installation/repositories`, {
    method: 'get',
    data: {
      ...params,
    },
  });

export const getUserOrgs = (prefix: string, params: PaginationParams) =>
  request(`${prefix}/user/orgs`, {
    method: 'get',
    data: params,
  });

export const getOrgRepos = (prefix: string, org: string, params: PaginationParams) =>
  request(`${prefix}/orgs/${org}/repos`, {
    method: 'get',
    data: {
      ...params,
      sort: 'full_name',
    },
  });

export const getUserRepos = (prefix: string, params: PaginationParams) =>
  request(`${prefix}/user/repos`, {
    method: 'get',
    data: {
      ...params,
      type: 'owner',
      sort: 'full_name',
    },
  });

type SearchRepoParams = {
  q: string;
};

export const searchRepo = (prefix: string, params: SearchRepoParams) =>
  request(`${prefix}/search/repositories`, {
    method: 'get',
    data: params,
  });

export const testConnection = (payload: any) => request('/plugins/github/test', { method: 'post', data: payload });
