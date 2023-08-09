/*
Copyright 2019-2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import React, { useEffect, useState, useRef } from 'react';
import { Box, Indicator, Flex } from 'design';

import styled from 'styled-components';

import { DbProtocol } from 'shared/services/databases';

import {
  FeatureBox,
  FeatureHeader,
  FeatureHeaderTitle,
} from 'teleport/components/Layout';
import ErrorMessage from 'teleport/components/AgentErrorMessage';
import useTeleport from 'teleport/useTeleport';
import DbConnectDialog from 'teleport/Databases/ConnectDialog';
import KubeConnectDialog from 'teleport/Kubes/ConnectDialog';
import AgentButtonAdd from 'teleport/components/AgentButtonAdd';
import QuickLaunch from 'teleport/components/QuickLaunch';

import { useResources } from './useResources';
import { ResourceCard } from './ResourceCard';
import SearchPanel from './SearchPanel';
import { FilterPanel } from './FilterPanel';

export function Resources() {
  const teleCtx = useTeleport();
  const {
    attempt,
    fetchedData,
    fetchMore,
    getNodeLoginOptions,
    getWindowsLoginOptions,
    accessRequestId,
    canCreate,
    isLeafCluster,
    username,
    clusterId,
    authType,
    startSshSession,
    startRemoteDesktopSession,
    filtering: {
      pathname,
      params,
      setParams,
      setSort,
      replaceHistory,
      onLabelClick,
    },
  } = useResources(teleCtx);
  const observed = useRef(null);

  const [dbConnectInfo, setDbConnectInfo] = useState<{
    name: string;
    protocol: DbProtocol;
  }>(null);

  const [kubeConnectName, setKubeConnectName] = useState('');

  useEffect(() => {
    if (observed.current) {
      const observer = new IntersectionObserver(entries => {
        if (entries[0]?.isIntersecting) {
          fetchMore();
        }
      });
      observer.observe(observed.current);
      return () => observer.disconnect();
    }
  });

  return (
    <FeatureBox>
      <FeatureHeader alignItems="center" justifyContent="space-between">
        <FeatureHeaderTitle>Resources</FeatureHeaderTitle>
        {attempt.status === 'success' && (
          <Flex alignItems="center">
            <QuickLaunch width="280px" onPress={startSshSession} mr={3} />
            <AgentButtonAdd
              agent="unified_resource"
              beginsWithVowel={false}
              isLeafCluster={isLeafCluster}
              canCreate={canCreate}
            />
          </Flex>
        )}
      </FeatureHeader>
      <SearchPanel
        params={params}
        setParams={setParams}
        pathname={pathname}
        replaceHistory={replaceHistory}
      />
      <FilterPanel
        params={params}
        setParams={setParams}
        setSort={setSort}
        pathname={pathname}
        replaceHistory={replaceHistory}
      />
      {attempt.status === 'failed' && (
        <ErrorMessage message={attempt.statusText} />
      )}
      <ResourcesContainer gap={2}>
        {fetchedData.agents.map((agent, i) => (
          <ResourceCard
            key={i}
            onLabelClick={onLabelClick}
            resource={agent}
            getNodeLoginOptions={getNodeLoginOptions}
            getWindowsLoginOptions={getWindowsLoginOptions}
            startRemoteDesktopSession={startRemoteDesktopSession}
            startSshSession={startSshSession}
            setDbConnectInfo={setDbConnectInfo}
            setKubeConnectInfo={setKubeConnectName}
          />
        ))}
      </ResourcesContainer>
      <div
        ref={observed}
        style={{
          visibility: attempt.status === 'processing' ? 'visible' : 'hidden',
        }}
      >
        {(attempt.status === 'processing' || fetchedData.startKey) && (
          <Box
            textAlign="center"
            style={{ visible: attempt.status === 'processing' }}
          >
            <Indicator />
          </Box>
        )}
      </div>
      {dbConnectInfo && (
        <DbConnectDialog
          username={username}
          clusterId={clusterId}
          dbName={dbConnectInfo.name}
          dbProtocol={dbConnectInfo.protocol}
          onClose={() => setDbConnectInfo(null)}
          authType={authType}
          accessRequestId={accessRequestId}
        />
      )}
      {kubeConnectName && (
        <KubeConnectDialog
          onClose={() => setKubeConnectName('')}
          username={username}
          authType={authType}
          kubeConnectName={kubeConnectName}
          clusterId={clusterId}
          accessRequestId={accessRequestId}
        />
      )}
    </FeatureBox>
  );
}

const ResourcesContainer = styled(Flex)`
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
`;
