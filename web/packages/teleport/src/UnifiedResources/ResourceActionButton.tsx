/**
 * Copyright 2023 Gravitational, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import React from 'react';
import { ButtonBorder } from 'design';
import { LoginItem, MenuLogin } from 'shared/components/MenuLogin';
import { DbProtocol } from 'shared/services/databases';

import { UnifiedResource } from 'teleport/services/agents';

import AwsLaunchButton from 'teleport/Apps/AppList/AwsLaunchButton';
import { Database } from 'teleport/services/databases';
import { App } from 'teleport/services/apps';
import { Kube } from 'teleport/services/kube';
import { Desktop } from 'teleport/services/desktops';

type Props = {
  resource: UnifiedResource;
  getNodeLoginOptions: (serverId: string) => LoginItem[];
  getWindowsLoginOptions: (desktop: Desktop) => LoginItem[];
  startSshSession: (login: string, serverId: string) => void;
  startRemoteDesktopSession: (username: string, desktopName: string) => void;
  setDbConnectInfo: React.Dispatch<
    React.SetStateAction<{
      name: string;
      protocol: DbProtocol;
    }>
  >;
  setKubeConnectInfo: React.Dispatch<React.SetStateAction<string>>;
};

export const ResourceActionButton = ({
  resource,
  getNodeLoginOptions,
  getWindowsLoginOptions,
  startSshSession,
  startRemoteDesktopSession,
  setDbConnectInfo,
  setKubeConnectInfo,
}: Props) => {
  switch (resource.kind) {
    case 'node':
      return renderNodeConnect(
        resource.id,
        startSshSession,
        getNodeLoginOptions
      );
    case 'app':
      return renderAppLaunch(resource);
    case 'db':
      return renderDatabaseConnect(resource, setDbConnectInfo);
    case 'kube_cluster':
      return renderKubeConnect(resource, setKubeConnectInfo);
    case 'windows_desktop':
      return renderDesktopConnect(
        resource,
        getWindowsLoginOptions,
        startRemoteDesktopSession
      );
    default:
      return null;
  }
};

const renderNodeConnect = (
  id: string,
  startSshSession: (login: string, serverId: string) => void,
  onOpen: (serverId: string) => LoginItem[]
) => {
  function handleOnOpen() {
    return onOpen(id);
  }

  function handleOnSelect(_, login: string) {
    if (!startSshSession) {
      return [];
    }

    return startSshSession(login, id);
  }

  return (
    <MenuLogin
      getLoginItems={handleOnOpen}
      onSelect={handleOnSelect}
      transformOrigin={{
        vertical: 'top',
        horizontal: 'right',
      }}
      anchorOrigin={{
        vertical: 'center',
        horizontal: 'right',
      }}
    />
  );
};

function renderDesktopConnect(
  desktop: Desktop,
  onOpen: (desktop: Desktop) => LoginItem[],
  onSelect: (username: string, desktopName: string) => void
) {
  function handleOnOpen() {
    return onOpen(desktop);
  }

  function handleOnSelect(_, login: string) {
    if (!onSelect) {
      return [];
    }

    return onSelect(login, desktop.name);
  }

  return (
    <MenuLogin
      getLoginItems={handleOnOpen}
      onSelect={handleOnSelect}
      transformOrigin={{
        vertical: 'top',
        horizontal: 'right',
      }}
      anchorOrigin={{
        vertical: 'center',
        horizontal: 'right',
      }}
    />
  );
}

function renderAppLaunch({
  launchUrl,
  awsConsole,
  awsRoles,
  fqdn,
  clusterId,
  publicAddr,
  isCloudOrTcpEndpoint,
  samlApp,
  samlAppSsoUrl,
}: App) {
  let $btn;
  if (awsConsole) {
    $btn = (
      <AwsLaunchButton
        awsRoles={awsRoles}
        fqdn={fqdn}
        clusterId={clusterId}
        publicAddr={publicAddr}
      />
    );
  } else if (isCloudOrTcpEndpoint) {
    $btn = (
      <ButtonBorder
        disabled
        width="88px"
        size="small"
        title="Cloud or TCP applications cannot be launched by the browser"
      >
        LAUNCH
      </ButtonBorder>
    );
  } else if (samlApp) {
    $btn = (
      <ButtonBorder
        as="a"
        width="88px"
        size="small"
        target="_blank"
        href={samlAppSsoUrl}
        rel="noreferrer"
      >
        LOGIN
      </ButtonBorder>
    );
  } else {
    $btn = (
      <ButtonBorder
        as="a"
        width="88px"
        size="small"
        target="_blank"
        href={launchUrl}
        rel="noreferrer"
      >
        LAUNCH
      </ButtonBorder>
    );
  }

  return $btn;
}

function renderDatabaseConnect(
  { name, protocol }: Database,
  setDbConnectInfo: React.Dispatch<
    React.SetStateAction<{
      name: string;
      protocol: DbProtocol;
    }>
  >
) {
  return (
    <ButtonBorder
      size="small"
      onClick={() => {
        setDbConnectInfo({ name, protocol });
      }}
    >
      Connect
    </ButtonBorder>
  );
}

export const renderKubeConnect = (
  { name }: Kube,
  setKubeConnectName: React.Dispatch<React.SetStateAction<string>>
) => {
  return (
    <ButtonBorder size="small" onClick={() => setKubeConnectName(name)}>
      Connect
    </ButtonBorder>
  );
};
