/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package common_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/mfa"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/mocku2f"
	wancli "github.com/gravitational/teleport/lib/auth/webauthncli"
	wantypes "github.com/gravitational/teleport/lib/auth/webauthntypes"
	libclient "github.com/gravitational/teleport/lib/client"
	libmfa "github.com/gravitational/teleport/lib/client/mfa"
	"github.com/gravitational/teleport/lib/service/servicecfg"
	"github.com/gravitational/teleport/lib/utils"
	tctl "github.com/gravitational/teleport/tool/tctl/common"
	testserver "github.com/gravitational/teleport/tool/teleport/testenv"
	tsh "github.com/gravitational/teleport/tool/tsh/common"
	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestAdminATestAdminActionMFA is an e2e tests for "tctl" admin actions with MFA.
func TestAdminActionMFA(t *testing.T) {
	s := newAdminActionTestSuite(t)

	t.Run("UserCommand", func(t *testing.T) {
		testAdminActionMFA_UserCommands(t, s)
	})

	t.Run("ResourceCommand", func(t *testing.T) {
		testAdminActionMFA_ResourceCommands(t, s)
	})
}

type adminActionTestSuite struct {
	authServer        *auth.Server
	userClientWithMFA auth.ClientI
	userClientNoMFA   auth.ClientI
}

func newAdminActionTestSuite(t *testing.T) *adminActionTestSuite {
	ctx := context.Background()

	process := testserver.MakeTestServer(t)
	proxyAddr, err := process.ProxyWebAddr()
	require.NoError(t, err)
	authAddr, err := process.AuthAddr()
	require.NoError(t, err)
	authServer := process.GetAuthServer()

	// create admin role and user.
	username := "admin"
	adminRole, err := types.NewRole(username, types.RoleSpecV6{
		Allow: types.RoleConditions{
			Rules: []types.Rule{
				{
					Resources: []string{types.Wildcard},
					Verbs:     []string{types.Wildcard},
				},
			},
		},
	})
	require.NoError(t, err)
	adminRole, err = authServer.CreateRole(ctx, adminRole)
	require.NoError(t, err)

	user, err := types.NewUser(username)
	user.SetRoles([]string{adminRole.GetName()})
	require.NoError(t, err)
	_, err = authServer.CreateUser(ctx, user)
	require.NoError(t, err)

	// setup mfa for the user.
	err = authServer.SetAuthPreference(ctx, &types.AuthPreferenceV2{
		Spec: types.AuthPreferenceSpecV2{
			Type:         constants.Local,
			SecondFactor: constants.SecondFactorOptional,
			Webauthn: &types.Webauthn{
				RPID: "127.0.0.1",
			},
		},
	})
	require.NoError(t, err)

	mockWebauthnLogin := setupWebAuthn(t, authServer, username)
	mockMFAPromptConstructor := func(opts ...mfa.PromptOpt) mfa.Prompt {
		promptCfg := libmfa.NewPromptConfig(proxyAddr.String(), opts...)
		promptCfg.WebauthnLoginFunc = mockWebauthnLogin
		return libmfa.NewCLIPrompt(promptCfg, os.Stderr)
	}

	// Login as the admin user.
	tshHome := t.TempDir()
	err = tsh.Run(context.Background(), []string{
		"login",
		"--insecure",
		"--debug",
		"--user", username,
		"--proxy", proxyAddr.String(),
		"--auth", constants.PasswordlessConnector,
	},
		setHomePath(tshHome),
		setKubeConfigPath(filepath.Join(t.TempDir(), teleport.KubeConfigFile)),
		func(c *tsh.CLIConf) error {
			c.WebauthnLogin = mockWebauthnLogin
			return nil
		},
	)
	require.NoError(t, err)

	userClientNoMFA, err := auth.NewClient(client.Config{
		Addrs: []string{authAddr.String()},
		Credentials: []client.Credentials{
			client.LoadProfile(tshHome, ""),
		},
	})
	require.NoError(t, err)

	userClientWithMFA, err := auth.NewClient(client.Config{
		Addrs: []string{authAddr.String()},
		Credentials: []client.Credentials{
			client.LoadProfile(tshHome, ""),
		},
		MFAPromptConstructor: mockMFAPromptConstructor,
	})
	require.NoError(t, err)

	return &adminActionTestSuite{
		authServer:        authServer,
		userClientNoMFA:   userClientNoMFA,
		userClientWithMFA: userClientWithMFA,
	}
}

func (s *adminActionTestSuite) runTestCase(t *testing.T, ctx context.Context, tc adminActiontestCase) {
	t.Run("OK with MFA", func(t *testing.T) {
		err := s.runTestSubCase(t, ctx, tc, s.userClientWithMFA)
		require.NoError(t, err)
	})

	t.Run("NOK without MFA", func(t *testing.T) {
		err := s.runTestSubCase(t, ctx, tc, s.userClientNoMFA)
		require.ErrorContains(t, err, mfa.ErrAdminActionMFARequired.Message)
	})

	// turn MFA off, admin actions should not require MFA now.
	oldAuthPref, err := s.authServer.GetAuthPreference(ctx)
	require.NoError(t, err)
	err = s.authServer.SetAuthPreference(ctx, &types.AuthPreferenceV2{
		Spec: types.AuthPreferenceSpecV2{
			Type:         constants.Local,
			SecondFactor: constants.SecondFactorOff,
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, s.authServer.SetAuthPreference(ctx, oldAuthPref))
	})

	t.Run("OK mfa off", func(t *testing.T) {
		err := s.runTestSubCase(t, ctx, tc, s.userClientNoMFA)
		require.NoError(t, err)
	})
}

func (s *adminActionTestSuite) runTestSubCase(t *testing.T, ctx context.Context, tc adminActiontestCase, client auth.ClientI) error {
	t.Helper()

	if tc.setup != nil {
		tc.setup(t, s.authServer)
	}
	if tc.cleanup != nil {
		t.Cleanup(func() { tc.cleanup(t, s.authServer) })
	}

	app := utils.InitCLIParser("tctl", tctl.GlobalHelpString)
	cfg := servicecfg.MakeDefaultConfig()
	tc.cliCommand.Initialize(app, cfg)

	args := strings.Split(tc.command, " ")
	commandName, err := app.Parse(args)
	require.NoError(t, err)

	match, err := tc.cliCommand.TryRun(ctx, commandName, client)
	require.True(t, match)
	return err
}

type adminActiontestCase struct {
	command    string
	cliCommand tctl.CLICommand
	setup      func(t *testing.T, auth *auth.Server)
	cleanup    func(t *testing.T, auth *auth.Server)
}

func testAdminActionMFA_ResourceCommands(t *testing.T, s *adminActionTestSuite) {
	ctx := context.Background()

	user, err := types.NewUser("teleuser")
	require.NoError(t, err)

	for _, rc := range []struct {
		resource        types.Resource
		resourceSetup   func(t *testing.T, authServer *auth.Server)
		resourceCleanup func(t *testing.T, authServer *auth.Server)
		editDisabled    bool
	}{
		{
			resource: user,
			resourceSetup: func(t *testing.T, authServer *auth.Server) {
				_, err := authServer.CreateUser(ctx, user)
				if !trace.IsAlreadyExists(err) {
					require.NoError(t, err)
				}
			},
			resourceCleanup: func(t *testing.T, authServer *auth.Server) {
				err := authServer.DeleteUser(ctx, user.GetName())
				if !trace.IsNotFound(err) {
					require.NoError(t, err)
				}
			},
			editDisabled: true, // editing users secrets is not allowed.
		},
	} {
		resource := rc.resource
		resourceKind := resource.GetKind()
		resourceName := resource.GetName()

		t.Run(resourceKind, func(t *testing.T) {
			t.Parallel()

			resourceYaml, err := yaml.Marshal(resource)
			require.NoError(t, err)
			resourceYamlPath := filepath.Join(t.TempDir(), fmt.Sprintf("%v.yaml", resourceKind))
			require.NoError(t, os.WriteFile(resourceYamlPath, []byte(resourceYaml), 0o644))

			t.Run(fmt.Sprintf("create %v.yaml", resourceKind), func(t *testing.T) {
				s.runTestCase(t, ctx, adminActiontestCase{
					command:    fmt.Sprintf("create %v", resourceYamlPath),
					cliCommand: &tctl.ResourceCommand{},
					cleanup:    rc.resourceCleanup,
				})
			})

			t.Run(fmt.Sprintf("create -f %v.yaml", resourceKind), func(t *testing.T) {
				s.runTestCase(t, ctx, adminActiontestCase{
					command:    fmt.Sprintf("create -f %v", resourceYamlPath),
					cliCommand: &tctl.ResourceCommand{},
					setup:      rc.resourceSetup,
					cleanup:    rc.resourceCleanup,
				})
			})

			rmCommand := fmt.Sprintf("rm %v/%v", resourceKind, resourceName)
			t.Run(rmCommand, func(t *testing.T) {
				s.runTestCase(t, ctx, adminActiontestCase{
					command:    rmCommand,
					cliCommand: &tctl.ResourceCommand{},
					setup:      rc.resourceSetup,
					cleanup:    rc.resourceCleanup,
				})
			})

			if !rc.editDisabled {
				editCommand := fmt.Sprintf("edit %v/%v", resourceKind, resourceName)
				t.Run(editCommand, func(t *testing.T) {
					s.runTestCase(t, ctx, adminActiontestCase{
						command: editCommand,
						cliCommand: &tctl.EditCommand{
							Editor: func(filename string) error {
								return os.WriteFile(filename, []byte(resourceYamlPath), 0o644)
							},
						},
						setup:   rc.resourceSetup,
						cleanup: rc.resourceSetup,
					})
				})
			}
		})
	}
}

func testAdminActionMFA_UserCommands(t *testing.T, s *adminActionTestSuite) {
	ctx := context.Background()

	user, err := types.NewUser("teleuser")
	require.NoError(t, err)

	createUser := func(t *testing.T, authServer *auth.Server) {
		_, err := authServer.CreateUser(ctx, user)
		// ensure broken test cases don't impact
		if !trace.IsAlreadyExists(err) {
			require.NoError(t, err)
		}
	}

	deleteUser := func(t *testing.T, authServer *auth.Server) {
		err := authServer.DeleteUser(ctx, "teleuser")
		// ensure broken test cases don't impact
		if !trace.IsNotFound(err) {
			require.NoError(t, err)
		}
	}

	for _, tc := range []adminActiontestCase{
		{
			command:    "users add teleuser --roles=access",
			cliCommand: &tctl.UserCommand{},
			cleanup:    deleteUser,
		}, {
			command:    "users update teleuser --set-roles=access,auditor",
			cliCommand: &tctl.UserCommand{},
			setup:      createUser,
			cleanup:    deleteUser,
		}, {
			command:    "users rm teleuser",
			cliCommand: &tctl.UserCommand{},
			setup:      createUser,
			cleanup:    deleteUser,
		},
	} {
		t.Run(tc.command, func(t *testing.T) {
			s.runTestCase(t, ctx, tc)
		})
	}
}

func setupWebAuthn(t *testing.T, authServer *auth.Server, username string) libclient.WebauthnLoginFunc {
	t.Helper()
	ctx := context.Background()

	const origin = "https://127.0.0.1"
	device, err := mocku2f.Create()
	require.NoError(t, err)
	device.SetPasswordless()

	token, err := authServer.CreateResetPasswordToken(ctx, auth.CreateUserTokenRequest{
		Name: username,
	})
	require.NoError(t, err)

	tokenID := token.GetName()
	res, err := authServer.CreateRegisterChallenge(ctx, &proto.CreateRegisterChallengeRequest{
		TokenID:     tokenID,
		DeviceType:  proto.DeviceType_DEVICE_TYPE_WEBAUTHN,
		DeviceUsage: proto.DeviceUsage_DEVICE_USAGE_PASSWORDLESS,
	})
	require.NoError(t, err)
	cc := wantypes.CredentialCreationFromProto(res.GetWebauthn())

	userWebID := res.GetWebauthn().PublicKey.User.Id

	ccr, err := device.SignCredentialCreation(origin, cc)
	require.NoError(t, err)
	_, err = authServer.ChangeUserAuthentication(ctx, &proto.ChangeUserAuthenticationRequest{
		TokenID: tokenID,
		NewMFARegisterResponse: &proto.MFARegisterResponse{
			Response: &proto.MFARegisterResponse_Webauthn{
				Webauthn: wantypes.CredentialCreationResponseToProto(ccr),
			},
		},
	})
	require.NoError(t, err)

	return func(ctx context.Context, origin string, assertion *wantypes.CredentialAssertion, prompt wancli.LoginPrompt, opts *wancli.LoginOpts) (*proto.MFAAuthenticateResponse, string, error) {
		car, err := device.SignAssertion(origin, assertion)
		if err != nil {
			return nil, "", err
		}
		car.AssertionResponse.UserHandle = userWebID

		return &proto.MFAAuthenticateResponse{
			Response: &proto.MFAAuthenticateResponse_Webauthn{
				Webauthn: wantypes.CredentialAssertionResponseToProto(car),
			},
		}, "", nil
	}
}

func setHomePath(path string) tsh.CliOption {
	return func(cf *tsh.CLIConf) error {
		cf.HomePath = path
		return nil
	}
}

func setKubeConfigPath(path string) tsh.CliOption {
	return func(cf *tsh.CLIConf) error {
		cf.KubeConfigPath = path
		return nil
	}
}
