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
	"os"
	"path/filepath"
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
	tctl "github.com/gravitational/teleport/tool/tctl/common"
	testserver "github.com/gravitational/teleport/tool/teleport/testenv"
	tsh "github.com/gravitational/teleport/tool/tsh/common"
	"github.com/stretchr/testify/require"
)

// TestAdminActions is an e2e tests for tctl admin actions.
func TestAdminActions(t *testing.T) {
	ctx := context.Background()

	process := testserver.MakeTestServer(t)
	proxyAddr, err := process.ProxyWebAddr()
	require.NoError(t, err)
	authAddr, err := process.AuthAddr()
	require.NoError(t, err)
	authServer := process.GetAuthServer()

	mfaAuthPreference := &types.AuthPreferenceV2{
		Spec: types.AuthPreferenceSpecV2{
			Type:         constants.Local,
			SecondFactor: constants.SecondFactorOptional,
			Webauthn: &types.Webauthn{
				RPID: "127.0.0.1",
			},
		},
	}
	err = authServer.SetAuthPreference(ctx, mfaAuthPreference)
	require.NoError(t, err)

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

	userClient, err := auth.NewClient(client.Config{
		Addrs: []string{authAddr.String()},
		Credentials: []client.Credentials{
			client.LoadProfile(tshHome, ""),
		},
		MFAPromptConstructor: mockMFAPromptConstructor,
	})
	require.NoError(t, err)

	userClientNoMFA, err := auth.NewClient(client.Config{
		Addrs: []string{authAddr.String()},
		Credentials: []client.Credentials{
			client.LoadProfile(tshHome, ""),
		},
	})
	require.NoError(t, err)

	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T)
		command func(ctx context.Context, client auth.ClientI) error
		cleanup func(t *testing.T)
		args    []string
	}{
		{
			name: "add user",
			command: (&tctl.UserCommand{
				Login:        "Alice",
				AllowedRoles: []string{"access"},
			}).Add,
			cleanup: func(t *testing.T) {
				authServer.DeleteUser(ctx, "Alice")
			},
		}, {
			name: "update user",
			setup: func(t *testing.T) {
				user, err := types.NewUser("Alice")
				require.NoError(t, err)
				_, err = authServer.CreateUser(ctx, user)
				require.NoError(t, err)
			},
			command: (&tctl.UserCommand{
				Login:        "Alice",
				AllowedRoles: []string{"access"},
			}).Update,
			cleanup: func(t *testing.T) {
				authServer.DeleteUser(ctx, "Alice")
			},
		}, {
			name: "delete user",
			setup: func(t *testing.T) {
				user, err := types.NewUser("Alice")
				require.NoError(t, err)
				_, err = authServer.CreateUser(ctx, user)
				require.NoError(t, err)
			},
			command: (&tctl.UserCommand{
				Login: "Alice",
			}).Delete,
			cleanup: func(t *testing.T) {
				authServer.DeleteUser(ctx, "Alice")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("OK with MFA", func(t *testing.T) {
				if tc.setup != nil {
					tc.setup(t)
				}
				if tc.cleanup != nil {
					t.Cleanup(func() { tc.cleanup(t) })
				}

				err := tc.command(ctx, userClient)
				require.NoError(t, err)
			})

			t.Run("NOK without MFA", func(t *testing.T) {
				if tc.setup != nil {
					tc.setup(t)
				}
				if tc.cleanup != nil {
					t.Cleanup(func() { tc.cleanup(t) })
				}

				err := tc.command(ctx, userClientNoMFA)
				require.ErrorContains(t, err, mfa.ErrAdminActionMFARequired.Message)
			})

			// turn off MFA, admin actions should not require MFA now.
			err = authServer.SetAuthPreference(ctx, &types.AuthPreferenceV2{
				Spec: types.AuthPreferenceSpecV2{
					Type:         constants.Local,
					SecondFactor: constants.SecondFactorOff,
				},
			})
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, authServer.SetAuthPreference(ctx, mfaAuthPreference))
			})

			t.Run("OK mfa off", func(t *testing.T) {
				if tc.setup != nil {
					tc.setup(t)
				}
				if tc.cleanup != nil {
					t.Cleanup(func() { tc.cleanup(t) })
				}

				err := tc.command(ctx, userClientNoMFA)
				require.NoError(t, err)
			})
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
