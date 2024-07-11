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

package dynamo

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go/middleware"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/test"
	"github.com/gravitational/teleport/lib/utils"
)

func TestMain(m *testing.M) {
	utils.InitLoggerForTests()
	os.Exit(m.Run())
}

func ensureTestsEnabled(t *testing.T) {
	const varName = "TELEPORT_DYNAMODB_TEST"
	if os.Getenv(varName) == "" {
		t.Skipf("DynamoDB tests are disabled. Enable by defining the %v environment variable", varName)
	}
}

func dynamoDBTestTable() string {
	if t := os.Getenv("TELEPORT_DYNAMODB_TEST_TABLE"); t != "" {
		return t
	}

	return "teleport.dynamo.test"
}

func TestDynamoDB(t *testing.T) {
	ensureTestsEnabled(t)

	dynamoCfg := map[string]interface{}{
		"table_name":         dynamoDBTestTable(),
		"poll_stream_period": 300 * time.Millisecond,
	}

	newBackend := func(options ...test.ConstructionOption) (backend.Backend, clockwork.FakeClock, error) {
		testCfg, err := test.ApplyOptions(options)
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}

		if testCfg.MirrorMode {
			return nil, nil, test.ErrMirrorNotSupported
		}

		// This would seem to be a bad thing for dynamo to omit
		if testCfg.ConcurrentBackend != nil {
			return nil, nil, test.ErrConcurrentAccessNotSupported
		}

		uut, err := New(context.Background(), dynamoCfg)
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}
		clock := clockwork.NewFakeClockAt(time.Now())
		uut.clock = clock
		return uut, clock, nil
	}

	test.RunBackendComplianceSuite(t, newBackend)
}

type dynamoDBAPIMock struct {
	dynamoClient

	expectedTableName             string
	expectedBillingMode           types.BillingMode
	expectedProvisionedthroughput *types.ProvisionedThroughput
}

func (d *dynamoDBAPIMock) CreateTable(ctx context.Context, input *dynamodb.CreateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.CreateTableOutput, error) {

	if d.expectedTableName != aws.ToString(input.TableName) {
		return nil, trace.BadParameter("table names do not match")
	}

	if d.expectedBillingMode != input.BillingMode {
		return nil, trace.BadParameter("billing mode does not match")
	}

	if d.expectedProvisionedthroughput != nil {
		if input.BillingMode == types.BillingModePayPerRequest {
			return nil, trace.BadParameter("pthroughput should be nil if on demand is true")
		}

		if aws.ToInt64(d.expectedProvisionedthroughput.ReadCapacityUnits) != aws.ToInt64(input.ProvisionedThroughput.ReadCapacityUnits) ||
			aws.ToInt64(d.expectedProvisionedthroughput.WriteCapacityUnits) != aws.ToInt64(input.ProvisionedThroughput.WriteCapacityUnits) {

			return nil, trace.BadParameter("pthroughput values were not equal")
		}
	}

	return nil, nil
}

func (d *dynamoDBAPIMock) DescribeTable(ctx context.Context, input *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	if d.expectedTableName != aws.ToString(input.TableName) {
		return nil, trace.BadParameter("table names do not match")
	}
	return &dynamodb.DescribeTableOutput{
		Table: &types.TableDescription{
			TableName:   input.TableName,
			TableStatus: types.TableStatusActive,
		},
		ResultMetadata: middleware.Metadata{},
	}, nil
}

func TestCreateTable(t *testing.T) {
	const tableName = "table"

	errIsNil := func(err error) bool { return err == nil }

	for _, tc := range []struct {
		name                          string
		errorIsFn                     func(error) bool
		readCapacityUnits             int
		writeCapacityUnits            int
		expectedProvisionedThroughput *types.ProvisionedThroughput
		expectedBillingMode           types.BillingMode
		billingMode                   billingMode
	}{
		{
			name:                "table creation succeeds",
			errorIsFn:           errIsNil,
			billingMode:         billingModePayPerRequest,
			expectedBillingMode: types.BillingModePayPerRequest,
		},
		{
			name:                "read/write capacity units are ignored if on demand is on",
			readCapacityUnits:   10,
			writeCapacityUnits:  10,
			errorIsFn:           errIsNil,
			billingMode:         billingModePayPerRequest,
			expectedBillingMode: types.BillingModePayPerRequest,
		},
		{
			name:               "bad parameter when provisioned throughput is set",
			readCapacityUnits:  10,
			writeCapacityUnits: 10,
			errorIsFn:          trace.IsBadParameter,
			expectedProvisionedThroughput: &types.ProvisionedThroughput{
				ReadCapacityUnits:  aws.Int64(10),
				WriteCapacityUnits: aws.Int64(10),
			},
			billingMode:         billingModePayPerRequest,
			expectedBillingMode: types.BillingModePayPerRequest,
		},
		{
			name:               "bad parameter when the incorrect billing mode is set",
			readCapacityUnits:  10,
			writeCapacityUnits: 10,
			errorIsFn:          trace.IsBadParameter,
			expectedProvisionedThroughput: &types.ProvisionedThroughput{
				ReadCapacityUnits:  aws.Int64(10),
				WriteCapacityUnits: aws.Int64(10),
			},
			billingMode:         billingModePayPerRequest,
			expectedBillingMode: types.BillingModePayPerRequest,
		},
		{
			name:               "create table succeeds",
			readCapacityUnits:  10,
			writeCapacityUnits: 10,
			errorIsFn:          errIsNil,
			expectedProvisionedThroughput: &types.ProvisionedThroughput{
				ReadCapacityUnits:  aws.Int64(10),
				WriteCapacityUnits: aws.Int64(10),
			},
			billingMode:         billingModeProvisioned,
			expectedBillingMode: types.BillingModeProvisioned,
		},
	} {

		ctx := context.Background()
		t.Run(tc.name, func(t *testing.T) {
			mock := dynamoDBAPIMock{
				expectedBillingMode:           tc.expectedBillingMode,
				expectedTableName:             tableName,
				expectedProvisionedthroughput: tc.expectedProvisionedThroughput,
			}
			b := &Backend{
				Entry: log.NewEntry(log.New()),
				Config: Config{
					BillingMode:        tc.billingMode,
					ReadCapacityUnits:  int64(tc.readCapacityUnits),
					WriteCapacityUnits: int64(tc.writeCapacityUnits),
				},

				dbClient: &mock,
			}

			err := b.createTable(ctx, tableName, "_")
			require.True(t, tc.errorIsFn(err), err)
		})
	}
}
