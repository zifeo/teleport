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
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/applicationautoscaling"
	autoscalingtypes "github.com/aws/aws-sdk-go-v2/service/applicationautoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// SetContinuousBackups enables continuous backups.
func SetContinuousBackups(ctx context.Context, svc dynamoClient, tableName string) error {
	// Make request to AWS to update continuous backups settings.
	_, err := svc.UpdateContinuousBackups(ctx, &dynamodb.UpdateContinuousBackupsInput{
		PointInTimeRecoverySpecification: &types.PointInTimeRecoverySpecification{
			PointInTimeRecoveryEnabled: aws.Bool(true),
		},
		TableName: aws.String(tableName),
	})
	if err != nil {
		return convertError(err)
	}

	return nil
}

// AutoScalingParams defines auto scaling parameters for DynamoDB.
type AutoScalingParams struct {
	// ReadMaxCapacity is the maximum provisioned read capacity.
	ReadMaxCapacity int32
	// ReadMinCapacity is the minimum provisioned read capacity.
	ReadMinCapacity int32
	// ReadTargetValue is the ratio of consumed read to provisioned capacity.
	ReadTargetValue float64
	// WriteMaxCapacity is the maximum provisioned write capacity.
	WriteMaxCapacity int32
	// WriteMinCapacity is the minimum provisioned write capacity.
	WriteMinCapacity int32
	// WriteTargetValue is the ratio of consumed write to provisioned capacity.
	WriteTargetValue float64
}

// SetAutoScaling enables auto-scaling for the specified table with given configuration.
func SetAutoScaling(ctx context.Context, svc *applicationautoscaling.Client, resourceID string, params AutoScalingParams) error {
	readDimension := autoscalingtypes.ScalableDimensionDynamoDBTableReadCapacityUnits
	writeDimension := autoscalingtypes.ScalableDimensionDynamoDBTableWriteCapacityUnits

	// Check if the resource ID refers to an index - those IDs have the following form:
	// 'table/<tableName>/index/<indexName>'
	//
	// Indices use a slightly different scaling dimension than tables
	if strings.Contains(resourceID, "/index/") {
		readDimension = autoscalingtypes.ScalableDimensionDynamoDBIndexReadCapacityUnits
		writeDimension = autoscalingtypes.ScalableDimensionDynamoDBIndexWriteCapacityUnits
	}

	// Define scaling targets. Defines minimum and maximum {read,write} capacity.
	if _, err := svc.RegisterScalableTarget(ctx, &applicationautoscaling.RegisterScalableTargetInput{
		MinCapacity:       aws.Int32(params.ReadMinCapacity),
		MaxCapacity:       aws.Int32(params.ReadMaxCapacity),
		ResourceId:        aws.String(resourceID),
		ScalableDimension: readDimension,
		ServiceNamespace:  autoscalingtypes.ServiceNamespaceDynamodb,
	}); err != nil {
		return convertError(err)
	}
	if _, err := svc.RegisterScalableTarget(ctx, &applicationautoscaling.RegisterScalableTargetInput{
		MinCapacity:       aws.Int32(params.WriteMinCapacity),
		MaxCapacity:       aws.Int32(params.WriteMaxCapacity),
		ResourceId:        aws.String(resourceID),
		ScalableDimension: writeDimension,
		ServiceNamespace:  autoscalingtypes.ServiceNamespaceDynamodb,
	}); err != nil {
		return convertError(err)
	}

	// Define scaling policy. Defines the ratio of {read,write} consumed capacity to
	// provisioned capacity DynamoDB will try and maintain.
	if _, err := svc.PutScalingPolicy(ctx, &applicationautoscaling.PutScalingPolicyInput{
		PolicyName:        aws.String(getReadScalingPolicyName(resourceID)),
		PolicyType:        autoscalingtypes.PolicyTypeTargetTrackingScaling,
		ResourceId:        aws.String(resourceID),
		ScalableDimension: readDimension,
		ServiceNamespace:  autoscalingtypes.ServiceNamespaceDynamodb,
		TargetTrackingScalingPolicyConfiguration: &autoscalingtypes.TargetTrackingScalingPolicyConfiguration{
			PredefinedMetricSpecification: &autoscalingtypes.PredefinedMetricSpecification{
				PredefinedMetricType: autoscalingtypes.MetricTypeDynamoDBReadCapacityUtilization,
			},
			TargetValue: aws.Float64(params.ReadTargetValue),
		},
	}); err != nil {
		return convertError(err)
	}
	if _, err := svc.PutScalingPolicy(ctx, &applicationautoscaling.PutScalingPolicyInput{
		PolicyName:        aws.String(getWriteScalingPolicyName(resourceID)),
		PolicyType:        autoscalingtypes.PolicyTypeTargetTrackingScaling,
		ResourceId:        aws.String(resourceID),
		ScalableDimension: writeDimension,
		ServiceNamespace:  autoscalingtypes.ServiceNamespaceDynamodb,
		TargetTrackingScalingPolicyConfiguration: &autoscalingtypes.TargetTrackingScalingPolicyConfiguration{
			PredefinedMetricSpecification: &autoscalingtypes.PredefinedMetricSpecification{
				PredefinedMetricType: autoscalingtypes.MetricTypeDynamoDBWriteCapacityUtilization,
			},
			TargetValue: aws.Float64(params.WriteTargetValue),
		},
	}); err != nil {
		return convertError(err)
	}

	return nil
}

// GetTableID returns the resourceID of a table based on its table name
func GetTableID(tableName string) string {
	return fmt.Sprintf("table/%s", tableName)
}

// GetIndexID returns the resourceID of an index, based on the table & index name
func GetIndexID(tableName, indexName string) string {
	return fmt.Sprintf("table/%s/index/%s", tableName, indexName)
}

// getWriteScalingPolicyName returns the policy name for our write scaling policy
func getWriteScalingPolicyName(resourceID string) string {
	// We're trimming the "table/" prefix since policies before 6.1.0 didn't contain it. By referencing an existing
	// policy name in 'PutScalingPolicy', AWS will update that one instead of creating a new resource.
	return fmt.Sprintf("%s-write-target-tracking-scaling-policy", strings.TrimPrefix(resourceID, "table/"))
}

// getWriteScalingPolicyName returns the policy name for our read scaling policy
func getReadScalingPolicyName(resourceID string) string {
	return fmt.Sprintf("%s-read-target-tracking-scaling-policy", strings.TrimPrefix(resourceID, "table/"))
}

func TurnOnTimeToLive(ctx context.Context, svc dynamoClient, tableName string, ttlKey string) error {
	status, err := svc.DescribeTimeToLive(ctx, &dynamodb.DescribeTimeToLiveInput{
		TableName: aws.String(tableName),
	})
	if err != nil {
		return convertError(err)
	}
	switch status.TimeToLiveDescription.TimeToLiveStatus {
	case types.TimeToLiveStatusEnabled, types.TimeToLiveStatusEnabling:
		return nil
	}
	_, err = svc.UpdateTimeToLive(ctx, &dynamodb.UpdateTimeToLiveInput{
		TableName: aws.String(tableName),
		TimeToLiveSpecification: &types.TimeToLiveSpecification{
			AttributeName: aws.String(ttlKey),
			Enabled:       aws.Bool(true),
		},
	})
	return convertError(err)
}

func TurnOnStreams(ctx context.Context, svc dynamoClient, tableName string) error {
	status, err := svc.DescribeTable(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})
	if err != nil {
		return convertError(err)
	}
	if status.Table.StreamSpecification != nil && aws.ToBool(status.Table.StreamSpecification.StreamEnabled) {
		return nil
	}
	_, err = svc.UpdateTable(ctx, &dynamodb.UpdateTableInput{
		TableName: aws.String(tableName),
		StreamSpecification: &types.StreamSpecification{
			StreamEnabled:  aws.Bool(true),
			StreamViewType: types.StreamViewTypeNewImage,
		},
	})
	return convertError(err)
}
