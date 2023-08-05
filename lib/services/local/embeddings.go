// Copyright 2023 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package local

import (
	"context"
	"time"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

	embeddingpb "github.com/gravitational/teleport/api/gen/proto/go/teleport/embedding/v1"
	"github.com/gravitational/teleport/api/internalutils/stream"
	"github.com/gravitational/teleport/api/utils/retryutils"
	"github.com/gravitational/teleport/lib/backend"
)

// EmbeddingsService implements the services.Embeddings interface.
type EmbeddingsService struct {
	log    *logrus.Entry
	jitter retryutils.Jitter
	backend.Backend
	clock clockwork.Clock
}

const (
	embeddingsPrefix = "embeddings"
	embeddingExpiry  = 30 * 24 * time.Hour // 30 days
)

// GetEmbedding looks up a single embedding by its name in the backend.
func (e EmbeddingsService) GetEmbedding(ctx context.Context, kind, resourceID string) (*embeddingpb.Embedding, error) {
	result, err := e.Get(ctx, backend.Key(embeddingsPrefix, kind, resourceID))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if len(result.Value) == 0 {
		return nil, trace.BadParameter("missing embedding data")
	}
	var embedding embeddingpb.Embedding
	if err := proto.Unmarshal(result.Value, &embedding); err != nil {
		return nil, trace.Wrap(err)
	}

	return &embedding, nil
}

// GetEmbeddings returns a stream of embeddings for a given kind.
func (e EmbeddingsService) GetEmbeddings(ctx context.Context, kind string) stream.Stream[*embeddingpb.Embedding] {
	startKey := backend.ExactKey(embeddingsPrefix, kind)
	items := backend.StreamRange(ctx, e, startKey, backend.RangeEnd(startKey), 50)
	return stream.FilterMap(items, func(item backend.Item) (*embeddingpb.Embedding, bool) {
		if len(item.Value) == 0 {
			e.log.Warnf("Skipping embedding at %s, no data found", item.Key)
			return nil, false
		}
		var embedding embeddingpb.Embedding
		if err := proto.Unmarshal(item.Value, &embedding); err != nil {
			e.log.Warnf("Skipping embedding at %s, failed to unmarshal: %v", item.Key, err)
			return nil, false
		}
		return &embedding, true
	})
}

// UpsertEmbedding creates or update a single ai.Embedding in the backend.
func (e EmbeddingsService) UpsertEmbedding(ctx context.Context, embedding *embeddingpb.Embedding) (*embeddingpb.Embedding, error) {
	value, err := proto.Marshal(embedding)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	_, err = e.Put(ctx, backend.Item{
		Key:     embeddingItemKey(embedding),
		Value:   value,
		Expires: e.clock.Now().Add(embeddingExpiry),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return embedding, nil
}

// NewEmbeddingsService is a constructor for the EmbeddingsService.
func NewEmbeddingsService(b backend.Backend) *EmbeddingsService {
	return &EmbeddingsService{
		log:     logrus.WithFields(logrus.Fields{trace.Component: "Embeddings"}),
		jitter:  retryutils.NewFullJitter(),
		Backend: b,
		clock:   clockwork.NewRealClock(),
	}
}

// embeddingItemKey builds the backend item key for a given ai.Embedding.
func embeddingItemKey(embedding *embeddingpb.Embedding) []byte {
	name := embedding.EmbeddedKind + string(backend.Separator) + embedding.EmbeddedId
	return backend.Key(embeddingsPrefix, name)
}
